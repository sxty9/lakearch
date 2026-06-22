//! Ende-zu-Ende-Integrationstest des Daemons (§Plan „Ende-zu-Ende"): startet den
//! gRPC-Server **in-process** auf einem **ephemeren** Port (`127.0.0.1:0`) und
//! fährt einen echten tonic-Client dagegen.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2/§7.1/§1.2/§11) und der
//! Plan (Ende-zu-Ende: `append` (Client A) nebenläufig zu `traverse`/Read
//! (Client B), MVCC ohne Blockade; das Tor auf jeder Anfrage).
//!
//! Abgedeckt:
//! 1. `append` → `get_by_content_id` (Round-Trip durch das Tor, §5.2/§11).
//! 2. eine kleine `traverse` (§1.2) liefert die erwarteten Nachbarn.
//! 3. ein **nebenläufiger** Read, während ein Write „in flight" ist (MVCC).
//! 4. **Gate-Test:** eine Anfrage **ohne** den gewährenden Bereich sieht das
//!    beschränkte Daten **nicht** (VANISH, §11.3); mit gewährtem Bereich schon.

use lakearchd::proto::lakearch_client::LakearchClient;
use lakearchd::proto::{
    datum, AppendRequest, ContextPointsToRequest, Datum as WireDatum, Direction,
    FindDependentsRequest, GetRequest, NodeContexts, Subject, TraverseRequest,
};
use lakearchd::{Bestand, LakearchService};
use lakearchd::proto::lakearch_server::LakearchServer;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

/// Startet den Daemon in-process auf einem ephemeren Port und liefert die
/// verbundene Client-Stub + ein Drop-Guard, das den Server beim Test-Ende beendet.
async fn start_server() -> (LakearchClient<Channel>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let bestand = Bestand::open(dir.path(), 64).expect("bestand öffnen");
    let service = LakearchService::new(bestand);

    // Ephemerer Port: 127.0.0.1:0 binden, die echte Adresse auslesen.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind :0");
    let addr = listener.local_addr().expect("local_addr");
    let incoming = TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .add_service(LakearchServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("server lief");
    });

    // Verbinden (mit kleinem Retry, falls der Server noch nicht horcht).
    let endpoint = format!("http://{addr}");
    let mut last_err = None;
    for _ in 0..50 {
        match LakearchClient::connect(endpoint.clone()).await {
            Ok(client) => return (client, dir),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    }
    panic!("Client konnte nicht verbinden: {last_err:?}");
}

/// Bequemer Wire-Konstruktor: ein Blatt-Datum.
fn wire_leaf(bytes: &[u8]) -> WireDatum {
    WireDatum {
        kind: Some(datum::Kind::Leaf(bytes.to_vec())),
    }
}

/// Bequemer Wire-Konstruktor: ein Knoten-Datum aus rohen 32-Byte-IDs.
fn wire_node(ids: &[Vec<u8>]) -> WireDatum {
    WireDatum {
        kind: Some(datum::Kind::Node(NodeContexts {
            context_ids: ids.to_vec(),
        })),
    }
}

/// Hängt ein Datum an und liefert seine 32-Byte-ContentId.
async fn append(client: &mut LakearchClient<Channel>, d: WireDatum) -> Vec<u8> {
    client
        .append(AppendRequest { datum: Some(d) })
        .await
        .expect("append rpc")
        .into_inner()
        .content_id
}

// ---------------------------------------------------------------------------
// 1 + 2 + 3: append → get → traverse → nebenläufiger Read während eines Writes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn append_get_traverse_and_concurrent_read() {
    let (mut client, _dir) = start_server().await;

    // (1) append eines Blattes, dann get_by_content_id (Round-Trip durchs Tor).
    let x = append(&mut client, wire_leaf(b"x")).await;
    let y = append(&mut client, wire_leaf(b"y")).await;

    let got = client
        .get_by_content_id(GetRequest {
            subject: None, // kein Subjekt ⇒ unbeschränkte Daten sichtbar.
            content_id: x.clone(),
        })
        .await
        .expect("get rpc")
        .into_inner();
    assert!(got.present, "angehängtes unbeschränktes Datum ist sichtbar");
    assert!(
        !got.canonical_bytes.is_empty(),
        "das Tor legt die kanonischen Bytes frei (§11.5)"
    );

    // (2) ein Knoten besitzt x und y; eine kleine Vorwärts-Traversierung liefert
    //     genau x und y als Nachbarn (Adress-Order, der Rand ordnet nichts um).
    let node = append(&mut client, wire_node(&[x.clone(), y.clone()])).await;
    let steps = client
        .traverse(TraverseRequest {
            subject: None,
            start: node.clone(),
            direction: Direction::Forward as i32,
            max_depth: 2,
            max_nodes: 100,
            edge_type_filter: vec![],
        })
        .await
        .expect("traverse rpc")
        .into_inner()
        .steps;
    let mut neighbors: Vec<Vec<u8>> = steps.iter().map(|s| s.to.clone()).collect();
    neighbors.sort();
    let mut expected = vec![x.clone(), y.clone()];
    expected.sort();
    assert_eq!(neighbors, expected, "Forward-Nachbarn von node sind x und y");

    // §1.3 (ii): context_points_to — node besitzt x. Gegated (§11.2/§11.3): ohne
    // Subjekt sind nur unbeschränkte Daten sichtbar; node/x sind unbeschränkt, also
    // ist der Besitz-Fakt sichtbar (value=true). Ein verborgener Operand VANISHt.
    let pts = client
        .context_points_to(ContextPointsToRequest {
            subject: None,
            ctx: node.clone(),
            target: x.clone(),
        })
        .await
        .expect("context_points_to rpc")
        .into_inner()
        .value;
    assert!(pts, "node zeigt auf x (§1.3 ii)");

    // find_dependents auf einem unbekannten Input ⇒ leerer Strom (kein Fehler).
    let deps = client
        .find_dependents(FindDependentsRequest {
            subject: None,
            input: x.clone(),
        })
        .await
        .expect("find_dependents rpc")
        .into_inner()
        .steps;
    assert!(deps.is_empty(), "x ist keine Herkunfts-Eingabe ⇒ leer");

    // (3) Nebenläufiger Read während eines Writes „in flight": viele Appends auf
    //     Client A parallel zu vielen Reads auf Client B — MVCC, keine Blockade.
    let writer = client.clone();
    let reader = client.clone();
    let xb = x.clone();

    let write_task = tokio::spawn(async move {
        let mut w = writer;
        for i in 0..64u32 {
            let _ = append(&mut w, wire_leaf(format!("burst-{i}").as_bytes())).await;
        }
    });
    let read_task = tokio::spawn(async move {
        let mut r = reader;
        for _ in 0..64u32 {
            // x existiert durabel; jeder Read muss es sehen (kein Schreib-Lock
            // blockiert den Leser — MVCC-Snapshot über das Watermark).
            let g = r
                .get_by_content_id(GetRequest {
                    subject: None,
                    content_id: xb.clone(),
                })
                .await
                .expect("concurrent get rpc")
                .into_inner();
            assert!(g.present, "x bleibt während laufender Writes sichtbar");
        }
    });
    let (wr, rr) = tokio::join!(write_task, read_task);
    wr.expect("write-task ok");
    rr.expect("read-task ok");
}

// ---------------------------------------------------------------------------
// 4: Gate-Test — ohne gewährenden Bereich VANISHt das beschränkte Daten (§11.3).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gate_vanishes_restricted_datum_without_granting_scope() {
    let (mut client, _dir) = start_server().await;

    // Ein Subjekt, ein Bereich, ein dem Bereich angehörendes (beschränktes) Daten.
    let subject = append(&mut client, wire_leaf(b"subject")).await;
    let area = append(&mut client, wire_leaf(b"area")).await;
    // Zugehörigkeits-Konvention (§11.1): Marker, dann { Marker, area }, dann ein
    // Daten, das diesen Zugehörigkeits-Kontext besitzt ⇒ es gehört dem Bereich an.
    let _am_marker = append(&mut client, wire_leaf(b"lakearch/area-membership/v1")).await;
    // Den Zugehörigkeits-Kontext { area_membership_marker, area } bauen: wir kennen
    // die ContentId des Markers nicht clientseitig hartkodiert, also bauen wir den
    // Knoten aus den IDs, die der Server uns zurückgibt.
    let am_marker_id = _am_marker;
    let membership = append(&mut client, wire_node(&[am_marker_id.clone(), area.clone()])).await;
    let secret = append(&mut client, wire_node(std::slice::from_ref(&membership))).await;

    // OHNE Subjekt (keine gewährten Bereiche): das beschränkte Daten VANISHt.
    let without = client
        .get_by_content_id(GetRequest {
            subject: None,
            content_id: secret.clone(),
        })
        .await
        .expect("get ohne scope")
        .into_inner();
    assert!(
        !without.present,
        "ohne gewährten Bereich VANISHt das beschränkte Daten (§11.3)"
    );

    // Auch ein Subjekt OHNE Berechtigung sieht es nicht.
    let unprivileged = client
        .get_by_content_id(GetRequest {
            subject: Some(Subject {
                subject_id: subject.clone(),
            }),
            content_id: secret.clone(),
        })
        .await
        .expect("get mit unberechtigtem subjekt")
        .into_inner();
    assert!(
        !unprivileged.present,
        "ein Subjekt ohne Berechtigung sieht das beschränkte Daten nicht (§11.3)"
    );

    // Jetzt dem Subjekt den Bereich gewähren (§11.1): die Rollen-Kontexte + die
    // Berechtigung selbst anhängen (die schreibende Schicht baut die Struktur).
    let _psm = append(&mut client, wire_leaf(b"lakearch/perm-subject/v1")).await;
    let _pam = append(&mut client, wire_leaf(b"lakearch/perm-area/v1")).await;
    let _pm = append(&mut client, wire_leaf(b"lakearch/permission/v1")).await;
    // Subjekt-Rollen-Kontext { perm_subject_marker, subject }.
    let subj_role = append(&mut client, wire_node(&[_psm.clone(), subject.clone()])).await;
    // Bereichs-Rollen-Kontext { perm_area_marker, area }.
    let area_role = append(&mut client, wire_node(&[_pam.clone(), area.clone()])).await;
    // Die Berechtigung selbst { perm_marker, subj_role, area_role }.
    let _perm = append(
        &mut client,
        wire_node(&[_pm.clone(), subj_role.clone(), area_role.clone()]),
    )
    .await;

    // MIT berechtigtem Subjekt: das beschränkte Daten ist jetzt sichtbar.
    let with = client
        .get_by_content_id(GetRequest {
            subject: Some(Subject {
                subject_id: subject.clone(),
            }),
            content_id: secret.clone(),
        })
        .await
        .expect("get mit berechtigtem subjekt")
        .into_inner();
    assert!(
        with.present,
        "mit gewährtem Bereich ist das Daten sichtbar (§11.2)"
    );
    assert!(
        !with.canonical_bytes.is_empty(),
        "das Tor legt die Bytes erst nach Berechtigung frei (§11.5)"
    );

    // Ein unbeschränktes Daten bleibt für alle sichtbar (Policy-Default).
    let public = append(&mut client, wire_leaf(b"public")).await;
    let pub_get = client
        .get_by_content_id(GetRequest {
            subject: None,
            content_id: public,
        })
        .await
        .expect("get public")
        .into_inner();
    assert!(pub_get.present, "unbeschränkt ⇒ für alle sichtbar");

    // §1.3 (ii) ist ebenfalls gegated (§11.2/§11.3): `secret` besitzt `membership`
    // (sein Bereichs-Zugehörigkeits-Kontext) — der Besitz-Fakt besteht strukturell.
    // OHNE Berechtigung VANISHt der beschränkte Operand `secret` ⇒ value=false (kein
    // Struktur-Orakel über verborgene Daten), MIT Berechtigung ⇒ value=true.
    let pts_without = client
        .context_points_to(ContextPointsToRequest {
            subject: None,
            ctx: secret.clone(),
            target: membership.clone(),
        })
        .await
        .expect("context_points_to ohne scope")
        .into_inner()
        .value;
    assert!(
        !pts_without,
        "ohne Berechtigung VANISHt der Besitz-Fakt über das beschränkte Daten (§11.3)"
    );

    let pts_with = client
        .context_points_to(ContextPointsToRequest {
            subject: Some(Subject {
                subject_id: subject.clone(),
            }),
            ctx: secret.clone(),
            target: membership.clone(),
        })
        .await
        .expect("context_points_to mit scope")
        .into_inner()
        .value;
    assert!(
        pts_with,
        "mit gewährtem Bereich ist der Besitz-Fakt sichtbar (§11.2/§1.3 ii)"
    );
}
