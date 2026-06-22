//! Ende-zu-Ende-Integrationstests des konkreten Kernels (§5.2/§5.3/§7.1/§11)
//! **über die öffentliche Crate-Oberfläche**.
//!
//! Maßgeblich: `semantics/lakearch.md` (§5.2 Speicher-Identität, §5.3 Dedup,
//! §7.1 append-only, §8.4 Log = Wahrheit, §11 Tor) und der gehärtete Plan
//! („Kernel-API-Vertrag", „Betrieb & Beobachtbarkeit"). Diese Tests nutzen
//! ausschließlich die `pub`-API (`LakearchKernel`, der `Kernel`-Trait, `open`,
//! `GrantedScopes`) — kein crate-interner Zugriff. Damit belegen sie zugleich,
//! dass die `lib.rs`-Re-Exports einen externen Aufrufer vollständig bedienen.

use lakearch_core::{
    open, CancelFlag, ContentId, Datum, Direction, GrantedScopes, Kernel, LakearchKernel,
    TraversalParams,
};
use tempfile::tempdir;

/// §7.1 + §5.2 + §11: append → get_by_content_id (durchs Tor) → open → strikt
/// dekodieren ⇒ dasselbe Daten. Der ganze Pfad läuft über den öffentlichen
/// `Kernel`-Vertrag.
#[test]
fn append_get_open_round_trip_over_public_api() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");

    // Reifikation (§3.4): ein Knoten, der zwei Blätter besitzt.
    let a = k.append(&Datum::leaf(b"alpha".to_vec())).unwrap();
    let b = k.append(&Datum::leaf(b"beta".to_vec())).unwrap();
    let node = Datum::node([a, b]).unwrap();
    let node_id = k.append(&node).unwrap();
    assert_eq!(node_id, ContentId::of_datum(&node));

    // Snapshot + Capability über die öffentlichen Verben.
    let snap = k.pin_snapshot().unwrap();
    let cap = k
        .authorize(GrantedScopes::from_scope_ids([]), snap)
        .unwrap();

    let sealed = k
        .get_by_content_id(node_id, &cap, snap)
        .unwrap()
        .expect("vorhanden");
    assert_eq!(sealed.content_id(), node_id);

    // Nur `open` (das Tor) gibt den Inhalt frei.
    let visible = open(&sealed, &cap).expect("Tor legt Inhalt frei");
    assert_eq!(visible.content_id(), node_id);
    let decoded = lakearch_core::strict_decode(visible.canonical_bytes()).unwrap();
    assert_eq!(decoded, node);
}

/// §5.3: Dedup spiegelt sich in den Betriebs-Zählern (`stats`).
#[test]
fn dedup_shows_up_in_stats() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");
    let d = Datum::leaf(b"value-identity".to_vec());

    k.append(&d).unwrap();
    let bytes_after_first = k.stats().unwrap().committed_bytes;
    k.append(&d).unwrap();

    let stats = k.stats().unwrap();
    assert_eq!(stats.append_count, 1, "ein physischer Record");
    assert_eq!(stats.dedup_hit_count, 1, "ein Dedup-Treffer");
    assert_eq!(
        stats.committed_bytes, bytes_after_first,
        "Dedup-Treffer schreibt nichts"
    );
    assert_eq!(stats.segment_count, 1);
}

/// §8.4: den Kernel von Platte neu öffnen und die Daten zurücklesen.
#[test]
fn reopen_from_disk_and_read_back() {
    let dir = tempdir().unwrap();
    let leaf_id;
    let node_id;
    let committed;
    {
        let k = LakearchKernel::open(dir.path()).expect("open kernel");
        leaf_id = k.append(&Datum::leaf(b"durable".to_vec())).unwrap();
        node_id = k.append(&Datum::node([leaf_id]).unwrap()).unwrap();
        committed = k.stats().unwrap().committed_bytes;
    }

    // Neu öffnen: Recovery + Index-Versöhnung beim Öffnen (§8.4).
    let k = LakearchKernel::open(dir.path()).expect("reopen kernel");
    assert_eq!(k.stats().unwrap().committed_bytes, committed);

    let snap = k.pin_snapshot().unwrap();
    let cap = k
        .authorize(GrantedScopes::from_scope_ids([]), snap)
        .unwrap();

    let sealed = k
        .get_by_content_id(node_id, &cap, snap)
        .unwrap()
        .expect("durabel");
    let visible = open(&sealed, &cap).unwrap();
    assert_eq!(
        lakearch_core::strict_decode(visible.canonical_bytes()).unwrap(),
        Datum::node([leaf_id]).unwrap()
    );

    // Re-append nach Reopen ⇒ Dedup-Treffer (Dedup-Karte aus dem Log gebaut).
    let again = k.append(&Datum::node([leaf_id]).unwrap()).unwrap();
    assert_eq!(again, node_id);
    assert_eq!(k.stats().unwrap().dedup_hit_count, 1);
}

/// §11.3 VANISH über die öffentliche Oberfläche: ein bereichs-beschränktes Daten
/// ist ohne den Bereich schon an der **Verb-Grenze** `None` (ununterscheidbar von
/// „existiert nicht" — kein Existenz-Orakel über die Rückgabeform), mit dem
/// Bereich sichtbar.
#[test]
fn gate_vanish_over_public_api() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");

    // Bereich + Zugehörigkeits-Kontext + ein dem Bereich angehörendes Daten.
    let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
    let _marker = k.append(&Datum::area_membership_marker()).unwrap();
    let membership = k.append(&Datum::area_membership(area)).unwrap();
    let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();

    let snap = k.pin_snapshot().unwrap();

    // Ohne den Bereich: das Verb liefert bereits `None` (VANISH an der Verb-Grenze)
    // — ununterscheidbar von einer unbekannten Adresse, kein Existenz-Orakel (§11.3).
    let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
    assert!(
        k.get_by_content_id(secret, &denied, snap).unwrap().is_none(),
        "kein gewährter Bereich ⇒ VANISH (None) schon an der Verb-Grenze (§11.3)"
    );
    // Eine unbekannte Adresse liefert ebenfalls `None` — beide Fälle sind für den
    // rechtlosen Leser ununterscheidbar.
    let missing = ContentId::from_bytes([0x7F; 32]);
    assert!(
        k.get_by_content_id(missing, &denied, snap).unwrap().is_none(),
        "unbekannte Adresse ⇒ None (ununterscheidbar von verborgen)"
    );

    // Mit dem Bereich: das Verb gibt das Daten heraus und das Tor legt es frei.
    let granted = k
        .authorize(GrantedScopes::from_scope_ids([area]), snap)
        .unwrap();
    let sealed2 = k
        .get_by_content_id(secret, &granted, snap)
        .unwrap()
        .expect("mit Recht vorhanden");
    assert!(
        open(&sealed2, &granted).is_some(),
        "mit gewährtem Bereich ⇒ sichtbar"
    );
}

/// §11.1/§11.2/§11.4: Berechtigung & Entzug über die öffentliche Oberfläche.
/// Eine Berechtigung gewährt einem Subjekt einen Bereich; nach einem Entzug
/// (§11.4) ist dasselbe Daten für **künftige** Lesevorgänge des Subjekts
/// unsichtbar (VANISH). Strukturell, ohne Wall-Clock (§11.5).
#[test]
fn revocation_hides_future_reads_over_public_api() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");

    // Ein Subjekt, ein Bereich, ein dem Bereich angehörendes (beschränktes) Daten.
    let subject = k.append(&Datum::leaf(b"subject".to_vec())).unwrap();
    let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
    let _am = k.append(&Datum::area_membership_marker()).unwrap();
    let membership = k.append(&Datum::area_membership(area)).unwrap();
    let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();

    // Eine Berechtigung (Subjekt → Bereich): erst die Rollen-Kontexte, dann die
    // Berechtigung selbst (die schreibende Schicht baut die Struktur, §7.2).
    k.append(&Datum::permission_subject_marker()).unwrap();
    k.append(&Datum::permission_area_marker()).unwrap();
    k.append(&Datum::permission_marker()).unwrap();
    k.append(&Datum::permission_subject_role(subject)).unwrap();
    k.append(&Datum::permission_area_role(area)).unwrap();
    let perm = k.append(&Datum::permission(subject, area)).unwrap();

    // VOR dem Entzug: das Subjekt erhält eine Capability mit dem Bereich und sieht
    // das geheime Daten.
    let snap = k.pin_snapshot().unwrap();
    let cap = k.authorize_subject(subject, snap).unwrap();
    let sealed = k
        .get_by_content_id(secret, &cap, snap)
        .unwrap()
        .expect("Adresse vorhanden");
    assert!(open(&sealed, &cap).is_some(), "mit aktiver Berechtigung sichtbar");

    // Entzug anhängen (§11.4).
    k.append(&Datum::revocation_marker()).unwrap();
    k.append(&Datum::revocation(perm)).unwrap();

    // NACH dem Entzug: eine frische Autorisierung des Subjekts gewährt den Bereich
    // nicht mehr → das geheime Daten VANISHt schon an der Verb-Grenze (`None`,
    // ununterscheidbar von „existiert nicht", §11.4/§11.3).
    let snap2 = k.pin_snapshot().unwrap();
    let cap2 = k.authorize_subject(subject, snap2).unwrap();
    assert!(
        k.get_by_content_id(secret, &cap2, snap2).unwrap().is_none(),
        "nach Entzug VANISHt das Daten für künftige Reads an der Verb-Grenze (§11.4)"
    );
}

/// §1.2/§1.7 a: beschränkte mechanische Traversierung über die öffentliche
/// `traverse_with`-Methode, gegated und deterministisch aufsteigend emittiert.
#[test]
fn gated_traverse_over_public_api() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");

    let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
    let c = k.append(&Datum::leaf(b"c".to_vec())).unwrap();
    let a = k.append(&Datum::node([b, c]).unwrap()).unwrap();

    let snap = k.pin_snapshot().unwrap();
    let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
    let params = TraversalParams {
        start: a,
        dir: Direction::Forward,
        max_depth: 2,
        max_nodes: 100,
        edge_type_filter: None,
    };
    let steps: Vec<_> = k
        .traverse_with(params, &cap, snap, &CancelFlag::new())
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let tos: Vec<ContentId> = steps.iter().map(|s| s.to).collect();
    let mut expected = vec![b, c];
    expected.sort();
    assert_eq!(tos, expected, "Forward-Nachbarn von A, aufsteigend (§5.2/§1.4)");
}
