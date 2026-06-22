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
    open, ContentId, Datum, GrantedScopes, Kernel, LakearchKernel,
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
