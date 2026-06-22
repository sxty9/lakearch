//! Integrationstests des Content-Stores (§5.2/§5.3) und der Kanten-Indizes
//! (§1.2/§10.3) **über die öffentliche Crate-Oberfläche** — Log = alleinige
//! Wahrheit (§8.4).
//!
//! Maßgeblich: `semantics/lakearch.md` (§5.3 Dedup, §7.1 append-only, §8.4 Log =
//! Wahrheit) und der gehärtete Plan („Log-als-alleinige-Wahrheit + neu-baubarer
//! Index"). Diese Tests nutzen ausschließlich die `pub`-API
//! (`ContentStore`/`RedbEdgeIndex`/`EdgeIndex`), nicht crate-interne Felder.

use lakearch_core::{
    open, ContentId, ContentStore, Datum, EdgeIndex, GrantedScopes, Kernel, LakearchKernel,
    RedbEdgeIndex, SegmentLog,
};
use tempfile::tempdir;

/// Baut einen Store (Log-Verzeichnis + redb-Index) unter `dir`.
fn open_store(dir: &std::path::Path) -> ContentStore<RedbEdgeIndex> {
    let log_dir = dir.join("log");
    std::fs::create_dir_all(&log_dir).expect("log dir");
    let log = SegmentLog::open(&log_dir).expect("log");
    let index = RedbEdgeIndex::open(dir.join("index.redb")).expect("index");
    ContentStore::open(log, index).expect("store")
}

/// §1.2/§3.2: A besitzt B ⇒ owner(A)→B und referrer(B)→A; beide Richtungen.
#[test]
fn owner_and_referrer_edges_are_recorded() {
    let dir = tempdir().unwrap();
    let mut store = open_store(dir.path());

    let b_id = store.append_datum(&Datum::leaf(b"B".to_vec())).unwrap();
    let a = Datum::node([b_id]).unwrap();
    let a_id = store.append_datum(&a).unwrap();

    assert_eq!(store.index().contexts_of(a_id).unwrap(), vec![b_id]);
    assert_eq!(store.index().referrers_of(b_id).unwrap(), vec![a_id]);
}

/// §5.3: zweimal dasselbe Daten ⇒ EIN physischer Record; Dedup-Treffer gezählt.
#[test]
fn appending_identical_datum_twice_writes_one_record() {
    let dir = tempdir().unwrap();
    let mut store = open_store(dir.path());
    let d = Datum::leaf(b"value-identity".to_vec());

    let id1 = store.append_datum(&d).unwrap();
    let committed_after_first = store.log_metrics().committed_bytes;
    let id2 = store.append_datum(&d).unwrap();

    assert_eq!(id1, id2);
    assert_eq!(id1, ContentId::of_datum(&d));
    // Log-Länge unverändert ⇒ kein zweiter Record.
    assert_eq!(committed_after_first, store.log_metrics().committed_bytes);
    assert_eq!(store.log_metrics().append_count, 1);
    assert_eq!(store.metrics().dedup_hit_count, 1);
}

/// §8.4 operationalisiert: Index löschen, aus dem Log neu bauen ⇒ identisch.
#[test]
fn wipe_and_rebuild_yields_identical_index() {
    let dir = tempdir().unwrap();
    let mut store = open_store(dir.path());

    let l1 = store.append_datum(&Datum::leaf(b"l1".to_vec())).unwrap();
    let l2 = store.append_datum(&Datum::leaf(b"l2".to_vec())).unwrap();
    let n1 = store.append_datum(&Datum::node([l1, l2]).unwrap()).unwrap();
    let n2 = store.append_datum(&Datum::node([n1]).unwrap()).unwrap();

    let ids = [l1, l2, n1, n2];
    let snapshot = |s: &ContentStore<RedbEdgeIndex>| -> Vec<(Vec<ContentId>, Vec<ContentId>)> {
        ids.iter()
            .map(|id| {
                (
                    s.index().contexts_of(*id).unwrap(),
                    s.index().referrers_of(*id).unwrap(),
                )
            })
            .collect()
    };
    let before = snapshot(&store);
    store.rebuild_index_from_log().unwrap();
    let after = snapshot(&store);
    assert_eq!(before, after, "neu gebauter Index identisch (§8.4)");
}

/// §5.2-Fetch über die **öffentliche, gegatete** API (§11.2/§11.5): der einzige
/// externe Lese-Pfad geht durch das Tor — `get_by_content_id` liefert ein opakes
/// `SealedRecord`, und nur `open` (gegen eine vom Kernel ausgestellte `Capability`)
/// legt die kanonischen Bytes frei. Ungegateter Roh-Byte-Zugriff (`ContentStore::
/// get_by_content_id`/`get_canonical_bytes`) ist `pub(crate)` und damit von außen
/// **nicht** erreichbar.
#[test]
fn get_by_content_id_round_trips_through_the_gate() {
    let dir = tempdir().unwrap();
    let k = LakearchKernel::open(dir.path()).expect("open kernel");

    let d = Datum::node([
        k.append(&Datum::leaf(b"x".to_vec())).unwrap(),
        k.append(&Datum::leaf(b"y".to_vec())).unwrap(),
    ])
    .unwrap();
    let id = k.append(&d).unwrap();

    let snap = k.pin_snapshot().unwrap();
    let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

    // Fetch durchs Tor: SealedRecord → open gegen die Capability → kanonische
    // Bytes → strikt dekodieren ⇒ Original (§5.2/§K6).
    let sealed = k
        .get_by_content_id(id, &cap, snap)
        .unwrap()
        .expect("vorhanden");
    assert_eq!(sealed.content_id(), id);
    let visible = open(&sealed, &cap).expect("Tor legt Inhalt frei");
    assert_eq!(
        lakearch_core::strict_decode(visible.canonical_bytes()).unwrap(),
        d
    );

    // Unbekannte ID ⇒ None (VANISH-Vorform; kein Orakel, §11.3).
    assert!(k
        .get_by_content_id(ContentId::from_bytes([0x00; 32]), &cap, snap)
        .unwrap()
        .is_none());
}

/// §8.4: nach Reopen ist der Store konsistent mit dem Log (Watermark W == T).
#[test]
fn reopen_is_consistent_with_log() {
    let dir = tempdir().unwrap();
    let (l1, n1);
    {
        let mut store = open_store(dir.path());
        l1 = store.append_datum(&Datum::leaf(b"p".to_vec())).unwrap();
        n1 = store.append_datum(&Datum::node([l1]).unwrap()).unwrap();
    }
    let store = open_store(dir.path());
    assert!(store.contains(l1));
    assert!(store.contains(n1));
    assert_eq!(store.index().contexts_of(n1).unwrap(), vec![l1]);
    assert_eq!(store.index().referrers_of(l1).unwrap(), vec![n1]);
    assert_eq!(
        store.index().watermark().unwrap(),
        store.log_metrics().committed_bytes
    );
}
