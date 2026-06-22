//! Der **Content-Store** (§5.2/§5.3) — die Brücke zwischen dem abstrakten Daten
//! ([`crate::model::Datum`]) und dem durablen Append-Segment-Log
//! ([`crate::log::SegmentLog`]), plus die abgeleiteten Kanten-Indizes
//! ([`crate::index::EdgeIndex`]).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2 Speicher-Identität;
//! §5.3 Wert-Identität/Dedup; §7.1 append-only; §8.4 Log = alleinige Wahrheit)
//! und der gehärtete Plan (Abschnitte „Identitäts- & Hashing-Modell", „Log-als-
//! alleinige-Wahrheit + neu-baubarer Index").
//!
//! ## Was der Store tut (rein mechanisch, §1.4)
//!
//! - **[`ContentStore::append_datum`]** (§7.1): kanonisiert das Daten
//!   ([`crate::serialize::canonical_cbor`]), bildet seine [`ContentId`]
//!   ([`ContentId::of_datum`], §K5) und **dedupliziert** (§5.3): existiert die
//!   `ContentId` schon, wird **nichts** geschrieben und **keine** seq verbraucht —
//!   die vorhandene ID kommt zurück. Andernfalls wird der gerahmte Record an das
//!   Log angehängt **und committet** (Log-`fsync`); **erst danach** werden die
//!   abgeleiteten Kanten in den Index committet (Ordnung **log-fsync →
//!   index-commit**, §8.4).
//! - **[`ContentStore::get_by_content_id`]** (§5.2-Fetch): schlägt die `ContentId`
//!   in der (aus dem Log gebauten) Dedup-Karte nach und liest den durablen Record
//!   über das read-only-`mmap` des Logs zurück; die Prüfsumme ist dabei
//!   verifiziert (§Durability). Liefert die kanonischen Bytes bzw. das
//!   strikt-dekodierte [`Datum`] (§K6).
//!
//! ## Log-als-Wahrheit (§8.4): Dedup-Karte + Index sind reine Derivate
//!
//! Die **Dedup-Karte** (`ContentId → Record-Offset`) und **beide** Kanten-Indizes
//! sind **reine, neu-baubare** Projektionen über das Log. Beim Öffnen werden sie
//! aus dem Log **rekonstruiert/versöhnt**:
//! - Dedup-Karte: immer vollständig aus dem Log gebaut (sie ist klein und
//!   in-memory; das Log ist die Wahrheit, §8.4).
//! - Index: Watermark `W` (im Index persistiert) vs. durabler Log-Tail `T`:
//!   `W < T` ⇒ `[W..T)` nachspielen; `W > T` ⇒ Index unsicher ⇒ voller Neu-Bau
//!   ([`ContentStore::rebuild_index_from_log`]); `W == T` ⇒ in sync. **Keine**
//!   Suffix-Chirurgie (§8.4).
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: das `unsafe` lebt allein im
//! `mmap`-Leaf [`crate::log`].

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::error::KernelError;
use crate::gate::SealedRecord;
use crate::id::ContentId;
use crate::index::{Edge, EdgeIndex};
use crate::log::SegmentLog;
use crate::model::Datum;
use crate::serialize::{canonical_cbor, strict_decode};

/// Leichtgewichtige **Betriebs-Zähler** des Stores (§Betrieb). Reine Mechanik
/// (§1.4); keine Wertung, keine sichtbaren Daten/IDs in Labels.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StoreMetrics {
    /// Anzahl **physisch geschriebener** Daten (neue Records; ohne Dedup-Treffer).
    pub append_count: u64,
    /// Anzahl **Dedup-Treffer** (§5.3): inhaltsgleiches `append_datum`, das
    /// **nichts** geschrieben hat.
    pub dedup_hit_count: u64,
    /// Anzahl in den Index committeter Kanten (über alle Appends/Rebuilds).
    pub edge_count: u64,
}

/// Der **Content-Store**: Append + Dedup über dem Log, plus die abgeleiteten
/// Kanten-Indizes. Generisch über die [`EdgeIndex`]-Engine (billig revidierbar,
/// §Storage-Engine).
///
/// **Nebenläufigkeit (Phase 1).** Wie [`SegmentLog`] ist dies der **eine**
/// Append-Pfad (`&mut self` für Mutationen); die volle MPSC-Pipeline folgt später.
pub struct ContentStore<I: EdgeIndex> {
    /// Das Append-Segment-Log — die **alleinige** Durability-Wahrheit (§8.4).
    log: SegmentLog,
    /// Die Kanten-Index-Engine — reines, neu-baubares Derivat (§8.4).
    index: I,
    /// In-memory **Dedup-Karte** `ContentId → Record-Offset` (§5.3). Reines
    /// Derivat aus dem Log; beim Öffnen rekonstruiert.
    dedup: HashMap<ContentId, u64>,
    /// Betriebs-Zähler (§Betrieb).
    metrics: StoreMetrics,
}

impl<I: EdgeIndex> ContentStore<I> {
    /// Öffnet einen Store über einem bereits geöffneten Log und Index. Baut die
    /// Dedup-Karte vollständig aus dem Log und **versöhnt** den Index mit dem
    /// durablen Log-Tail (§8.4): `W < T` ⇒ nachspielen, `W > T` ⇒ voller Neu-Bau.
    pub fn open(log: SegmentLog, index: I) -> Result<Self, KernelError> {
        let mut store = ContentStore {
            log,
            index,
            dedup: HashMap::new(),
            metrics: StoreMetrics::default(),
        };
        store.rebuild_dedup_from_log()?;
        store.reconcile_index_with_log()?;
        Ok(store)
    }

    /// **append** (§7.1) — die einzige Mutation: kanonisiert `datum`, bildet seine
    /// [`ContentId`] (§K5) und **dedupliziert** (§5.3).
    ///
    /// - **Dedup-Treffer:** die `ContentId` existiert bereits ⇒ es wird **nichts**
    ///   geschrieben, **keine** seq verbraucht, und die vorhandene ID kommt zurück
    ///   ([`StoreMetrics::dedup_hit_count`] +1).
    /// - **Neu:** der gerahmte Record (kanonisches CBOR als Nutzlast) wird an das
    ///   Log angehängt **und committet** (Log-`fsync`, Durability-on-Ack);
    ///   **erst danach** werden die abgeleiteten Kanten (für einen besitzenden
    ///   Knoten) in den Index committet (Ordnung **log-fsync → index-commit**,
    ///   §8.4). Liefert die `ContentId` des neuen Daten.
    ///
    /// `append` **rechnet und wertet nicht** (§7.3): es findet **nicht** den Platz
    /// und beurteilt **nicht** die Verbindung (§7.2).
    pub fn append_datum(&mut self, datum: &Datum) -> Result<ContentId, KernelError> {
        let id = ContentId::of_datum(datum);

        // §5.3-Dedup: existiert das Daten schon, schreibe NICHTS und gib die
        // vorhandene ID zurück (ein primitives Daten existiert genau einmal).
        if self.dedup.contains_key(&id) {
            self.metrics.dedup_hit_count += 1;
            return Ok(id);
        }

        // Neu: kanonische Bytes (= Nutzlast des Records, §K5) ans Log anhängen und
        // committen (Log-`fsync` ZUERST, §8.4).
        let cbor = canonical_cbor(datum);
        let offset = self.log.committed_offset();
        self.log.append_and_commit(&cbor)?;
        self.dedup.insert(id, offset);
        self.metrics.append_count += 1;

        // ERST NACH dem Log-`fsync`: die abgeleiteten Kanten in den Index committen
        // (Ordnung log-fsync → index-commit, §8.4). Watermark = neuer committed
        // Log-Offset.
        let edges = edges_of(id, datum);
        let new_watermark = self.log.committed_offset();
        self.index.commit_edges(&edges, new_watermark)?;
        self.metrics.edge_count += edges.len() as u64;

        Ok(id)
    }

    /// **get_canonical_bytes** (§5.2-Fetch, **un-gated**) — liefert die **kanonischen
    /// Bytes** des durablen Daten, falls vorhanden (sonst `None`). Die Prüfsumme ist
    /// beim Lesen verifiziert (§Durability).
    ///
    /// **`pub(crate)` mit Absicht (§11.2/§11.5).** Diese Methode gibt die Roh-Bytes
    /// **ohne** das Zugriffs-Tor heraus; sie ist daher **nicht** Teil der externen
    /// Crate-Oberfläche. Der **einzige** externe Lese-Pfad ist
    /// [`ContentStore::get_sealed`] (+ [`crate::gate::open`] gegen eine
    /// [`crate::gate::Capability`]) bzw. der [`crate::api::Kernel`]-Vertrag. Intern
    /// nutzen sie [`ContentStore::get_sealed`]/[`ContentStore::get_by_content_id`]
    /// und die Reconcile-/Rebuild-Pfade. So bleibt „ohne Tor lesen ist nicht
    /// darstellbar" eine Compile-Zeit-Eigenschaft (Tor-Modul-Doc, §11.5).
    pub(crate) fn get_canonical_bytes(&self, id: ContentId) -> Result<Option<Vec<u8>>, KernelError> {
        let offset = match self.dedup.get(&id) {
            Some(o) => *o,
            None => return Ok(None),
        };
        let rec = self.log.read_at(offset)?;
        Ok(Some(rec.payload))
    }

    /// **get_by_content_id** als strikt-dekodiertes [`Datum`] (§K6, **un-gated**).
    /// Liefert `None`, wenn die `ContentId` nicht im Store ist. Eine Inkonsistenz
    /// zwischen gespeicherter ID und dekodierten Bytes (dürfte nach erfolgreicher
    /// Recovery nie auftreten) ist [`KernelError::Inconsistent`] — **nie** still
    /// ignoriert.
    ///
    /// **`pub(crate)`, nur Tests (§11.2/§11.5).** Wie [`ContentStore::get_canonical_bytes`]
    /// gibt diese Methode ein **vollständig dekodiertes** [`Datum`] **ohne** das Tor
    /// heraus. Sie wird ausschließlich von crate-internen Tests genutzt (in denen
    /// roher, gate-loser Zugriff legitim ist) und ist daher `#[cfg(test)]`. Der
    /// externe Lese-Pfad ist [`ContentStore::get_sealed`] + das Tor.
    #[cfg(test)]
    pub(crate) fn get_by_content_id(&self, id: ContentId) -> Result<Option<Datum>, KernelError> {
        let bytes = match self.get_canonical_bytes(id)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let datum = strict_decode(&bytes)?;
        // Defensiv (§Durability): die zurückgelesene Form muss dieselbe ID tragen.
        if ContentId::of_datum(&datum) != id {
            return Err(KernelError::Inconsistent);
        }
        Ok(Some(datum))
    }

    /// **get_sealed** (§5.2-Fetch durchs Tor) — liefert ein opakes
    /// [`crate::gate::SealedRecord`] für die durablen kanonischen Bytes der
    /// `ContentId`, falls vorhanden (sonst `None`). Der Inhalt ist **versiegelt**:
    /// nur [`crate::gate::open`] gegen eine [`crate::gate::Capability`] legt ihn
    /// frei (§11.5). Die Prüfsumme ist beim Lesen verifiziert (§Durability).
    ///
    /// **Stand (Phase 1).** Hier wird **noch keine** Sichtbarkeit ausgewertet
    /// (VANISH/Bereichs-Filter = Phase 2); das Versiegeln stellt allein sicher,
    /// dass kein Aufrufer die Bytes **ohne** das künftige Tor liest. `None` ⇒
    /// nicht vorhanden (ab Phase 2 zusätzlich „oder nicht sichtbar", ununter-
    /// scheidbar).
    pub fn get_sealed(&self, id: ContentId) -> Result<Option<SealedRecord>, KernelError> {
        match self.get_canonical_bytes(id)? {
            Some(bytes) => Ok(Some(SealedRecord::seal(id, bytes))),
            None => Ok(None),
        }
    }

    /// `true`, wenn die `ContentId` durabel im Store vorhanden ist (§5.2). Reines
    /// Adress-Matching (§1.3); keine Wertung.
    pub fn contains(&self, id: ContentId) -> bool {
        self.dedup.contains_key(&id)
    }

    /// Anzahl distinkter durabler Daten (= Größe der Dedup-Karte).
    pub fn len(&self) -> usize {
        self.dedup.len()
    }

    /// `true`, wenn der Store leer ist.
    pub fn is_empty(&self) -> bool {
        self.dedup.is_empty()
    }

    /// Betriebs-Zähler des Stores (§Betrieb).
    pub fn metrics(&self) -> StoreMetrics {
        self.metrics
    }

    /// Lese-Sicht auf die Log-Metriken (§Betrieb).
    pub fn log_metrics(&self) -> crate::log::LogMetrics {
        self.log.metrics()
    }

    /// Lese-Zugriff auf die Index-Engine (für Traversierung/Tests; liefert owned
    /// `ContentId`s, §EdgeIndex).
    pub fn index(&self) -> &I {
        &self.index
    }

    // -- Neu-Bau / Versöhnung (§8.4) -----------------------------------------

    /// **rebuild_index_from_log** (§8.4 operationalisiert) — **wipet** den Index
    /// und baut **beide** Kanten-Richtungen aus dem **gesamten** Log neu auf
    /// (`owner→contexts` / `target→referrers`). Nach dem Neu-Bau steht das
    /// Watermark wieder am durablen Log-Tail.
    ///
    /// Der Neu-Bau ist der Beleg dafür, dass der Index ein **reines Derivat** ist:
    /// ein gewipter, neu gebauter Index hat **denselben** Inhalt wie der zuvor
    /// inkrementell gepflegte (Test `wipe_and_rebuild_is_identical`).
    pub fn rebuild_index_from_log(&mut self) -> Result<(), KernelError> {
        self.index.wipe()?;
        let records = self.log.read_all()?;
        let mut edges: Vec<Edge> = Vec::new();
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            edges.extend(edges_of(id, &datum));
        }
        // Den ganzen Neu-Bau in EINEM Index-Commit ablegen; Watermark = durabler
        // Log-Tail (alles nachgezogen).
        let watermark = self.log.committed_offset();
        self.index.commit_edges(&edges, watermark)?;
        // edge_count zählt nur inkrementelle Appends; ein Rebuild setzt ihn nicht
        // zurück (Mechanik-Zähler, §1.4) — wir vermerken die neu committeten Kanten.
        self.metrics.edge_count = self.metrics.edge_count.saturating_add(edges.len() as u64);
        Ok(())
    }

    /// Baut die in-memory **Dedup-Karte** (`ContentId → Offset`) vollständig aus
    /// dem Log neu (§8.4: Log = Wahrheit). Idempotent.
    fn rebuild_dedup_from_log(&mut self) -> Result<(), KernelError> {
        self.dedup.clear();
        let records = self.log.read_all()?;
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            // Erstes Vorkommen gewinnt (eine ContentId existiert genau einmal,
            // §5.3; ein zweiter physischer Record gleicher ID wäre ein Dedup-
            // Fehler oberhalb — er käme hier nie zustande).
            self.dedup.entry(id).or_insert(rec.offset);
        }
        Ok(())
    }

    /// **Versöhnt** den Index mit dem durablen Log-Tail (§8.4-Recovery-
    /// Reconciliation). Watermark `W` vs. committed Log-Offset `T`:
    /// - `W == T` ⇒ in sync, nichts zu tun.
    /// - `W < T` ⇒ Normal-Lag ⇒ Records ab Offset `W` nachspielen, Watermark auf
    ///   `T` setzen.
    /// - `W > T` ⇒ der Index raste einem verlorenen Log-`fsync` voraus ⇒ Index
    ///   ist unsicher ⇒ **voller Neu-Bau** (keine Suffix-Chirurgie, §8.4).
    fn reconcile_index_with_log(&mut self) -> Result<(), KernelError> {
        let w = self.index.watermark()?;
        let t = self.log.committed_offset();
        if w == t {
            return Ok(());
        }
        if w > t {
            // Index lief dem Log voraus → komplett neu bauen.
            return self.rebuild_index_from_log();
        }
        // w < t: nur die Records ab Offset `w` nachspielen.
        let records = self.log.read_all()?;
        let mut edges: Vec<Edge> = Vec::new();
        for rec in &records {
            if rec.offset < w {
                continue;
            }
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            edges.extend(edges_of(id, &datum));
        }
        self.index.commit_edges(&edges, t)?;
        self.metrics.edge_count = self.metrics.edge_count.saturating_add(edges.len() as u64);
        Ok(())
    }
}

/// Die abgeleiteten **Kanten** eines Daten (§3.2): für einen besitzenden Knoten
/// `A` mit `owns = { K_1, …, K_n }` je eine Kante `A ⊳ K_i`. Ein Blatt hat
/// **keine** Kanten (es besitzt nichts, §K2.1).
///
/// Reines mechanisches Ableiten (§1.4): es wird nichts gewertet, nichts
/// validiert — die `owns`-Menge ist schon kanonisch sortiert/dedupliziert
/// (§K2.3).
fn edges_of(owner: ContentId, datum: &Datum) -> Vec<Edge> {
    match datum.owns() {
        Some(owns) => owns
            .iter()
            .map(|ctx| Edge {
                owner,
                context: *ctx,
            })
            .collect(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::RedbEdgeIndex;
    use tempfile::tempdir;

    /// Baut einen frischen Store (Log + redb-Index) in `dir`.
    fn open_store(dir: &std::path::Path) -> ContentStore<RedbEdgeIndex> {
        let log_dir = dir.join("log");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let log = SegmentLog::open(&log_dir).expect("log");
        let index = RedbEdgeIndex::open(dir.join("index.redb")).expect("index");
        ContentStore::open(log, index).expect("store")
    }

    #[test]
    fn append_two_data_owner_and_referrer_edges() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // B ist ein Blatt; A ist ein Knoten, der B besitzt.
        let b = Datum::leaf(b"target".to_vec());
        let b_id = store.append_datum(&b).unwrap();
        let a = Datum::node([b_id]).unwrap();
        let a_id = store.append_datum(&a).unwrap();

        // owner(A) → B und referrer(B) → A.
        assert_eq!(store.index().contexts_of(a_id).unwrap(), vec![b_id]);
        assert_eq!(store.index().referrers_of(b_id).unwrap(), vec![a_id]);
        // Beide Daten sind durabel lesbar.
        assert_eq!(store.get_by_content_id(b_id).unwrap(), Some(b));
        assert_eq!(store.get_by_content_id(a_id).unwrap(), Some(a));
    }

    #[test]
    fn append_returns_stable_content_id_and_get_round_trips() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = Datum::leaf(b"lakearch".to_vec());
        let id = store.append_datum(&d).unwrap();
        // §K5: die zurückgegebene ID ist die ContentId des Daten.
        assert_eq!(id, ContentId::of_datum(&d));
        // §5.2-Fetch: kanonische Bytes round-trippen.
        assert_eq!(
            store.get_canonical_bytes(id).unwrap(),
            Some(canonical_cbor(&d))
        );
        assert_eq!(store.get_by_content_id(id).unwrap(), Some(d));
        // Unbekannte ID ⇒ None (kein Panik, kein Orakel auf dieser Ebene).
        assert_eq!(
            store.get_by_content_id(ContentId::from_bytes([0xFE; 32])).unwrap(),
            None
        );
    }

    // ------------------------------------------------------------------------
    // Dedup (§5.3): zweimal dasselbe Daten ⇒ EIN Record; Log-Länge unverändert,
    // Dedup-Zähler erhöht, keine seq verbraucht.
    // ------------------------------------------------------------------------

    #[test]
    fn dedup_writes_one_record_and_counts_the_hit() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = Datum::leaf(b"einmalig".to_vec());

        let id1 = store.append_datum(&d).unwrap();
        let log_after_first = store.log_metrics();
        let committed_after_first = store.log_metrics().committed_bytes;

        // Zweites identisches append: KEIN Record, KEINE seq, Dedup-Treffer.
        let id2 = store.append_datum(&d).unwrap();
        assert_eq!(id1, id2, "inhaltsgleich ⇒ dieselbe ContentId (§5.3)");

        let log_after_second = store.log_metrics();
        // Log-Länge unverändert.
        assert_eq!(
            committed_after_first, log_after_second.committed_bytes,
            "Dedup-Treffer schreibt nichts (Log-Länge unverändert, §5.3)"
        );
        // Genau ein physischer Record / eine seq.
        assert_eq!(log_after_first.append_count, 1);
        assert_eq!(log_after_second.append_count, 1);
        // Store-Metriken: ein Append, ein Dedup-Treffer.
        assert_eq!(store.metrics().append_count, 1);
        assert_eq!(store.metrics().dedup_hit_count, 1);
        assert_eq!(store.len(), 1, "genau ein distinktes Daten");
    }

    // ------------------------------------------------------------------------
    // Watermark schreitet monoton voran (über mehrere Appends).
    // ------------------------------------------------------------------------

    #[test]
    fn watermark_advances_monotonically_over_appends() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let mut last = store.index().watermark().unwrap();
        assert_eq!(last, 0);
        for i in 0..5u8 {
            store.append_datum(&Datum::leaf(vec![i])).unwrap();
            let w = store.index().watermark().unwrap();
            assert!(w >= last, "Watermark nicht-fallend (§8.4)");
            // Nach jedem neuen Record ist das Watermark = committed Log-Offset.
            assert_eq!(w, store.log_metrics().committed_bytes);
            last = w;
        }
        assert!(last > 0);
    }

    // ------------------------------------------------------------------------
    // WIPE-AND-REBUILD (§8.4): Index löschen, aus dem Log neu bauen ⇒ identischer
    // Inhalt (operationalisiert „Log = alleinige Wahrheit").
    // ------------------------------------------------------------------------

    #[test]
    fn wipe_and_rebuild_is_identical() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // Ein kleiner Graph: drei Blätter, ein Knoten der zwei besitzt, ein Knoten
        // der den Knoten besitzt (Reifikation, §3.4) — beide Richtungen entstehen.
        let l1 = store.append_datum(&Datum::leaf(b"l1".to_vec())).unwrap();
        let l2 = store.append_datum(&Datum::leaf(b"l2".to_vec())).unwrap();
        let l3 = store.append_datum(&Datum::leaf(b"l3".to_vec())).unwrap();
        let n1 = store.append_datum(&Datum::node([l1, l2]).unwrap()).unwrap();
        let _n2 = store.append_datum(&Datum::node([n1, l3]).unwrap()).unwrap();

        // Schnappschuss aller owner→contexts UND target→referrers VOR dem Wipe.
        let all_ids = [l1, l2, l3, n1, _n2];
        let before: Vec<(Vec<ContentId>, Vec<ContentId>)> = all_ids
            .iter()
            .map(|id| {
                (
                    store.index().contexts_of(*id).unwrap(),
                    store.index().referrers_of(*id).unwrap(),
                )
            })
            .collect();
        let wm_before = store.index().watermark().unwrap();

        // Wipe + Neu-Bau aus dem Log.
        store.rebuild_index_from_log().unwrap();

        let after: Vec<(Vec<ContentId>, Vec<ContentId>)> = all_ids
            .iter()
            .map(|id| {
                (
                    store.index().contexts_of(*id).unwrap(),
                    store.index().referrers_of(*id).unwrap(),
                )
            })
            .collect();
        assert_eq!(before, after, "neu gebauter Index ist identisch (§8.4)");
        // Watermark wieder am durablen Log-Tail.
        assert_eq!(store.index().watermark().unwrap(), wm_before);
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reopen: nach Crash/Neustart ist der Store (Dedup + Index) konsistent mit dem
    // Log — Reconciliation versöhnt das Watermark, ohne Suffix-Chirurgie.
    // ------------------------------------------------------------------------

    #[test]
    fn reopen_recovers_store_consistent_with_log() {
        let dir = tempdir().unwrap();
        let l1;
        let n1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"persist".to_vec())).unwrap();
            n1 = store.append_datum(&Datum::node([l1]).unwrap()).unwrap();
        }
        // Reopen Log + Index (beide durabel) → Store rekonstruiert Dedup + versöhnt
        // den Index.
        let store = open_store(dir.path());
        assert!(store.contains(l1));
        assert!(store.contains(n1));
        assert_eq!(store.len(), 2);
        // Kanten sind nach Reopen unverändert.
        assert_eq!(store.index().contexts_of(n1).unwrap(), vec![l1]);
        assert_eq!(store.index().referrers_of(l1).unwrap(), vec![n1]);
        // Watermark ist nach Reopen = durabler Log-Tail (W == T, in sync).
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reconciliation: ein Index, der dem Log NACHHÄNGT (W < T), wird beim Öffnen
    // nachgespielt — OHNE Wipe (Normal-Lag).
    // ------------------------------------------------------------------------

    #[test]
    fn lagging_index_is_replayed_on_open() {
        let dir = tempdir().unwrap();
        // Erst Daten ins LOG schreiben, den Index aber NICHT mit-pflegen, um Lag
        // zu simulieren: wir öffnen einen Store, hängen an, und löschen dann den
        // Index per Wipe (W → 0), während das Log seine Records behält.
        let l1;
        let n1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"a".to_vec())).unwrap();
            n1 = store.append_datum(&Datum::node([l1]).unwrap()).unwrap();
            // Index künstlich auf 0 zurücksetzen (simuliert verlorenen Index-Tail).
            store.index.wipe().unwrap();
            assert_eq!(store.index().watermark().unwrap(), 0);
            assert!(store.index().contexts_of(n1).unwrap().is_empty());
        }
        // Reopen: W (0) < T ⇒ Reconciliation spielt den ganzen Log nach.
        let store = open_store(dir.path());
        assert_eq!(store.index().contexts_of(n1).unwrap(), vec![l1]);
        assert_eq!(store.index().referrers_of(l1).unwrap(), vec![n1]);
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reconciliation: ein Index, der dem Log VORAUSEILT (W > T), wird voll neu
    // gebaut (keine Suffix-Chirurgie, §8.4).
    // ------------------------------------------------------------------------

    #[test]
    fn index_ahead_of_log_triggers_full_rebuild() {
        let dir = tempdir().unwrap();
        let l1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"only".to_vec())).unwrap();
            // Index künstlich VORAUS setzen (W > committed Log-Offset), als ob ein
            // Index-Commit einem verlorenen Log-fsync vorausraste.
            let t = store.log_metrics().committed_bytes;
            store.index.commit_edges(&[], t + 10_000).unwrap();
            assert!(store.index().watermark().unwrap() > t);
        }
        // Reopen: W > T ⇒ voller Neu-Bau; Watermark wieder am Log-Tail, Inhalt korrekt.
        let store = open_store(dir.path());
        assert!(store.contains(l1));
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    #[test]
    fn leaf_has_no_edges() {
        // Ein Blatt besitzt nichts ⇒ keine Kanten in keiner Richtung (§K2.1).
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let id = store.append_datum(&Datum::leaf(b"atom".to_vec())).unwrap();
        assert!(store.index().contexts_of(id).unwrap().is_empty());
        assert!(store.index().referrers_of(id).unwrap().is_empty());
        assert_eq!(store.metrics().edge_count, 0);
    }
}
