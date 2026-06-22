//! Die konkrete **Kernel-Implementierung** ([`LakearchKernel`]) — die
//! Verdrahtung der Phase-1-Verben des eingefrorenen [`crate::api::Kernel`]-
//! Vertrags an den durablen Speicher.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2/§5.3 Identität &
//! Dedup; §7.1 append-only als einzige Mutation; §8.4 Log = alleinige Wahrheit;
//! §11 das Zugriffs-Tor) und der gehärtete Plan (Abschnitte „Kernel-API-Vertrag",
//! „Durability, Recovery & Atomarität", „Betrieb & Beobachtbarkeit").
//!
//! ## Was diese Phase verdrahtet
//!
//! - **[`Kernel::append`]** (§7.1) — die **einzige** Mutation: ein Daten samt
//!   seinen besessenen Kontexten kommt hinzu; Content-Dedup (§5.3) schreibt
//!   nichts und verbraucht keine seq; die abgeleiteten Kanten werden **erst nach**
//!   dem Log-`fsync` in den Index committet (Ordnung log-fsync → index-commit,
//!   §8.4).
//! - **[`Kernel::get_by_content_id`]** (§5.2-Fetch) — geht durchs Tor (§11):
//!   liefert ein opakes [`SealedRecord`], dessen Inhalt **nur** [`crate::gate::open`]
//!   gegen eine [`Capability`] freilegt. So kann **kein** Aufrufer die Bytes ohne
//!   das (Phase-2-)Tor lesen.
//!
//! Die Snapshot-/Capability-Verben sind in dieser Phase **minimal** verdrahtet,
//! damit ein Ende-zu-Ende-Lesepfad existiert; ihre **volle** Semantik landet in
//! ihren Phasen (siehe je Verb). Alle übrigen Verben (Matching, Traversierung,
//! Anker, Provenance, Aktiv-Marker) bleiben die phasenrichtigen
//! [`KernelError::NotYetImplemented`]-Stubs des Trait-Defaults.
//!
//! ## Nebenläufigkeit (Phase 1)
//!
//! Der [`crate::store::ContentStore`] ist der **eine** Append-Pfad (`&mut self`).
//! Da der `Kernel`-Vertrag jeden Verb über `&self` führt, kapselt
//! [`LakearchKernel`] den Store hinter einem [`std::sync::RwLock`]: `append`
//! nimmt den Schreib-Lock, Lesepfade den Lese-Lock. Ein **vergifteter Lock**
//! (ein Panic hielt ihn) ⇒ [`KernelError::Poisoned`] (fail-closed, §11). Die volle
//! lock-freie MPSC-/Group-Commit-Pipeline folgt in einer späteren Phase.
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: das `unsafe` lebt allein im
//! `mmap`-Leaf [`crate::log`].

#![forbid(unsafe_code)]

use std::sync::RwLock;

use crate::api::{Kernel, SnapshotToken};
use crate::error::KernelError;
use crate::gate::{Capability, GrantedScopes, SealedRecord};
use crate::id::ContentId;
use crate::index::EdgeIndex;
use crate::log::SegmentLog;
use crate::model::Datum;
use crate::store::ContentStore;

/// Aggregierte **Betriebs-Zähler** des Kernels (§Betrieb). Reine Mechanik-Signale
/// (§1.4): keine Wertung, **keine** sichtbaren Daten/IDs/Bereiche in Labels
/// (sichtbarkeits-blind, §11.3).
///
/// Sie fasst die Zähler des [`crate::store::ContentStore`] und des
/// [`crate::log::SegmentLog`] zu **einer** Lese-Sicht zusammen, wie sie der
/// Betrieb/Backup-Layer braucht (Append-Zahl, Dedup-Treffer, `fsync`-Zahl,
/// Log-Bytes, Segmentzahl).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KernelMetrics {
    /// Anzahl **physisch geschriebener** Daten (neue Records; ohne Dedup-Treffer).
    pub append_count: u64,
    /// Anzahl **Dedup-Treffer** (§5.3): inhaltsgleiches `append`, das **nichts**
    /// geschrieben hat.
    pub dedup_hit_count: u64,
    /// Anzahl in den Index committeter Kanten (über alle Appends/Rebuilds).
    pub edge_count: u64,
    /// Anzahl committeter Batches (Group-Commit-`fsync`s der Daten).
    pub batch_count: u64,
    /// Anzahl `fsync`-Aufrufe (Daten **und** Verzeichnis) im Log.
    pub fsync_count: u64,
    /// Anzahl Segmente im Log (in v1 stets 1).
    pub segment_count: u64,
    /// Committete Log-Bytes (= durable Watermark `W`, der committed offset).
    pub committed_bytes: u64,
}

/// Die konkrete **Kernel-Implementierung**: besitzt den
/// [`crate::store::ContentStore`] (und damit das Segment-Log + den Content-Store +
/// die Kanten-Indizes) und implementiert die Phase-1-Verben des
/// [`Kernel`]-Vertrags.
///
/// Generisch über die [`EdgeIndex`]-Engine (billig revidierbar, §Storage-Engine);
/// die Standard-Konstruktion ([`LakearchKernel::open`]) nutzt die pure-Rust-redb-
/// Engine.
pub struct LakearchKernel<I: EdgeIndex> {
    /// Der Content-Store hinter einem Lese-/Schreib-Lock. Der Store ist der eine
    /// Append-Pfad (`&mut self`); der Lock erlaubt den `&self`-Vertrag des Traits.
    store: RwLock<ContentStore<I>>,
}

impl<I: EdgeIndex> LakearchKernel<I> {
    /// Baut einen Kernel über einem bereits geöffneten [`ContentStore`]. Beim
    /// Öffnen hat der Store seine reinen Derivate (Dedup-Karte, Index) bereits aus
    /// dem Log rekonstruiert/versöhnt (§8.4).
    pub fn from_store(store: ContentStore<I>) -> Self {
        LakearchKernel {
            store: RwLock::new(store),
        }
    }

    /// Aggregierte **Betriebs-Zähler** (§Betrieb). Liest sowohl die Store- als auch
    /// die Log-Metriken unter dem Lese-Lock zusammen.
    pub fn stats(&self) -> Result<KernelMetrics, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let sm = store.metrics();
        let lm = store.log_metrics();
        Ok(KernelMetrics {
            append_count: sm.append_count,
            dedup_hit_count: sm.dedup_hit_count,
            edge_count: sm.edge_count,
            batch_count: lm.batch_count,
            fsync_count: lm.fsync_count,
            segment_count: lm.segment_count,
            committed_bytes: lm.committed_bytes,
        })
    }
}

impl LakearchKernel<crate::index::RedbEdgeIndex> {
    /// Öffnet einen Kernel mit der Standard-Engine (redb) unter `dir`: ein
    /// Log-Verzeichnis `dir/log` und ein redb-Index `dir/index.redb`. Das
    /// Verzeichnis `dir` muss existieren.
    ///
    /// Beim Öffnen läuft die Log-Recovery (§Durability) und die Index-Versöhnung
    /// (§8.4); danach ist der Kernel betriebsbereit.
    pub fn open(dir: impl AsRef<std::path::Path>) -> Result<Self, KernelError> {
        let dir = dir.as_ref();
        let log_dir = dir.join("log");
        std::fs::create_dir_all(&log_dir).map_err(|_| KernelError::Io)?;
        let log = SegmentLog::open(&log_dir)?;
        let index = crate::index::RedbEdgeIndex::open(dir.join("index.redb"))?;
        let store = ContentStore::open(log, index)?;
        Ok(LakearchKernel::from_store(store))
    }
}

impl<I: EdgeIndex> Kernel for LakearchKernel<I> {
    /// **Phase 1.** Pinnt einen MVCC-Snapshot am aktuellen durablen Watermark `W`
    /// (= committed Log-Offset). Der Token ist der Lese-Handle für jede
    /// Read-Signatur (§8.4/§13).
    ///
    /// **Stand (Phase 1).** Der Token trägt nur die Watermark; die **volle**
    /// Epochen-/Sichtbarkeits-Semantik (§13: „strukturell-aktiv-im-Snapshot")
    /// landet in Phase 5. Reine Mechanik (§1.4), **kein** Wall-Clock-Vergleich.
    fn pin_snapshot(&self) -> Result<SnapshotToken, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        Ok(SnapshotToken::at_watermark(store.log_metrics().committed_bytes))
    }

    /// **Phase 1 (minimal).** Stellt für ein Subjekt (dessen [`GrantedScopes`])
    /// eine [`Capability`] aus — der unfälschbare Tor-Nachweis für
    /// [`Kernel::get_by_content_id`].
    ///
    /// **Stand (Phase 1).** Es wird **noch kein** strukturelles Berechtigungs-
    /// Matching gegen den Snapshot ausgeführt (das ist die Tor-Logik, Phase 2):
    /// die Capability bündelt allein die übergebenen Scopes, sodass der durchs
    /// Tor versiegelte Lesepfad schon Ende-zu-Ende existiert. `snapshot` wird
    /// formal entgegengenommen (jede Tor-Operation läuft über **dasselbe** S,
    /// §11.2), in Phase 2 dann ausgewertet.
    fn authorize(
        &self,
        scopes: GrantedScopes,
        snapshot: SnapshotToken,
    ) -> Result<Capability, KernelError> {
        // Phase 2: hier matcht das Tor die aktiven Berechtigungen im Snapshot
        // strukturell (§11.2/§1.3) und stellt erst dann eine Capability aus.
        let _ = snapshot;
        Ok(Capability::issue(scopes))
    }

    /// **append** (§7.1) — die **einzige** Mutation: genau ein neues Daten samt
    /// seinen besessenen Kontexten kommt hinzu (nie geändert, nie gelöscht).
    /// Inhaltsgleiches dedupliziert automatisch (§5.3) und schreibt **nichts**
    /// Neues. Liefert die [`ContentId`] des (ggf. schon vorhandenen) Daten.
    ///
    /// Die abgeleiteten Kanten (`owner→contexts` / `target→referrers`) werden
    /// **erst nach** dem Log-`fsync` in den Index committet (Ordnung log-fsync →
    /// index-commit, §8.4). `append` **rechnet und wertet nicht** (§7.3).
    fn append(&self, datum: &Datum) -> Result<ContentId, KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.append_datum(datum)
    }

    /// **get_by_content_id** (§5.2-Fetch) — geht **durchs Tor** (§11): liefert ein
    /// opakes [`SealedRecord`], dessen Inhalt **nur** [`crate::gate::open`] gegen
    /// die [`Capability`] freilegt. `None` ⇒ nicht vorhanden.
    ///
    /// **Stand (Phase 1).** Die Tor-**Sichtbarkeitslogik** (VANISH: verborgen und
    /// „nicht vorhanden" ununterscheidbar; Bereichs-Filter §11.3) ist Phase 2.
    /// Diese Phase liefert bereits den `SealedRecord`, sodass **kein** Aufrufer die
    /// Bytes ohne das (künftige) Tor lesen kann. `capability` und `snapshot`
    /// werden formal entgegengenommen; ihre Auswertung folgt in Phase 2/5.
    fn get_by_content_id(
        &self,
        id: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Option<SealedRecord>, KernelError> {
        // Phase 2/5: hier wertet das Tor `capability`/`snapshot` aus (Sichtbarkeit
        // + Snapshot-Epoche); in Phase 1 versiegeln wir den durablen Inhalt.
        let _ = (capability, snapshot);
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        store.get_sealed(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{open, GrantedScopes};
    use crate::index::RedbEdgeIndex;
    use crate::serialize::strict_decode;
    use tempfile::tempdir;

    /// Baut einen frischen Kernel (redb-Engine) in einem temporären Verzeichnis.
    fn open_kernel(dir: &std::path::Path) -> LakearchKernel<RedbEdgeIndex> {
        LakearchKernel::open(dir).expect("open kernel")
    }

    /// Mintet eine Capability + Snapshot über die Phase-1-Verben (so wie ein
    /// In-Process-Einbetter es täte).
    fn cap_and_snap(
        k: &LakearchKernel<RedbEdgeIndex>,
    ) -> (Capability, SnapshotToken) {
        let snap = k.pin_snapshot().expect("pin");
        let cap = k
            .authorize(GrantedScopes::from_scope_ids([]), snap)
            .expect("authorize");
        (cap, snap)
    }

    // ------------------------------------------------------------------------
    // Ende-zu-Ende: append → get_by_content_id → open → strikt dekodieren ⇒
    // dasselbe Daten (§5.2/§5.3 über das Tor, §11.5).
    // ------------------------------------------------------------------------

    #[test]
    fn append_then_get_round_trips_through_the_gate() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Ein kleiner Graph: zwei Blätter, ein Knoten, der beide besitzt.
        let x = k.append(&Datum::leaf(b"x".to_vec())).unwrap();
        let y = k.append(&Datum::leaf(b"y".to_vec())).unwrap();
        let node = Datum::node([x, y]).unwrap();
        let node_id = k.append(&node).unwrap();
        assert_eq!(node_id, ContentId::of_datum(&node));

        let (cap, snap) = cap_and_snap(&k);

        // Fetch durchs Tor: SealedRecord, dann open gegen die Capability.
        let sealed = k
            .get_by_content_id(node_id, &cap, snap)
            .unwrap()
            .expect("vorhanden");
        assert_eq!(sealed.content_id(), node_id);
        let visible = open(&sealed, &cap).expect("Tor legt Inhalt frei");
        assert_eq!(visible.content_id(), node_id);

        // Die freigelegten kanonischen Bytes dekodieren strikt zum Original (§K6).
        let decoded = strict_decode(visible.canonical_bytes()).unwrap();
        assert_eq!(decoded, node);
    }

    // ------------------------------------------------------------------------
    // VANISH-Vorform: unbekannte ID ⇒ None (Phase 2 macht „verborgen" hiervon
    // ununterscheidbar). Kein Panik, kein Orakel auf dieser Ebene.
    // ------------------------------------------------------------------------

    #[test]
    fn get_unknown_id_is_none() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let (cap, snap) = cap_and_snap(&k);
        let missing = ContentId::from_bytes([0xEE; 32]);
        assert!(k.get_by_content_id(missing, &cap, snap).unwrap().is_none());
    }

    // ------------------------------------------------------------------------
    // Dedup spiegelt sich in den Stats (§5.3): zweimal dasselbe Daten ⇒ ein
    // Append, ein Dedup-Treffer; Log-Bytes unverändert nach dem zweiten append.
    // ------------------------------------------------------------------------

    #[test]
    fn dedup_is_reflected_in_stats() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let d = Datum::leaf(b"once".to_vec());

        let id1 = k.append(&d).unwrap();
        let after_first = k.stats().unwrap();
        assert_eq!(after_first.append_count, 1);
        assert_eq!(after_first.dedup_hit_count, 0);
        let bytes_after_first = after_first.committed_bytes;

        // Zweites identisches append: Dedup-Treffer, kein neuer Record.
        let id2 = k.append(&d).unwrap();
        assert_eq!(id1, id2, "inhaltsgleich ⇒ dieselbe ContentId (§5.3)");

        let after_second = k.stats().unwrap();
        assert_eq!(after_second.append_count, 1, "kein zweiter physischer Record");
        assert_eq!(after_second.dedup_hit_count, 1, "ein Dedup-Treffer gezählt");
        assert_eq!(
            after_second.committed_bytes, bytes_after_first,
            "Dedup-Treffer schreibt nichts (Log-Bytes unverändert)"
        );
        // Plausible Log-Zähler: ein Batch (ein append_and_commit), fsyncs > 0.
        assert_eq!(after_second.batch_count, 1);
        assert!(after_second.fsync_count >= 1);
        assert_eq!(after_second.segment_count, 1);
    }

    // ------------------------------------------------------------------------
    // Reopen von Platte: nach Drop + Neu-Öffnen sind die Daten durabel lesbar,
    // die Kanten rekonstruiert (§8.4) und die committeten Bytes konsistent.
    // ------------------------------------------------------------------------

    #[test]
    fn reopen_from_disk_reads_back() {
        let dir = tempdir().unwrap();
        let (leaf_id, node_id, committed);
        {
            let k = open_kernel(dir.path());
            leaf_id = k.append(&Datum::leaf(b"persist".to_vec())).unwrap();
            let node = Datum::node([leaf_id]).unwrap();
            node_id = k.append(&node).unwrap();
            committed = k.stats().unwrap().committed_bytes;
        } // Kernel gedroppt → Log/Index geschlossen.

        // Neu öffnen: Recovery + Index-Versöhnung beim Öffnen.
        let k = open_kernel(dir.path());
        let stats = k.stats().unwrap();
        // Committete Bytes überstehen den Reopen (Watermark = durabler Tail).
        assert_eq!(stats.committed_bytes, committed);
        // append_count ist ein Mechanik-Zähler des laufenden Prozesses; nach einem
        // frischen Reopen ohne neue Appends ist er 0 (die Daten sind durabel, der
        // Zähler aber nicht persistiert — er zählt physische Schreibvorgänge).
        assert_eq!(stats.append_count, 0);

        let (cap, snap) = cap_and_snap(&k);

        // Beide Daten sind durabel über das Tor lesbar.
        let leaf_sealed = k
            .get_by_content_id(leaf_id, &cap, snap)
            .unwrap()
            .expect("Blatt durabel");
        let leaf_visible = open(&leaf_sealed, &cap).unwrap();
        assert_eq!(
            strict_decode(leaf_visible.canonical_bytes()).unwrap(),
            Datum::leaf(b"persist".to_vec())
        );

        let node_sealed = k
            .get_by_content_id(node_id, &cap, snap)
            .unwrap()
            .expect("Knoten durabel");
        let node_visible = open(&node_sealed, &cap).unwrap();
        assert_eq!(
            strict_decode(node_visible.canonical_bytes()).unwrap(),
            Datum::node([leaf_id]).unwrap()
        );

        // Erneutes append desselben Knotens nach Reopen ⇒ Dedup-Treffer (die
        // Dedup-Karte wurde aus dem Log rekonstruiert, §8.4).
        let again = k.append(&Datum::node([leaf_id]).unwrap()).unwrap();
        assert_eq!(again, node_id);
        assert_eq!(k.stats().unwrap().dedup_hit_count, 1);
    }

    // ------------------------------------------------------------------------
    // Phasen-Disziplin: die nicht verdrahteten Verben melden weiterhin ihre
    // Phase (NotYetImplemented), kein Verb panickt.
    // ------------------------------------------------------------------------

    #[test]
    fn unwired_verbs_still_report_their_phase() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();
        let a = ContentId::from_bytes([0x01; 32]);
        let b = ContentId::from_bytes([0x02; 32]);

        assert!(matches!(
            k.content_equal(a, b, snap),
            Err(KernelError::NotYetImplemented(2))
        ));
        assert!(matches!(
            k.context_points_to(a, b, snap),
            Err(KernelError::NotYetImplemented(2))
        ));
        assert!(matches!(
            k.is_member_of_set(a, b, snap),
            Err(KernelError::NotYetImplemented(2))
        ));
        assert!(matches!(
            k.set_active_marker(&[a, b]),
            Err(KernelError::NotYetImplemented(5))
        ));
        assert!(matches!(
            k.find_dependents(a, snap).err(),
            Some(KernelError::NotYetImplemented(6))
        ));
    }
}
