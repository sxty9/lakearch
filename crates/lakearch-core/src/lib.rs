//! lakearch-core — Kernel-Substrat.
//!
//! Maßgeblich ist das Gesetzbuch `semantics/lakearch.md`; die eingefrorene
//! kanonische Kodierung steht in `semantics/canonical-encoding.md`. Dieses Crate
//! implementiert ausschließlich die Kernel-Primitive (§1–§13): speichern
//! (append), traversieren, strukturell matchen, das Zugriffs-Tor. Rechnen,
//! Werten und Sortieren liegen außerhalb (§1.4/§1.5).
//!
//! ## Aktueller Stand: Identitäts-Kern (Phase 0.5)
//!
//! - [`model`] — das abstrakte Daten-Modell (§2.1/§4.3): ein Daten ist
//!   **entweder** ein atomares Blatt **oder** ein besitzender Knoten mit einer
//!   sortiert-deduplizierten Menge besessener Kontext-IDs (§K2.1). Ein Kontext
//!   ist die **Rolle** eines besessenen Daten (§3.1), kein separater Typ.
//! - [`serialize`] — die kanonische CBOR-Kodierung (RFC 8949 Kerndeterminismus,
//!   explizit erzwungen; §K3/§K4). Ein zweiter, unabhängiger Encoder in den
//!   Integrationstests prüft Bytegleichheit (§K7).
//! - [`id`] — `ContentId = BLAKE3(DOMAIN_TAG_V1 || canonical_cbor(D))` (§K5):
//!   **ein** Hash als Adresse (§5.2), Dedup-Schlüssel (§5.3) und Föderations-
//!   Band (§12.3). `AnchorId` ist der bestand-lokale Anker-Handle (§9.1/§12.4).
//!
//! ## Typ-Verträge (Phase 0.5) — eingefrorene **Form**, Logik je Phase
//!
//! - [`gate`] — das **Zugriffs-Tor** (§11) als Typ-Skelett: `SealedRecord` ist
//!   opak (kein Inhalts-Getter), die **einzige** Funktion `SealedRecord →
//!   VisibleDatum` verlangt eine `Capability`, und `Capability`/`GrantedScopes`/
//!   `VisibleDatum` sind außerhalb des Tor-Moduls **nicht konstruierbar** →
//!   „ohne Tor lesen" ist ein **Compile-Fehler** (§11.5). Logik: Phase 2.
//! - [`api`] — der eingefrorene **Kernel-Vertrag** (§1): die drei §1.3-
//!   Prädikate getrennt, `traverse`/Anker-/Provenance-Verben (umbenannt), die
//!   einzigen Mutationen `append`/`set_active_marker`, ein opaker
//!   `SnapshotToken` an jeder Read-Signatur. Bodies sind Stubs je Phase.
//! - [`format`] — das **On-Disk-Format** des Append-Segment-Logs (§7.1): das
//!   gerahmte Record-Layout (`magic + format-version + checksum-algo-id + seq +
//!   payload-length` + reservierte NULL-Felder), der geprüfsummte Batch-Footer
//!   (Group-Commit) und die BLAKE3-Prüfsumme. Das Framing ist **getrennte**
//!   Metadaten und geht **nie** in den `ContentId`-Preimage ein (§K5). Reine
//!   in-memory Kodierung/Dekodierung; die Datei-I/O folgt in Phase 1.
//! - [`log`] — das **Append-Segment-Log** (§7.1) als alleinige Durability-
//!   Wahrheit (§8.4): `pwrite`-Schreibpfad, Group-Commit mit geprüfsummtem
//!   Footer, `fsync`-Durability-on-Ack (fsync-Fehler = fatal/poison), read-only
//!   `mmap` **nur** bis zum letzten committeten Footer, monotone seq je
//!   physischem Record und Recovery (Tail-Truncate nach dem letzten gültigen
//!   Footer; HALT bei Korruption davor). Einziges `unsafe`-Leaf-Modul (mmap).
//! - [`store`] — der **Content-Store** (§5.2/§5.3): `append_datum` kanonisiert +
//!   hasht + **dedupliziert** (§5.3: existiert die `ContentId`, wird nichts
//!   geschrieben) + hängt den gerahmten Record ans Log; `get_by_content_id`
//!   liest die durablen kanonischen Bytes/das [`Datum`] zurück. Hält die
//!   in-memory Dedup-Karte und beide Kanten-Indizes als **reine, neu-baubare**
//!   Derivate (§8.4): Ordnung **log-fsync → index-commit**, Reconciliation beim
//!   Öffnen, `rebuild_index_from_log`.
//! - [`index`] — die **Kanten-Indizes** (§1.2/§10.3): der [`EdgeIndex`]-Trait
//!   (`owner→contexts` / `target→referrers`; **owned** `ContentId`s; Range-Scan;
//!   transaktionales Watermark) und die redb-Impl [`RedbEdgeIndex`]. Reines
//!   Derivat (§8.4) — wipe-/neu-baubar, Engine billig revidierbar.
//! - [`kernel`] — die konkrete **Kernel-Implementierung** [`LakearchKernel`]: sie
//!   besitzt den [`ContentStore`] (Log + Content-Store + Kanten-Indizes) und
//!   verdrahtet die Phase-1-Verben des [`Kernel`]-Vertrags — `append` (§7.1,
//!   Dedup §5.3, Index erst nach Log-`fsync` §8.4) und `get_by_content_id`
//!   (§5.2-Fetch, liefert ein [`SealedRecord`] durchs Tor §11). Aggregierte
//!   Betriebs-Zähler [`KernelMetrics`] über [`LakearchKernel::stats`] (§Betrieb).
//! - [`traverse`] — die **mechanische Traversierung** (§1.2/§1.7 a): beschränkt
//!   (Tiefe/Knoten-Budget), zyklensicher über ein server-seitiges Visited-Set
//!   (§1.6), deterministisch emittiert in aufsteigender `ContentId`-Adress-Order
//!   (§5.2/§1.4, **kein** Wert-Sort), mit strukturellem `edge_type_filter` (§3.3)
//!   und kooperativem [`CancelFlag`]. Sie läuft **durch das Tor** (§11.3):
//!   Filter-vor-Auflösen + VANISH (nicht-sichtbare Nachbarn sind interne
//!   Front-Stopps und verändern die Ergebnisform nicht). Bei Budget-/Abbruch/
//!   Inkonsistenz endet der Strom mit einem definierten [`KernelError`].
//! - [`error`] — [`error::KernelError`] (rein **mechanische** Zustände, §1.4).
//! - Platzhalter-Konvention (§3.6) auf [`Datum`]
//!   ([`Datum::placeholder`]/[`Datum::unresolved_marker`]): geschlossene
//!   Verweise ohne baumelnde Ziele; volle Behandlung Phase 3.

mod model;
mod serialize;

pub mod api;
pub mod error;
pub mod format;
pub mod gate;
pub mod id;
pub mod index;
pub mod kernel;
pub mod log;
pub mod store;
pub mod traverse;

pub use api::{Direction, Kernel, SnapshotToken, Step, StepStream};
pub use error::KernelError;
pub use format::{
    checksum, decode_record, encode_record, encode_record_to_vec, BatchFooter, DecodedRecord,
    RecordHeader, CHECKSUM_ALGO_BLAKE3, CHECKSUM_LEN, FOOTER_MAGIC, RECORD_FORMAT_VERSION,
    RECORD_HEADER_LEN, RECORD_MAGIC,
};
pub use gate::{open, Capability, GrantedScopes, SealedRecord, VisibleDatum};
pub use id::{AnchorId, ContentId, DOMAIN_TAG_V1};
pub use index::{Edge, EdgeIndex, RedbEdgeIndex};
pub use kernel::{KernelMetrics, LakearchKernel};
pub use log::{LogMetrics, LoggedRecord, SegmentLog};
pub use model::Datum;
pub use serialize::{canonical_cbor, strict_decode};
pub use store::{ContentStore, StoreMetrics};
pub use traverse::{CancelFlag, TraversalParams};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_stable_and_dedups() {
        // §5.3: gleiche kanonische Form ⇒ gleiche ContentId (Dedup).
        let a = ContentId::of_datum(&Datum::leaf(b"lakearch".to_vec()));
        let b = ContentId::of_datum(&Datum::leaf(b"lakearch".to_vec()));
        let c = ContentId::of_datum(&Datum::leaf(b"lakearch!".to_vec()));
        assert_eq!(a, b, "gleiche Bytes ⇒ gleiche ContentId (Dedup, §5.3)");
        assert_ne!(a, c, "andere Bytes ⇒ andere ContentId");
    }

    #[test]
    fn content_id_byte_order_is_total() {
        // Deterministischer Tiebreak der Traversierung = aufsteigende
        // ContentId-Byte-Order (föderationsstabil, kein Wert-Sort, §1.4/§5.2).
        let mut ids = [
            ContentId::of_datum(&Datum::leaf(b"b".to_vec())),
            ContentId::of_datum(&Datum::leaf(b"a".to_vec())),
            ContentId::of_datum(&Datum::leaf(b"c".to_vec())),
        ];
        ids.sort();
        assert!(ids[0] <= ids[1] && ids[1] <= ids[2]);
    }

    #[test]
    fn anchor_id_roundtrips() {
        assert_eq!(AnchorId::new(42).get(), 42);
    }
}
