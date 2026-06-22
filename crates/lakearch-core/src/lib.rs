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
//!   Verweise ohne baumelnde Ziele. **Volle Behandlung (Phase 3):** die
//!   strukturelle **Auflösung** ([`ContentStore::resolve_placeholder`]) hängt das
//!   echte Daten an und verknüpft Platzhalter→real über einen Ersetzungs-Kontext
//!   (§6.3); der auflösende Pfad ist über die bestehenden Kanten-Indizes in beide
//!   Richtungen traversierbar.
//! - **Zeit als Daten (Phase 3, §6)** auf [`Datum`]: die **zwei Zeitachsen** (§6.2)
//!   — Aufzeichnungszeit ([`Datum::recording_time`]) und Gültigkeitszeit
//!   ([`Datum::validity_time`]) — sind besondere **Kontexte** `{ Achsen-Marker,
//!   opaker Zeit-Wert }`; ein Daten darf beide tragen, die Achsen dürfen
//!   auseinanderfallen. Der **Ersetzungs-Kontext** ([`Datum::supersedes`], §6.3)
//!   verknüpft ein neueres mit dem überholten älteren Daten (append-only). Der
//!   Kernel **speichert, indiziert (Exakt-Match/Mitgliedschaft) und traversiert**
//!   Zeit nur — er **interpretiert/ordnet/vergleicht** den Zeit-Wert **nie**
//!   (§1.4/§6.4); „welche Version gilt zum Zeitpunkt T" ist eine Leseregel der
//!   Schicht darüber (§8).
//! - **Bitemporale & Ersetzungs-Indizes (Phase 3, §6, §8.4)** im [`ContentStore`]:
//!   zwei weitere **reine, neu-baubare Derivate** (wie der Bereichs-/Berechtigungs-
//!   Index) — (a) der **Zeit-Aussage-Mitgliedschafts-Index** (welche Daten tragen
//!   eine gegebene Zeit-Aussage; **nur** Exakt-Match/Mitgliedschaft §1.3, **keine**
//!   geordnete Bereichs-Abfrage §1.4/§6.4) und (b) der **Ersetzungs-Index** in
//!   beide Richtungen (*supersedes* / *superseded-by*, §6.3). Beim Öffnen aus dem
//!   Log rekonstruiert und in `rebuild_index_from_log` mit-gewipt/-neu-gebaut (§8.4).
//!   Die **gegateten** Lese-Helfer ([`LakearchKernel::supersedes_visible`]/
//!   [`LakearchKernel::superseded_by_visible`]/[`LakearchKernel::time_carriers_visible`]/
//!   [`LakearchKernel::placeholder_resolvers_visible`]) reichen **nur sichtbare**
//!   `ContentId`s heraus (VANISH, §11.3; Inhalt nur übers Tor) und ordnen/vergleichen
//!   Zeit **nie** — es gibt **kein** Verb, das nach Zeit ordnet oder „die aktive"
//!   auswählt (§1.4/§6.4).
//! - **Anker / referenzielle Identität (Phase 4, §9, §5.5)** auf [`Datum`]: der
//!   **Anker** ([`Datum::anchor`], §9.1) ist ein gewöhnliches inhaltsadressiertes
//!   Daten (die **Klasse**); Repräsentanten verweisen per **gradierter
//!   Mitgliedschaft** ([`Datum::membership`], §9.3) auf den Anker (§9.2, nie auf
//!   einen Repräsentanten). **Gradierte referenzielle Identität** ([`IdentityStrength`]/
//!   [`Datum::graded_identity`], §5.5) ist eine Familie von Identitäts-Kontexten
//!   verschiedener Stärke (*deckungsgleich, ergänzt, widerspricht-in, verwandt-mit,
//!   bekannt-verschieden*), die reifizierte Sub-Kontexte (Attribute, **Konfidenz**,
//!   Urheber, Zeit, §3.4) tragen. **Kuratierung** ([`Datum::curation_hide`]/
//!   `curation_unhide`/`curation_replace`, §9.5) fügt nur **reversible** Kontexte
//!   hinzu; ein verborgenes Daten VANISHt aus der gegateten Projektion, nichts wird
//!   gelöscht (§7.1). Der Kernel **hält und traversiert** diese Strukturen — er
//!   **berechnet/vergleicht/schwellt Konfidenz nie** und **entscheidet keine
//!   Identität/Mitgliedschaft** (§9-Präambel/§1.4); ein expliziter Negativ-Test
//!   friert diese Grenze ein.
//! - **Anker-/Identitäts-/Kuratierungs-Indizes (Phase 4, §9/§5.5/§8.4)** im
//!   [`ContentStore`]: weitere **reine, neu-baubare Derivate** — Anker-Mitgliedschaft
//!   in beide Richtungen, die **bestand-lokale** AnchorId⇆Anker-Karte (§12.4,
//!   deterministisch vergeben), gradierte-Identitäts-Links und der reversible
//!   Kuratierungs-Verbergen-Filter. Aus dem Log rekonstruiert und in
//!   `rebuild_index_from_log` mit-gewipt/-neu-gebaut (§8.4). Die **gegateten** Helfer
//!   ([`LakearchKernel::anchor_members_visible`]/[`LakearchKernel::member_anchors_visible`]/
//!   [`LakearchKernel::graded_identity_links_visible`]) reichen **nur sichtbare**
//!   `ContentId`s heraus (VANISH inkl. kuratorisch verborgener; Inhalt nur übers Tor)
//!   und ranken/werten **nie**.
//! - **Föderation (Phase 8, §12)** auf [`ContentStore`]/[`LakearchKernel`]: einen
//!   **fremden** Bestand aufnehmen ist **kein Sonderfall** (§12.5) — jedes aktive
//!   fremde Daten läuft über den **einen** Append-Pfad ([`LakearchKernel::federate`]/
//!   [`ContentStore::ingest_foreign`]); inhaltsgleiche Daten kollabieren **automatisch**
//!   über ihre [`ContentId`] (Dedup §5.3/§12.3). Bestand-**lokale** Anker (§9.1) werden
//!   über **deterministische** gradierte-Identitäts-Versöhnungs-Kontexte versöhnt
//!   ([`LakearchKernel::reconcile_anchor`], [`Datum::reconcile_anchors`], §12.4 /
//!   Korrelations-Pfad §5.7 b): die Bytes sind eine **reine Funktion** von
//!   `(fremder Anker, lokaler Anker, Regel)` — **keine** Wall-Clock, **kein** Random ⇒
//!   Re-Run kollabiert per Hash (§5.3), Doppel-/Concurrent-Ingest ist **idempotent**
//!   (byte-gleicher Bestand). Der Kernel **entscheidet keine Identität** (§9-Präambel/
//!   §1.4) — er **verlinkt** nur; **welche** Anker „dasselbe Ding" sind, bestimmt die
//!   Schicht darüber. Vergleichs-Helfer: [`LakearchKernel::content_set`] (föderations-
//!   stabiler Inhalts-Schlüssel), [`LakearchKernel::anchor_cids`] (Versöhnungs-Kandidaten).
//! - **Crypto-Shredding (Phase 8, §15/§9.5)** in [`crypto`]: eine pure-Rust AEAD
//!   (ChaCha20-Poly1305) versiegelt eine erasbare Nutzlast unter einem pro-Lösch-
//!   Schlüssel; das **Zerstören** des Schlüssels macht die Bytes **unrückholbar**,
//!   während die [`ContentId`] und Kanten **intakt** bleiben (§3.6 — eine
//!   Traversierung trifft einen Tombstone). Der Nonce ist **deterministisch** aus der
//!   `ContentId` abgeleitet (kein Random/keine Uhr) ⇒ reproduzierbare Compaction.
//! - **Compaction & physische Erasure (Phase 8, §15/§9.5)** in [`compaction`]: der
//!   [`Compactor`] rewritet die aktiven Daten in eine **neue, unveränderliche**
//!   [`CompactedSegment`]-Generation, lässt Überholte (§6.3)/Verborgene (§9.5)/Eraste
//!   physisch fallen (Closure-/Refcount-geschützt, §3.6/§5.3 — nie eine rechtmäßig
//!   gehaltene Dedup-Referenz zerstört), versiegelt Eraste (Crypto-Shred) und schaltet
//!   die Generation **atomar** über den `CURRENT`-Marker live (§13-Epoche), **ohne** je
//!   ein Segment zu unmappen, das ein Leser hält (drop-after-quiesce). Index referenziert
//!   **stabile logische IDs** ([`ContentId`] + [`Generation`]), **nie** rohe Offsets.
//!   [`LakearchKernel::erase`] ist die **gegatete** (Erasure-Recht, sonst
//!   [`KernelError::ErasureDenied`]), **auditierte** ([`Datum::erasure_audit`], append-only
//!   §7.1) und **nicht-transitive** (§12.3 — lokaler [`Keystore`]) Lösch-Op; das logische
//!   Verbergen (§9.5) bleibt die reversible „Einschränkung der Verarbeitung", die physische
//!   Erasure das „Recht auf Vergessen".

mod model;
mod serialize;

pub mod api;
pub mod compaction;
pub mod crypto;
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
pub use compaction::{
    generation_dir, publish_generation, read_current_generation, CompactedSegment,
    CompactionPlan, CompactionReport, Compactor, Generation, Keystore, Refcounts,
};
pub use crypto::{ErasureKey, ERASURE_KEY_LEN};
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
pub use model::{Datum, IdentityStrength};
pub use serialize::{canonical_cbor, strict_decode};
pub use store::{ContentStore, StagedHandle, StoreMetrics};
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
