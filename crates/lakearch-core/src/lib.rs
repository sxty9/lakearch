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
//! - [`error`] — [`error::KernelError`] (rein **mechanische** Zustände, §1.4).
//! - Platzhalter-Konvention (§3.6) auf [`Datum`]
//!   ([`Datum::placeholder`]/[`Datum::unresolved_marker`]): geschlossene
//!   Verweise ohne baumelnde Ziele; volle Behandlung Phase 3.

mod model;
mod serialize;

pub mod api;
pub mod error;
pub mod gate;
pub mod id;

pub use api::{Direction, Kernel, SnapshotToken, Step, StepStream};
pub use error::KernelError;
pub use gate::{Capability, GrantedScopes, SealedRecord, VisibleDatum};
pub use id::{AnchorId, ContentId, DOMAIN_TAG_V1};
pub use model::Datum;
pub use serialize::canonical_cbor;

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
