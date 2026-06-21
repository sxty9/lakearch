//! lakearch-core — Kernel-Substrat.
//!
//! Maßgeblich ist das Gesetzbuch `semantics/lakearch.md`. Dieses Crate
//! implementiert ausschließlich die Kernel-Primitive (§1–§13): speichern
//! (append), traversieren, strukturell matchen, das Zugriffs-Tor. Rechnen,
//! Werten und Sortieren liegen außerhalb (§1.4/§1.5).
//!
//! Phase-0-Skeleton: nur die beiden Identitäts-Newtypes. Die kanonische
//! Serialisierung (Phase 0.5) und alles Weitere folgen in ihren Phasen.

/// Bestand-**globale** Identität (§5.2 Speicher-Identität / §5.3 Wert-Identität
/// sind zwei Sichten auf EINEN BLAKE3-Hash): die ContentId adressiert ein Daten
/// und dedupliziert es zugleich. Inhaltsgleiche Daten tragen dieselbe ContentId
/// und sind bestand-übergreifend identisch (§12.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Bildet die ContentId über die **bereits kanonisierten** Bytes eines Daten.
    /// Die kanonische Serialisierung selbst (RFC 8949 deterministisch, mit
    /// Hash-Algorithmus-Tag im Preimage) wird in Phase 0.5 eingefroren; bis
    /// dahin ist dies der rohe BLAKE3 über die übergebenen Bytes.
    pub fn of_canonical_bytes(bytes: &[u8]) -> Self {
        ContentId(*blake3::hash(bytes).as_bytes())
    }

    /// Die 32 rohen Hash-Bytes (Adresse; sie urteilt nicht, §5.2).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bestand-**lokaler** Auflösungs-Handle für Anker (§9.1) — **kein** Inhalts-Hash.
/// Anker-IDs sind bestand-lokal und werden bei Föderation über gradierte
/// Identität versöhnt (§12.4). Der Anker selbst ist ein gewöhnliches
/// inhaltsadressiertes Daten; AnchorId ist nur sein lokaler Handle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AnchorId(u128);

impl AnchorId {
    pub fn new(raw: u128) -> Self {
        AnchorId(raw)
    }
    pub fn get(self) -> u128 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_stable_and_dedups() {
        let a = ContentId::of_canonical_bytes(b"lakearch");
        let b = ContentId::of_canonical_bytes(b"lakearch");
        let c = ContentId::of_canonical_bytes(b"lakearch!");
        assert_eq!(a, b, "gleiche Bytes => gleiche ContentId (Dedup, §5.3)");
        assert_ne!(a, c, "andere Bytes => andere ContentId");
    }

    #[test]
    fn content_id_byte_order_is_total() {
        // Deterministischer Tiebreak der Traversierung = aufsteigende
        // ContentId-Byte-Order (föderationsstabil, kein Wert-Sort, §1.4/§5.2).
        let mut ids = [
            ContentId::of_canonical_bytes(b"b"),
            ContentId::of_canonical_bytes(b"a"),
            ContentId::of_canonical_bytes(b"c"),
        ];
        ids.sort();
        assert!(ids[0] <= ids[1] && ids[1] <= ids[2]);
    }

    #[test]
    fn anchor_id_roundtrips() {
        assert_eq!(AnchorId::new(42).get(), 42);
    }
}
