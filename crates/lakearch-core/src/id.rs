//! Identitäts-Newtypes: `ContentId` (bestand-global) und `AnchorId`
//! (bestand-lokal).
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md` §5/§9/§12 und die eingefrorene
//! `semantics/canonical-encoding.md` (§K5). Die `ContentId` ist **ein** BLAKE3-
//! Hash mit drei Sichten — Adresse (§5.2), Dedup-Schlüssel (§5.3) und
//! Föderations-Band (§12.3) — **nicht** drei verschiedene Hashes.

use crate::model::Datum;
use crate::serialize::canonical_cbor;

/// `DOMAIN_TAG_V1` — der **feste Byte-Präfix** des BLAKE3-Preimage (§K5.1).
///
/// Er kodiert die Hash-Algorithmus-/Encoding-Version **1** und steht **vor** dem
/// kanonischen CBOR, ist aber **nicht** Teil von `canonical_cbor` selbst (die
/// Domain-Separation lebt im Preimage, nicht im CBOR; §K3.6). Eine künftige
/// Encoding-/Hash-Änderung bekommt ein anderes Tag (`…/v2\n`) und damit einen
/// **disjunkten, koexistierenden** ID-Raum — niemals stille Kollisionen (§K5.2).
///
/// Exakte 16 Bytes = ASCII `lakearch/cid/v1` gefolgt von einem einzelnen `\n`
/// (`0x0a`) als unzweideutiger Trenner zwischen festem Tag und variablem CBOR.
pub const DOMAIN_TAG_V1: &[u8; 16] = b"lakearch/cid/v1\n";

/// Bestand-**globale** Identität (§5.2 Speicher-Identität / §5.3 Wert-Identität
/// sind zwei Sichten auf EINEN BLAKE3-Hash): die ContentId adressiert ein Daten
/// und dedupliziert es zugleich. Inhaltsgleiche Daten tragen dieselbe ContentId
/// und sind bestand-übergreifend identisch (§12.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Bildet die `ContentId` eines Daten gemäß §K5:
    /// `ContentId(D) = BLAKE3(DOMAIN_TAG_V1 || canonical_cbor(D))`.
    ///
    /// Dies ist die **maßgebliche** Konstruktion. `canonical_cbor` erzwingt das
    /// eingefrorene RFC-8949-Kerndeterminismus-Profil explizit (§K3/§K4); das
    /// Domain-Tag steht im Preimage (§K5.1). Speicher- **und** Wert-Identität
    /// fallen so auf **einen** Hash zusammen (§K5.3).
    pub fn of_datum(datum: &Datum) -> Self {
        let cbor = canonical_cbor(datum);
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_TAG_V1);
        hasher.update(&cbor);
        ContentId(*hasher.finalize().as_bytes())
    }

    /// Bildet die ContentId über **bereits kanonisierte** Bytes, ohne das
    /// Domain-Tag voranzustellen. **Nur** für Tests/Werkzeuge, die das Preimage
    /// selbst zusammensetzen (z. B. Golden-Vector-Gegenproben); der reguläre Pfad
    /// ist [`ContentId::of_datum`].
    pub fn of_raw_preimage(preimage: &[u8]) -> Self {
        ContentId(*blake3::hash(preimage).as_bytes())
    }

    /// Konstruiert eine `ContentId` aus 32 rohen Bytes. Für Index-/Test-Zwecke,
    /// bei denen eine ID direkt vorliegt (z. B. fixe Golden-Vector-Bytes); der
    /// reguläre Weg, eine ID zu *erhalten*, ist [`ContentId::of_datum`].
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ContentId(bytes)
    }

    /// Die 32 rohen Hash-Bytes (Adresse; sie urteilt nicht, §5.2).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Untere-Hex-Darstellung (64 Ziffern) — für Golden-Vector-Dokumentation und
    /// Logs. **Keine** Identitäts-Semantik; die `ContentId` *ist* die 32 Bytes.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            // Zwei Hex-Ziffern pro Byte, Kleinbuchstaben.
            const HEX: &[u8; 16] = b"0123456789abcdef";
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
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
    fn domain_tag_v1_is_frozen_bytes() {
        // §K5.1: exakte 16 Bytes; jede Abweichung bricht das ganze Universum.
        assert_eq!(DOMAIN_TAG_V1.len(), 16);
        assert_eq!(
            DOMAIN_TAG_V1,
            &[
                0x6c, 0x61, 0x6b, 0x65, 0x61, 0x72, 0x63, 0x68, 0x2f, 0x63, 0x69, 0x64, 0x2f, 0x76,
                0x31, 0x0a
            ]
        );
    }

    #[test]
    fn of_datum_equals_blake3_of_tag_then_cbor() {
        let d = Datum::leaf([]);
        let cbor = canonical_cbor(&d);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(DOMAIN_TAG_V1);
        preimage.extend_from_slice(&cbor);
        assert_eq!(ContentId::of_datum(&d), ContentId::of_raw_preimage(&preimage));
    }

    #[test]
    fn hex_roundtrips_byte_order() {
        let id = ContentId::from_bytes([0xab; 32]);
        assert_eq!(id.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn anchor_id_roundtrips() {
        assert_eq!(AnchorId::new(42).get(), 42);
    }
}
