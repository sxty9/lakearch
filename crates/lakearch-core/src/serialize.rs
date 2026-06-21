//! Kanonische CBOR-Serialisierung eines Daten (RFC 8949 §4.2.1 Core
//! Deterministic Encoding), **explizit erzwungen**.
//!
//! Maßgeblich und **eingefroren**: `semantics/canonical-encoding.md` §K3/§K4.
//! Wir verlassen uns **nicht** auf den Default-Output einer CBOR-Bibliothek
//! (§K1): die Regeln werden hier von Hand erzwungen und durch einen **zweiten,
//! unabhängigen** Encoder (Test-only, `tests/canonical_vectors.rs`) bytegleich
//! gegengeprüft (§K7), plus Golden Vectors (§K8).
//!
//! ## Erzwungene Regeln (Auswahl)
//! - **Kürzeste-Form-Längen/Counts** (§K3.1): jeder Map-/Array-/Byte-String-
//!   Längenpräfix in minimaler Additional-Info-Form.
//! - **Nur definite-length** (§K3.2): keine indefinite-length-Container.
//! - **Map-Schlüssel bytewise sortiert, keine Duplikate** (§K3.3): in v1
//!   trivial, da die Hülle stets eine **ein-elementige** Map ist (§K4.1).
//! - **Keine Floats / simple values / Tags / Text-Strings** in der Hülle
//!   (§K3.4–§K3.7): die kanonische Form nutzt **nur** Map, Array, unsigned
//!   Integer-Köpfe und Byte-Strings.
//!
//! ## Byte-Layout (§K4)
//! - **Blatt:** `A1 00 <bstr(payload)>` — Map{1}, Schlüssel `0`, Byte-String.
//! - **Knoten:** `A1 01 <array(n)> [58 20 <cid>]·n` — Map{1}, Schlüssel `1`,
//!   Array der aufsteigend sortierten, deduplizierten 32-Byte-Kontext-IDs.

use crate::model::Datum;

/// CBOR Major Types (RFC 8949 §3.1), in die hohen 3 Bits des Kopf-Bytes kodiert.
const MAJOR_UINT: u8 = 0 << 5; // Major Type 0 (unsigned integer) — hier nur als Map-Schlüssel.
const MAJOR_BYTES: u8 = 2 << 5; // Major Type 2 (byte string).
const MAJOR_ARRAY: u8 = 4 << 5; // Major Type 4 (array).
const MAJOR_MAP: u8 = 5 << 5; // Major Type 5 (map).

/// CBOR-Map-Schlüssel der festen Hülle (§K4.1). Genau **einer** kommt je vor.
const KEY_PAYLOAD: u8 = 0; // Blatt.
const KEY_OWNS: u8 = 1; // Knoten.

/// Serialisiert ein Daten in seine **kanonische** CBOR-Byte-Form (§K4).
///
/// Diese Funktion ist die **maßgebliche** v1-Kanonisierung; sie ist
/// bit-deterministisch und für alle Zeit eingefroren (§K1/§K9). Ihr Output geht
/// (nach Voranstellen von `DOMAIN_TAG_V1`) in die `ContentId` ein (§K5).
pub fn canonical_cbor(datum: &Datum) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(datum, &mut out);
    out
}

/// Schreibt die kanonische CBOR-Form direkt in einen vorhandenen Puffer (spart
/// eine Allokation, wenn der Aufrufer den Preimage selbst zusammensetzt).
pub fn encode_into(datum: &Datum, out: &mut Vec<u8>) {
    // Top-Level ist stets eine **ein-elementige** Map (§K4.1): `A1`.
    // 1 < 24 ⇒ kürzeste Form = direkt im Additional-Info-Nibble (§K3.1).
    write_head(out, MAJOR_MAP, 1);

    if let Some(payload) = datum.payload() {
        // Blatt: Schlüssel 0 (uint, kürzeste Form = `0x00`) + Byte-String (§K4.2).
        write_head(out, MAJOR_UINT, 0);
        write_byte_string(out, payload);
    } else if let Some(owns) = datum.owns() {
        // Knoten: Schlüssel 1 (`0x01`) + Array der sortiert-deduplizierten
        // 32-Byte-Kontext-IDs (§K4.3). Die Sortier-/Dedup-Invariante ist bereits
        // vom Modell-Konstruktor (`Datum::node`) hergestellt; hier wird sie nur
        // ausgeschrieben.
        write_head(out, MAJOR_UINT, KEY_OWNS as u64);
        write_head(out, MAJOR_ARRAY, owns.len() as u64);
        for cid in owns {
            // Jede ContentId ist exakt 32 Bytes ⇒ Kopf immer `58 20` (§K4.3).
            write_byte_string(out, cid.as_bytes());
        }
    } else {
        // Unerreichbar: ein `Datum` ist per Konstruktion entweder Blatt oder
        // Knoten (§K2.1); das „leere Nichts" ist nicht konstruierbar. Die feste
        // Hülle bliebe sonst eine leere Map (`A0`), was nicht-kanonisch wäre.
        // Wir schreiben bewusst keinen Schlüssel und überlassen die Wahrung der
        // Invariante dem Typ-System (`model::Datum`).
        debug_assert!(false, "Datum ist weder Blatt noch Knoten (§K2.1 verletzt)");
        let _ = KEY_PAYLOAD; // dokumentiert die Schlüssel-Konstante; nie hier benutzt.
    }
}

/// Schreibt einen Byte-String (Major Type 2) mit **kürzeste-Form**-Längenpräfix
/// (§K3.1) und **definite** Länge (§K3.2), gefolgt von den Roh-Bytes (§K4.2).
fn write_byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_head(out, MAJOR_BYTES, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Schreibt einen CBOR-Item-Kopf: Major-Type-Bits ‖ **kürzeste-Form**-
/// Additional-Info für den Wert/die Länge `value` (§K3.1).
///
/// - `0..=23`      → direkt im Additional-Info-Nibble (1 Byte).
/// - `24..=255`    → `ai = 24`, 1 Folgebyte (`uint8`).
/// - `256..=65535` → `ai = 25`, 2 Folgebytes (`uint16`, big-endian).
/// - `… 2^32-1`    → `ai = 26`, 4 Folgebytes (`uint32`, big-endian).
/// - `… 2^64-1`    → `ai = 27`, 8 Folgebytes (`uint64`, big-endian).
///
/// Eine längere-als-nötige Kodierung ist **verboten** (§K3.1) — diese Funktion
/// erzeugt **stets** die kürzeste Form.
fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => out.push(major | value as u8),
        24..=255 => {
            out.push(major | 24);
            out.push(value as u8);
        }
        256..=65_535 => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ContentId;

    fn cid(byte: u8) -> ContentId {
        ContentId::from_bytes([byte; 32])
    }

    #[test]
    fn empty_leaf_layout() {
        // §K4.2 / GV-1: leeres Blatt → `A1 00 40`.
        let d = Datum::leaf([]);
        assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x40]);
    }

    #[test]
    fn small_leaf_layout() {
        // §K4.2 / GV-2: payload 01 02 03 → `A1 00 43 01 02 03`.
        let d = Datum::leaf([0x01, 0x02, 0x03]);
        assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x43, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn single_byte_leaf_layout() {
        // §K4.2 / GV-3: payload "a" (0x61) → `A1 00 41 61`.
        let d = Datum::leaf([0x61]);
        assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x41, 0x61]);
    }

    #[test]
    fn length_24_leaf_uses_shortest_form_head() {
        // §K3.1-Grenze / GV-4: Länge 24 → bstr-Kopf `58 18` (ai=24), nicht direkt.
        let payload: Vec<u8> = (0u8..24).collect();
        let d = Datum::leaf(payload.clone());
        let mut expected = vec![0xA1, 0x00, 0x58, 0x18];
        expected.extend_from_slice(&payload);
        assert_eq!(canonical_cbor(&d), expected);
        // 4 Kopf-Bytes (A1 00 58 18) + 24 Nutzlast = 28 (die Spec-Prosa „27" in
        // §K8 GV-4 ist ein Tippfehler; das Layout `A1 00 58 18`+24 ist maßgeblich).
        assert_eq!(canonical_cbor(&d).len(), 28);
    }

    #[test]
    fn node_with_one_context_layout() {
        // §K4.3 / GV-5: Knoten mit einem 32-Byte-Kontext → `A1 01 81 58 20 <cid>`.
        let c = cid(0x09);
        let n = Datum::node([c]).expect("nicht-leerer Knoten");
        let mut expected = vec![0xA1, 0x01, 0x81, 0x58, 0x20];
        expected.extend_from_slice(c.as_bytes());
        assert_eq!(canonical_cbor(&n), expected);
        assert_eq!(canonical_cbor(&n).len(), 37);
    }

    #[test]
    fn node_array_count_uses_shortest_form() {
        // Array-Count ist kürzeste-Form (§K3.1): 2 Elemente → `82`.
        let n = Datum::node([cid(0x01), cid(0x02)]).expect("nicht-leerer Knoten");
        let bytes = canonical_cbor(&n);
        assert_eq!(&bytes[0..3], &[0xA1, 0x01, 0x82]);
        assert_eq!(bytes.len(), 3 + 2 * 34); // 3 Kopf + 2x (58 20 + 32 Bytes)
    }

    #[test]
    fn node_owns_are_sorted_ascending_in_bytes() {
        // §K2.3: die Kontext-IDs erscheinen aufsteigend, unabhängig von der
        // Einfüge-Reihenfolge.
        let a = cid(0x01);
        let b = cid(0x02);
        let from_ba = canonical_cbor(&Datum::node([b, a]).unwrap());
        let from_ab = canonical_cbor(&Datum::node([a, b]).unwrap());
        assert_eq!(from_ba, from_ab);
        // Erstes Element ist die kleinere ID (0x01-Bytes).
        assert_eq!(&from_ab[5..37], a.as_bytes());
        assert_eq!(&from_ab[39..71], b.as_bytes());
    }

    #[test]
    fn write_head_shortest_form_boundaries() {
        // Direkt verifizieren, dass jede §K3.1-Grenze die kürzeste Form nutzt.
        let mut v = Vec::new();
        write_head(&mut v, 0, 23);
        assert_eq!(v, vec![23]); // 0..=23 direkt
        v.clear();
        write_head(&mut v, 0, 24);
        assert_eq!(v, vec![24, 24]); // ai=24
        v.clear();
        write_head(&mut v, 0, 255);
        assert_eq!(v, vec![24, 255]);
        v.clear();
        write_head(&mut v, 0, 256);
        assert_eq!(v, vec![25, 0x01, 0x00]); // ai=25, uint16
        v.clear();
        write_head(&mut v, 0, 65_535);
        assert_eq!(v, vec![25, 0xFF, 0xFF]);
        v.clear();
        write_head(&mut v, 0, 65_536);
        assert_eq!(v, vec![26, 0x00, 0x01, 0x00, 0x00]); // ai=26, uint32
        v.clear();
        write_head(&mut v, 0, 4_294_967_295);
        assert_eq!(v, vec![26, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.clear();
        write_head(&mut v, 0, 4_294_967_296);
        assert_eq!(v, vec![27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // ai=27
    }

    #[test]
    fn determinism_same_datum_twice_is_byte_identical() {
        // §K1: dieselbe Eingabe → bytegleich (zweimal kodiert).
        let n = Datum::node([cid(0x05), cid(0x03), cid(0x05)]).unwrap();
        assert_eq!(canonical_cbor(&n), canonical_cbor(&n));
    }
}
