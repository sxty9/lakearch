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

use crate::error::KernelError;
use crate::id::ContentId;
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

/// CBOR-Major-Type-Maske (die hohen 3 Bits eines Kopf-Bytes) und Additional-Info
/// (die niedrigen 5 Bits), §K3.
const MAJOR_MASK: u8 = 0b1110_0000;
const AI_MASK: u8 = 0b0001_1111;

/// **Strict-Decode** (§K6): liest die kanonische CBOR-Byte-Form **bit-streng**
/// zurück in ein [`Datum`] und akzeptiert **ausschließlich** Bytes, die der
/// Kanonisierer ([`canonical_cbor`]) für dasselbe Daten ausgegeben hätte.
///
/// Maßgeblich: `semantics/canonical-encoding.md` §K3/§K4/§K6. Jede Abweichung
/// von der kanonischen Form (nicht-kürzeste Länge §K3.1, indefinite-length §K3.2,
/// fremder Major-Type/Tag/Float/Simple-Value §K3.4–§K3.6, falscher Map-Schlüssel,
/// gemischte/leere Klasse §K2.1, unsortierte/doppelte `owns`-IDs §K2.3, Rest-Bytes
/// nach dem Daten) ⇒ [`KernelError::Inconsistent`] — **nie** stilles
/// Re-Kanonisieren.
///
/// Es gilt die Round-Trip-/Idempotenz-Invariante (§K6):
/// `strict_decode(canonical_cbor(d)) == d` und
/// `canonical_cbor(strict_decode(bytes)) == bytes` für jede akzeptierte Eingabe.
///
/// Diese Funktion ist die mechanische Umkehr der Kanonisierung; sie **wertet
/// nicht** (§1.4) — sie prüft allein die strukturelle Kanonizität.
pub fn strict_decode(bytes: &[u8]) -> Result<Datum, KernelError> {
    let mut cur = Cursor { bytes, pos: 0 };

    // Top-Level MUSS eine ein-elementige Map sein (§K4.1): `A1`.
    let (major, ai) = cur.read_head_byte()?;
    if major != MAJOR_MAP {
        return Err(KernelError::Inconsistent);
    }
    let entries = cur.read_argument(ai)?;
    if entries != 1 {
        // §K4.4: weder die leere Map (`A0`) noch eine mehr-elementige ist kanonisch.
        return Err(KernelError::Inconsistent);
    }

    // Der einzige Schlüssel ist ein kleiner unsigned Integer: `0` (Blatt) oder
    // `1` (Knoten), §K4.1.
    let (kmajor, kai) = cur.read_head_byte()?;
    if kmajor != MAJOR_UINT {
        return Err(KernelError::Inconsistent);
    }
    let key = cur.read_argument(kai)?;

    let datum = match key {
        k if k == KEY_PAYLOAD as u64 => {
            // Blatt (§K4.2): ein Byte-String (Major Type 2).
            let payload = cur.read_byte_string()?;
            Datum::leaf(payload.to_vec())
        }
        k if k == KEY_OWNS as u64 => {
            // Knoten (§K4.3): ein Array von 32-Byte-Byte-Strings, aufsteigend
            // sortiert und ohne Duplikat (§K2.3).
            let (amajor, aai) = cur.read_head_byte()?;
            if amajor != MAJOR_ARRAY {
                return Err(KernelError::Inconsistent);
            }
            let n = cur.read_argument(aai)?;
            if n == 0 {
                // Ein Knoten ohne Kontexte ist nicht kanonisch (§K4.4).
                return Err(KernelError::Inconsistent);
            }
            let mut owns: Vec<ContentId> = Vec::new();
            let mut prev: Option<[u8; 32]> = None;
            for _ in 0..n {
                let id_bytes = cur.read_byte_string()?;
                let id32: [u8; 32] = id_bytes
                    .try_into()
                    .map_err(|_| KernelError::Inconsistent)?;
                // §K2.3: strikt aufsteigend (⇒ keine Duplikate, keine Unordnung).
                if let Some(p) = prev {
                    if id32 <= p {
                        return Err(KernelError::Inconsistent);
                    }
                }
                prev = Some(id32);
                owns.push(ContentId::from_bytes(id32));
            }
            // `node` re-sortiert/dedupliziert; da die Eingabe bereits strikt
            // aufsteigend war, bleibt die Menge unverändert (§K2.3-Erhalt). Der
            // `expect` ist unerreichbar, weil `n >= 1` schon geprüft ist.
            match Datum::node(owns) {
                Some(d) => d,
                None => return Err(KernelError::Inconsistent),
            }
        }
        // Jeder andere Schlüssel ist nicht-kanonisch (§K4.1).
        _ => return Err(KernelError::Inconsistent),
    };

    // Keine Rest-Bytes nach dem einen Daten (sonst nicht-kanonisch).
    if cur.pos != cur.bytes.len() {
        return Err(KernelError::Inconsistent);
    }
    Ok(datum)
}

/// Ein einfacher, panik-freier Lese-Cursor über die kanonischen CBOR-Bytes
/// (Strict-Decode, §K6). Hält keinen Zustand außer Position; jede Methode prüft
/// Grenzen und Kanonizität explizit.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Liest **ein** Kopf-Byte und zerlegt es in (Major-Type-Bits, Additional-
    /// Info). Trunkierung ⇒ [`KernelError::Inconsistent`].
    fn read_head_byte(&mut self) -> Result<(u8, u8), KernelError> {
        let b = *self.bytes.get(self.pos).ok_or(KernelError::Inconsistent)?;
        self.pos += 1;
        Ok((b & MAJOR_MASK, b & AI_MASK))
    }

    /// Liest das Argument (den Wert/die Länge) zur Additional-Info `ai` in
    /// **kürzester Form** (§K3.1). Lehnt indefinite-length (`ai = 31`), reservierte
    /// `ai` (28..=30) **und** jede längere-als-nötige Kodierung ab (§K3.1/§K3.2).
    fn read_argument(&mut self, ai: u8) -> Result<u64, KernelError> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => {
                let v = *self.bytes.get(self.pos).ok_or(KernelError::Inconsistent)?;
                self.pos += 1;
                // Kürzeste Form: ein uint8 < 24 müsste direkt kodiert sein (§K3.1).
                if v < 24 {
                    return Err(KernelError::Inconsistent);
                }
                Ok(v as u64)
            }
            25 => {
                let raw = self.read_fixed::<2>()?;
                let v = u16::from_be_bytes(raw) as u64;
                if v <= u8::MAX as u64 {
                    return Err(KernelError::Inconsistent); // nicht kürzeste Form.
                }
                Ok(v)
            }
            26 => {
                let raw = self.read_fixed::<4>()?;
                let v = u32::from_be_bytes(raw) as u64;
                if v <= u16::MAX as u64 {
                    return Err(KernelError::Inconsistent);
                }
                Ok(v)
            }
            27 => {
                let raw = self.read_fixed::<8>()?;
                let v = u64::from_be_bytes(raw);
                if v <= u32::MAX as u64 {
                    return Err(KernelError::Inconsistent);
                }
                Ok(v)
            }
            // 28..=30 reserviert, 31 indefinite-length — beide nicht-kanonisch
            // (§K3.2).
            _ => Err(KernelError::Inconsistent),
        }
    }

    /// Liest `N` Folgebytes (für die uint16/32/64-Argumente).
    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], KernelError> {
        let end = self.pos.checked_add(N).ok_or(KernelError::Inconsistent)?;
        let slice = self.bytes.get(self.pos..end).ok_or(KernelError::Inconsistent)?;
        let arr: [u8; N] = slice.try_into().map_err(|_| KernelError::Inconsistent)?;
        self.pos = end;
        Ok(arr)
    }

    /// Liest einen definite-length Byte-String (Major Type 2, §K3.7) mit
    /// kürzeste-Form-Längenpräfix (§K3.1) und gibt eine Sicht auf seine Bytes.
    fn read_byte_string(&mut self) -> Result<&'a [u8], KernelError> {
        let (major, ai) = self.read_head_byte()?;
        if major != MAJOR_BYTES {
            return Err(KernelError::Inconsistent);
        }
        let len = self.read_argument(ai)?;
        let len = usize::try_from(len).map_err(|_| KernelError::Inconsistent)?;
        let end = self.pos.checked_add(len).ok_or(KernelError::Inconsistent)?;
        let slice = self.bytes.get(self.pos..end).ok_or(KernelError::Inconsistent)?;
        self.pos = end;
        Ok(slice)
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

    // -- Strict-Decode (§K6) --------------------------------------------------

    #[test]
    fn strict_decode_round_trips_leaf_and_node() {
        // §K6: strict_decode(canonical_cbor(d)) == d.
        let samples = vec![
            Datum::leaf([]),
            Datum::leaf([0x61]),
            Datum::leaf([0x01, 0x02, 0x03]),
            Datum::leaf((0u8..24).collect::<Vec<u8>>()),
            Datum::leaf((0u8..200).collect::<Vec<u8>>()), // uint8-Längen-Kopf
            Datum::leaf(vec![0x55; 300]),                 // uint16-Längen-Kopf
            Datum::node([cid(0x03)]).unwrap(),
            Datum::node([cid(0x01), cid(0x02), cid(0x09)]).unwrap(),
        ];
        for d in &samples {
            let bytes = canonical_cbor(d);
            let back = strict_decode(&bytes).expect("kanonische Bytes dekodieren");
            assert_eq!(&back, d, "Round-Trip (§K6)");
            // Idempotenz: re-encode == bytes.
            assert_eq!(canonical_cbor(&back), bytes, "re-encode = identity (§K6)");
        }
    }

    #[test]
    fn strict_decode_rejects_non_canonical() {
        // Leere Map (`A0`) — §K4.4.
        assert!(matches!(
            strict_decode(&[0xA0]),
            Err(KernelError::Inconsistent)
        ));
        // Mehr-elementige Map (`A2 ...`) — §K4.1.
        assert!(matches!(
            strict_decode(&[0xA2, 0x00, 0x40, 0x01, 0x80]),
            Err(KernelError::Inconsistent)
        ));
        // Unbekannter Schlüssel `2` — §K4.1.
        assert!(matches!(
            strict_decode(&[0xA1, 0x02, 0x40]),
            Err(KernelError::Inconsistent)
        ));
        // Knoten mit leerem Array (`A1 01 80`) — §K4.4.
        assert!(matches!(
            strict_decode(&[0xA1, 0x01, 0x80]),
            Err(KernelError::Inconsistent)
        ));
        // Rest-Bytes nach dem Daten.
        let mut trailing = canonical_cbor(&Datum::leaf([0x01]));
        trailing.push(0xFF);
        assert!(matches!(
            strict_decode(&trailing),
            Err(KernelError::Inconsistent)
        ));
        // Nicht-kürzeste Längen-Form (`A1 00 58 01 61` statt `A1 00 41 61`) — §K3.1.
        assert!(matches!(
            strict_decode(&[0xA1, 0x00, 0x58, 0x01, 0x61]),
            Err(KernelError::Inconsistent)
        ));
        // Trunkiert (Header verspricht eine Länge, aber keine Bytes da).
        assert!(matches!(
            strict_decode(&[0xA1, 0x00, 0x43, 0x01]),
            Err(KernelError::Inconsistent)
        ));
        // Knoten mit nicht-32-Byte-Kontext-String.
        assert!(matches!(
            strict_decode(&[0xA1, 0x01, 0x81, 0x41, 0x00]),
            Err(KernelError::Inconsistent)
        ));
        // indefinite-length Byte-String (`5F ... FF`) im payload — §K3.2.
        assert!(matches!(
            strict_decode(&[0xA1, 0x00, 0x5F, 0x41, 0x61, 0xFF]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn strict_decode_rejects_unsorted_or_duplicate_owns() {
        // §K2.3: nicht aufsteigend sortiert ⇒ nicht-kanonisch.
        let big = cid(0x09);
        let small = cid(0x01);
        let mut unsorted = vec![0xA1u8, 0x01, 0x82, 0x58, 0x20];
        unsorted.extend_from_slice(big.as_bytes()); // große zuerst (falsch)
        unsorted.extend_from_slice(&[0x58, 0x20]);
        unsorted.extend_from_slice(small.as_bytes());
        assert!(matches!(
            strict_decode(&unsorted),
            Err(KernelError::Inconsistent)
        ));
        // Duplikat (zweimal dieselbe ID) ⇒ nicht-kanonisch.
        let mut dup = vec![0xA1u8, 0x01, 0x82, 0x58, 0x20];
        dup.extend_from_slice(small.as_bytes());
        dup.extend_from_slice(&[0x58, 0x20]);
        dup.extend_from_slice(small.as_bytes());
        assert!(matches!(strict_decode(&dup), Err(KernelError::Inconsistent)));
    }
}
