//! Golden Vectors (§K8) + zweiter unabhängiger Encoder (§K7) +
//! Identitäts-Eigenschaften (§5.3/§12.3) für die eingefrorene v1-Kanonik.
//!
//! Maßgeblich: `semantics/canonical-encoding.md`. Diese Datei friert die
//! `ContentId`-Bytes der Golden Vectors **für immer** ein: jede Abweichung ist
//! ein CI-Fehler und bedeutet einen Encoder-Drift, der Dedup (§5.3) und
//! Föderation (§12.3) lautlos brechen würde.
//!
//! Der **zweite, unabhängige Encoder** (`second_encoder`) ist hier von Hand auf
//! Basis der low-level `minicbor`-Crate geschrieben — ein **anderer** Code-Pfad
//! als der Produktiv-Encoder (`lakearch_core::canonical_cbor`, hand-gerollt) —
//! und muss bytegleichen Output liefern (§K7). minicbor wird **nur** im Test
//! benutzt (dev-dependency), nie im Produktiv-Pfad.

use lakearch_core::{canonical_cbor, ContentId, Datum, DOMAIN_TAG_V1};

/// Wandelt 64 Hex-Ziffern in 32 Bytes (Test-Helfer für die eingefrorenen IDs).
fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "ContentId-Hex muss 64 Ziffern haben");
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16).expect("hex") as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
        *slot = (hi << 4) | lo;
    }
    out
}

// ---------------------------------------------------------------------------
// Eingefrorene Golden-Vector-ContentIds (§K8). Berechnet aus
//   ContentId = BLAKE3(DOMAIN_TAG_V1 || canonical_cbor), DOMAIN_TAG_V1 = §K5.1.
// ---------------------------------------------------------------------------
const GV1_CID: &str = "e05fc4bc77e675f131dd618eb2181f1be23dc4ddc6bcdc4c1a342e1312484921";
const GV2_CID: &str = "2615273e765a89ac9dd6ebc5a2b6470832c3bf29173faea3c45a2f91b015e4f5";
const GV3_CID: &str = "07ba90197aa18f77e57afa5b11591ce17f6177686aead272aaee02b8d60a5c9d";
const GV4_CID: &str = "f3a86f813e3185d1d6e0c9f638e778164e4ed8083e335f959ce2f70942376922";
const GV5_CID: &str = "062d53bd4352003017079e8b9a5938fb3e7e294566efd89773addc4dbc9fa7ee";
const GV6_CID: &str = "6d909d128f2a3a31f642589578c94f96f5ee1a3a706273a8f7ff1ccac618b134";

fn gv3_cid_a() -> ContentId {
    ContentId::of_datum(&Datum::leaf([0x61]))
}
fn gv2_cid_b() -> ContentId {
    ContentId::of_datum(&Datum::leaf([0x01, 0x02, 0x03]))
}

// =========================================================================
// (a) Golden Vectors: fixe Eingabe → fixe canonical_cbor-Bytes UND fixe
//     ContentId-Bytes (§K8). Bei Drift schlägt genau diese Assertion fehl.
// =========================================================================

#[test]
fn gv1_empty_leaf() {
    let d = Datum::leaf([]);
    assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x40], "GV-1 cbor (§K4.2)");
    assert_eq!(ContentId::of_datum(&d).as_bytes(), &hex32(GV1_CID), "GV-1 cid");
}

#[test]
fn gv2_small_leaf() {
    let d = Datum::leaf([0x01, 0x02, 0x03]);
    assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x43, 0x01, 0x02, 0x03]);
    assert_eq!(ContentId::of_datum(&d).as_bytes(), &hex32(GV2_CID), "GV-2 cid");
}

#[test]
fn gv3_single_byte_leaf() {
    let d = Datum::leaf([0x61]);
    assert_eq!(canonical_cbor(&d), vec![0xA1, 0x00, 0x41, 0x61]);
    assert_eq!(ContentId::of_datum(&d).as_bytes(), &hex32(GV3_CID), "GV-3 cid");
}

#[test]
fn gv4_length_24_leaf_shortest_form_boundary() {
    // §K3.1-Grenze: Länge 24 ⇒ bstr-Kopf `58 18`. Gesamt 28 Bytes
    // (A1 00 58 18 = 4 Kopf + 24 Nutzlast).
    let payload: Vec<u8> = (0u8..24).collect();
    let d = Datum::leaf(payload.clone());
    let mut expected = vec![0xA1, 0x00, 0x58, 0x18];
    expected.extend_from_slice(&payload);
    assert_eq!(canonical_cbor(&d), expected);
    assert_eq!(canonical_cbor(&d).len(), 28);
    assert_eq!(ContentId::of_datum(&d).as_bytes(), &hex32(GV4_CID), "GV-4 cid");
}

#[test]
fn gv5_node_one_context() {
    let n = Datum::node([gv3_cid_a()]).expect("nicht-leerer Knoten");
    let mut expected = vec![0xA1, 0x01, 0x81, 0x58, 0x20];
    expected.extend_from_slice(gv3_cid_a().as_bytes());
    assert_eq!(canonical_cbor(&n), expected, "GV-5 cbor (§K4.3)");
    assert_eq!(ContentId::of_datum(&n).as_bytes(), &hex32(GV5_CID), "GV-5 cid");
}

#[test]
fn gv6_node_two_contexts_sort_and_dedup() {
    // §K2.3-Kernbeweis: Eingabe-Multiset { CID_b, CID_a, CID_b } ⇒
    // dedupliziert { CID_a, CID_b }, aufsteigend sortiert. CID_a (07..) < CID_b (26..).
    let a = gv3_cid_a();
    let b = gv2_cid_b();
    let n = Datum::node([b, a, b]).expect("nicht-leerer Knoten");

    let mut expected = vec![0xA1, 0x01, 0x82, 0x58, 0x20];
    expected.extend_from_slice(a.as_bytes()); // kleinere zuerst
    expected.extend_from_slice(&[0x58, 0x20]);
    expected.extend_from_slice(b.as_bytes());
    assert_eq!(canonical_cbor(&n), expected, "GV-6 cbor (§K4.3)");
    assert_eq!(ContentId::of_datum(&n).as_bytes(), &hex32(GV6_CID), "GV-6 cid");

    // Jede Eingabe-Permutation desselben Multisets ⇒ dieselbe ContentId.
    for perm in [[a, b], [b, a]] {
        let p = Datum::node(perm).unwrap();
        assert_eq!(ContentId::of_datum(&p), ContentId::of_datum(&n));
    }
    // Auch das Duplikat im Eingabe-Multiset ändert nichts.
    assert_eq!(
        ContentId::of_datum(&Datum::node([a, a, b, b, a]).unwrap()),
        ContentId::of_datum(&n)
    );
}

// =========================================================================
// (b) Gleiches Atom, verschiedene besessene Kontexte ⇒ verschiedene ContentId
//     (§12.3-Erhalt: inhaltsgleich ⇒ identisch; daher müssen Knoten mit
//     unterschiedlichen Kontext-Mengen verschiedene IDs tragen).
// =========================================================================

#[test]
fn same_atom_different_owned_contexts_differ() {
    let atom = gv3_cid_a(); // dasselbe „Atom" als Kontext-Referenz
    let other = gv2_cid_b();
    let n_just_atom = Datum::node([atom]).unwrap();
    let n_atom_plus = Datum::node([atom, other]).unwrap();
    assert_ne!(
        ContentId::of_datum(&n_just_atom),
        ContentId::of_datum(&n_atom_plus),
        "unterschiedliche Kontext-Menge ⇒ unterschiedliche ContentId (§12.3)"
    );

    // Und: ein Blatt mit Bytes X ist nie identisch mit einem Knoten, der X
    // besitzt — verschiedene Klassen, verschiedene kanonische Hülle.
    let leaf_like = Datum::leaf(atom.as_bytes().to_vec());
    assert_ne!(
        ContentId::of_datum(&leaf_like),
        ContentId::of_datum(&n_just_atom)
    );
}

// =========================================================================
// (c) Primitives Blatt dedupliziert auf seinen atomaren Bytes allein (§5.3).
// =========================================================================

#[test]
fn primitive_leaf_dedups_on_bytes() {
    let a = ContentId::of_datum(&Datum::leaf(b"same".to_vec()));
    let b = ContentId::of_datum(&Datum::leaf(b"same".to_vec()));
    let c = ContentId::of_datum(&Datum::leaf(b"diff".to_vec()));
    assert_eq!(a, b, "gleiche atomare Bytes ⇒ dasselbe Daten (§5.3)");
    assert_ne!(a, c, "andere atomare Bytes ⇒ anderes Daten");
}

// =========================================================================
// (d) Zweiter, unabhängiger Encoder (§K7): minicbor-basiert, anderer Code-Pfad,
//     muss bytegleich zum Produktiv-Encoder sein — über mehrere Daten.
// =========================================================================

/// Unabhängiger Encoder über die low-level `minicbor::Encoder` (§K7). Schreibt
/// dieselbe kanonische Hülle (§K4) über eine **andere** Implementierung:
/// minicbor emittiert Map/Array/Byte-String-Köpfe selbst in kürzester Form. Wir
/// nutzen **nicht** den hand-gerollten `write_head` des Produktiv-Pfads.
fn second_encoder(datum: &Datum) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut buf);
    // Top-Level: 1-elementige Map.
    enc.map(1).expect("map head");
    if let Some(payload) = datum.payload() {
        enc.u8(0).expect("key 0"); // Schlüssel payload
        enc.bytes(payload).expect("payload bytes");
    } else if let Some(owns) = datum.owns() {
        enc.u8(1).expect("key 1"); // Schlüssel owns
        enc.array(owns.len() as u64).expect("array head");
        for cid in owns {
            enc.bytes(cid.as_bytes()).expect("cid bytes");
        }
    } else {
        unreachable!("Datum ist Blatt oder Knoten (§K2.1)");
    }
    buf
}

#[test]
fn second_encoder_is_byte_identical_across_data() {
    let a = gv3_cid_a();
    let b = gv2_cid_b();
    let samples = vec![
        Datum::leaf([]),
        Datum::leaf([0x00]),
        Datum::leaf([0x01, 0x02, 0x03]),
        Datum::leaf((0u8..24).collect::<Vec<u8>>()),
        Datum::leaf((0u8..200).collect::<Vec<u8>>()), // erzwingt uint8-Längen-Kopf
        Datum::leaf(vec![0x55; 300]),                 // erzwingt uint16-Längen-Kopf
        Datum::node([a]).unwrap(),
        Datum::node([a, b]).unwrap(),
        Datum::node([b, a, b]).unwrap(),
    ];
    for d in &samples {
        assert_eq!(
            canonical_cbor(d),
            second_encoder(d),
            "Produktiv- und Zweit-Encoder müssen bytegleich sein (§K7)"
        );
    }
}

// =========================================================================
// (e) Determinismus (§K1): zweimal kodieren ist bytegleich; Hülle ist die
//     erwartete kanonische Form (Map-Kopf + Schlüssel-Ordnung).
// =========================================================================

#[test]
fn encoding_same_datum_twice_is_byte_identical() {
    let d = Datum::node([gv2_cid_b(), gv3_cid_a(), gv2_cid_b()]).unwrap();
    assert_eq!(canonical_cbor(&d), canonical_cbor(&d));
}

#[test]
fn canonical_shell_is_single_entry_map_with_fixed_keys() {
    // §K4.1: Top-Level ist immer `A1` (Map, 1 Eintrag); Schlüssel ist `00`
    // (Blatt) bzw. `01` (Knoten) — kürzeste Integer-Form, triviale Sortierung.
    let leaf = canonical_cbor(&Datum::leaf([0x09]));
    assert_eq!(&leaf[0..2], &[0xA1, 0x00]);
    let node = canonical_cbor(&Datum::node([gv3_cid_a()]).unwrap());
    assert_eq!(&node[0..2], &[0xA1, 0x01]);
}

#[test]
fn content_id_preimage_is_tag_then_cbor() {
    // §K5: ContentId = BLAKE3(DOMAIN_TAG_V1 || canonical_cbor). Direkt
    // nachgerechnet, damit das Preimage-Layout selbst eingefroren ist.
    let d = Datum::leaf([0x01, 0x02, 0x03]);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(DOMAIN_TAG_V1);
    preimage.extend_from_slice(&canonical_cbor(&d));
    assert_eq!(
        ContentId::of_datum(&d),
        ContentId::of_raw_preimage(&preimage)
    );
    // Und das Tag ist exakt die §K5.1-Bytes.
    assert_eq!(&preimage[0..16], b"lakearch/cid/v1\n");
}
