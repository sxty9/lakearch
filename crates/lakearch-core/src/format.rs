//! Das **On-Disk-Format** des Append-Segment-Logs (§7.1) — reine, in-memory
//! Kodierung/Dekodierung eines gerahmten Records und eines Batch-Footers, plus
//! die Prüfsumme. **Keine** Datei-I/O in diesem Modul (die kommt mit dem
//! Log-Writer/-Reader in Phase 1).
//!
//! Maßgeblich: der gehärtete Plan (Abschnitt „Durability, Recovery &
//! Atomarität") und das Gesetzbuch `semantics/lakearch.md` (§7.1 append-only;
//! §8.4 Log = alleinige Wahrheit). Dieses Modul ist `#![forbid(unsafe_code)]`:
//! es manipuliert nur Bytes-Slices und `Vec<u8>`, ohne `unsafe`.
//!
//! ## Strikte Trennung Framing ↔ ContentId-Preimage
//!
//! Das hier definierte **Framing** (Magic, Versionen, seq, Längen, reservierte
//! Felder, Prüfsumme) ist **getrennte Metadaten** und geht **niemals** in den
//! `ContentId`-Preimage ein (`ContentId = BLAKE3(DOMAIN_TAG_V1 ||
//! canonical_cbor(D))`, §K5). Die `ContentId`/kanonischen Bytes sind die
//! **Nutzlast** (`payload`) eines Records; das Framing wrappt sie. Das Storage-
//! `format-version` ist damit **unabhängig** vom Hash-Encoding-Tag `…/cid/v1`
//! (§K5.1) und darf sich später ändern, ohne das Universum neu zu hashen.
//!
//! ## Byte-Layout eines gerahmten Records (`format-version = 1`)
//!
//! Alle Mehrbyte-Integer sind **little-endian** (native Reihenfolge des
//! Ziel-Profils x86-64/aarch64; einmal festgelegt, dokumentiert, eingefroren).
//! Der **feste** Header ist [`RECORD_HEADER_LEN`] = 64 Bytes:
//!
//! ```text
//! Offset  Größe  Feld                     Bemerkung
//! ------  -----  -----------------------  ------------------------------------
//!   0      4     magic                    [`RECORD_MAGIC`] = b"LKR1"
//!   4      2     format_version (u16-le)  [`RECORD_FORMAT_VERSION`] = 1
//!   6      2     checksum_algo_id (u16)   [`CHECKSUM_ALGO_BLAKE3`] = 1
//!   8      8     seq (u64-le)             monotone Sequenz über PHYSISCHE Records
//!  16      8     payload_length (u64-le)  Länge der Nutzlast in Bytes
//!  -- reservierte, in v1 NULL-gefüllte Felder (für spätere Phasen, §K5.1) --
//!  24      8     activation_epoch (u64)   §13 Aktiv-Marker-Epoche (Audit)
//!  32      8     marker_offset (u64)      §13 Governing-Marker-Offset
//!  40      8     constituent_range (u64)  §13 Konstituenten-Bereich (gepackt)
//!  48      4     shard_id (u32-le)        Sharding-Achse (§2.3/§12)
//!  52      8     index_validity_offset    Index-Gültigkeits-Wasserzeichen
//!  60      4     reserved_pad (u32)       Auffüllung auf 64; NULL
//! ------  -----
//!  64     (header gesamt)
//!
//! danach: payload_length Nutzlast-Bytes
//! danach: [`CHECKSUM_LEN`] = 32 Prüfsummen-Bytes (über Header ‖ Payload)
//! ```
//!
//! Gesamtlänge eines Records = `64 + payload_length + 32`.
//!
//! ## Byte-Layout eines Batch-Footers (`format-version = 1`)
//!
//! Ein Batch endet mit einem **eigenen, geprüfsummten** Footer, der seine
//! Records benennt (Group-Commit, §Durability). Ein Batch ist genau dann durabel,
//! wenn sein Footer durabel ist (WAL-Commit-Record). Fester Footer
//! [`BATCH_FOOTER_LEN`] = 64 Bytes:
//!
//! ```text
//! Offset  Größe  Feld                     Bemerkung
//! ------  -----  -----------------------  ------------------------------------
//!   0      4     magic                    [`FOOTER_MAGIC`] = b"LKF1"
//!   4      2     format_version (u16-le)  [`RECORD_FORMAT_VERSION`] = 1
//!   6      2     checksum_algo_id (u16)   [`CHECKSUM_ALGO_BLAKE3`] = 1
//!   8      8     record_count (u64-le)    Anzahl Records im Batch
//!  16      8     first_seq (u64-le)       erste seq des Batches
//!  24      8     last_seq (u64-le)        letzte seq des Batches
//!  -- reservierte, in v1 NULL-gefüllte Felder --
//!  32      8     activation_epoch (u64)   §13 (Audit)
//!  40      8     shard_id_packed (u64)    Sharding (gepackt; §2.3/§12)
//!  48      8     index_validity_offset    Index-Gültigkeits-Wasserzeichen
//!  56      8     reserved_pad (u64)       Auffüllung; NULL
//! ------  -----
//!  64     (footer-rumpf gesamt, ohne Prüfsumme)
//!
//! danach: [`CHECKSUM_LEN`] = 32 Prüfsummen-Bytes (über den Footer-Rumpf)
//! ```
//!
//! ## Prüfsumme (`checksum-algo-id = 1`)
//!
//! [`checksum`] = die **ersten 32 Bytes** von `BLAKE3(bytes)` (= die volle
//! 32-Byte-Default-Ausgabe von BLAKE3). Für einen Record über `Header ‖ Payload`,
//! für einen Footer über den Footer-Rumpf. Eine Prüfsummen-Verletzung **oder**
//! eine seq-Lücke ist **Korruption** und wird **nie** still übersprungen
//! (§Durability); der Dekodierer meldet einen definierten Fehler.

#![forbid(unsafe_code)]

use crate::error::KernelError;

/// Magic eines gerahmten Records (`format-version = 1`). ASCII `LKR1`
/// (lakearch record v1) — selbst-dokumentierend im Hex-Dump.
pub const RECORD_MAGIC: [u8; 4] = *b"LKR1";

/// Magic eines Batch-Footers (`format-version = 1`). ASCII `LKF1`
/// (lakearch footer v1). Bewusst **verschieden** vom Record-Magic, damit ein
/// Footer beim Record-für-Record-Scan (Recovery) nie als Record fehlgedeutet
/// werden kann.
pub const FOOTER_MAGIC: [u8; 4] = *b"LKF1";

/// Storage-`format-version` des Framings. **Getrennt** vom Hash-Encoding-Tag
/// (`…/cid/v1`, §K5.1): das Framing darf evolvieren, ohne das ContentId-Universum
/// zu berühren. Regel (§7.1): „liest alle historischen Formate für immer, schreibt
/// nur das aktuelle".
pub const RECORD_FORMAT_VERSION: u16 = 1;

/// `checksum-algo-id` für die in v1 verwendete Prüfsumme: **BLAKE3** (32-Byte-
/// Default-Ausgabe). Im Header festgehalten, damit ein künftiger Algo-Wechsel
/// alte Records weiter prüfen kann (Read-all-formats-forever).
pub const CHECKSUM_ALGO_BLAKE3: u16 = 1;

/// Länge der Prüfsumme in Bytes (volle BLAKE3-Default-Ausgabe).
pub const CHECKSUM_LEN: usize = 32;

/// Feste Länge des Record-Headers in Bytes (siehe Modul-Doc-Layout).
pub const RECORD_HEADER_LEN: usize = 64;

/// Feste Länge des Batch-Footer-Rumpfs in Bytes (ohne Prüfsumme).
pub const BATCH_FOOTER_LEN: usize = 64;

// --- feste Feld-Offsets im Record-Header (siehe Modul-Doc) -----------------
const RH_MAGIC: usize = 0;
const RH_FORMAT_VERSION: usize = 4;
const RH_CHECKSUM_ALGO: usize = 6;
const RH_SEQ: usize = 8;
const RH_PAYLOAD_LEN: usize = 16;
const RH_ACTIVATION_EPOCH: usize = 24;
const RH_MARKER_OFFSET: usize = 32;
const RH_CONSTITUENT_RANGE: usize = 40;
const RH_SHARD_ID: usize = 48;
const RH_INDEX_VALIDITY_OFFSET: usize = 52;
const RH_RESERVED_PAD: usize = 60;

// --- feste Feld-Offsets im Batch-Footer (siehe Modul-Doc) ------------------
const BF_MAGIC: usize = 0;
const BF_FORMAT_VERSION: usize = 4;
const BF_CHECKSUM_ALGO: usize = 6;
const BF_RECORD_COUNT: usize = 8;
const BF_FIRST_SEQ: usize = 16;
const BF_LAST_SEQ: usize = 24;
const BF_ACTIVATION_EPOCH: usize = 32;
const BF_SHARD_ID_PACKED: usize = 40;
const BF_INDEX_VALIDITY_OFFSET: usize = 48;
const BF_RESERVED_PAD: usize = 56;

/// Der **feste** Kopf eines gerahmten Records (siehe Modul-Doc).
///
/// Trägt das Magic, die Versionen, die monotone Sequenznummer, die Nutzlast-
/// Länge und die **reservierten, in v1 NULL-gefüllten** Felder für spätere
/// Phasen (§K5.1 — so muss das append-only-Format nie geändert werden):
/// `activation_epoch` (§13), `marker_offset`/`constituent_range` (§13),
/// `shard_id` (Sharding), `index_validity_offset` (Index-Gültigkeit).
///
/// **seq** ist monoton über **physisch geschriebene** Records: ein Content-Dedup-
/// Treffer (§5.3) schreibt **keinen** Record und verbraucht **keine** seq.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecordHeader {
    /// Monotone Sequenznummer über physische Records (§Durability).
    pub seq: u64,
    /// Länge der Nutzlast (kanonische CBOR-Bytes des Daten, §K5) in Bytes.
    pub payload_len: u64,
    /// RESERVIERT (§13): Aktiv-Marker-Epoche; in v1 stets `0`.
    pub activation_epoch: u64,
    /// RESERVIERT (§13): Offset des regierenden Aktiv-Markers; in v1 stets `0`.
    pub marker_offset: u64,
    /// RESERVIERT (§13): gepackter Konstituenten-Bereich; in v1 stets `0`.
    pub constituent_range: u64,
    /// RESERVIERT (Sharding, §2.3/§12): Shard-ID; in v1 stets `0`.
    pub shard_id: u32,
    /// RESERVIERT: Index-Gültigkeits-Wasserzeichen; in v1 stets `0`.
    pub index_validity_offset: u64,
}

impl RecordHeader {
    /// Erzeugt einen Header für einen frisch zu schreibenden Record mit
    /// gegebener `seq` und `payload_len`. Alle reservierten Felder sind **NULL**
    /// (v1, §K5.1).
    pub fn new(seq: u64, payload_len: u64) -> Self {
        RecordHeader {
            seq,
            payload_len,
            activation_epoch: 0,
            marker_offset: 0,
            constituent_range: 0,
            shard_id: 0,
            index_validity_offset: 0,
        }
    }

    /// Setzt das **§13-Sichtbarkeitsfeld** `marker_offset` (Offset des regierenden
    /// Aktiv-Markers) auf diesem Header und gibt ihn zurück (Builder).
    ///
    /// Ein Record mit `marker_offset != 0` ist ein **bedingter Konstituent** (§13):
    /// er wird **erst** sichtbar, wenn sein regierender Marker durabel committet ist
    /// (`marker_offset <= W`). Ein `marker_offset == 0` bedeutet **unbedingt**
    /// (gewöhnlicher Einzel-Append) — der Offset 0 ist nie ein gültiger Marker-Offset
    /// (am Offset 0 steht stets der allererste Record, nie ein nachgelagerter Marker
    /// eines früheren Konstituenten), also ist `0` ein eindeutiges „kein Marker".
    pub fn with_marker_offset(mut self, marker_offset: u64) -> Self {
        self.marker_offset = marker_offset;
        self
    }

    /// Setzt das **§13-Sichtbarkeitsfeld** `constituent_range` (gepackter
    /// Konstituenten-Bereich des Markers) auf diesem Header und gibt ihn zurück
    /// (Builder).
    ///
    /// Auf einem **Marker-Record** trägt dieses Feld den **Anfangs-Offset** des
    /// **ersten** Konstituenten; zusammen mit dem eigenen Offset des Markers ergibt
    /// das den inklusiven Bereich `[constituent_range, marker_offset)` aller von
    /// diesem Marker regierten Konstituenten-Records (sie liegen contiguous **vor**
    /// dem Marker). Reines Audit-/Rekonstruktions-Feld (§13): die
    /// **Sichtbarkeits-Autorität** ist allein der Offset-Vergleich (`marker_offset
    /// <= W` je Konstituent), **nicht** dieser Bereich.
    pub fn with_constituent_range(mut self, constituent_range: u64) -> Self {
        self.constituent_range = constituent_range;
        self
    }

    /// Schreibt die festen 64 Header-Bytes in `out` (Magic, Versionen, Felder,
    /// reservierte Null-Felder). **Ohne** Nutzlast/Prüfsumme — das macht
    /// [`encode_record`].
    fn write_fixed_head(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + RECORD_HEADER_LEN, 0);
        let h = &mut out[start..start + RECORD_HEADER_LEN];
        h[RH_MAGIC..RH_MAGIC + 4].copy_from_slice(&RECORD_MAGIC);
        h[RH_FORMAT_VERSION..RH_FORMAT_VERSION + 2]
            .copy_from_slice(&RECORD_FORMAT_VERSION.to_le_bytes());
        h[RH_CHECKSUM_ALGO..RH_CHECKSUM_ALGO + 2]
            .copy_from_slice(&CHECKSUM_ALGO_BLAKE3.to_le_bytes());
        h[RH_SEQ..RH_SEQ + 8].copy_from_slice(&self.seq.to_le_bytes());
        h[RH_PAYLOAD_LEN..RH_PAYLOAD_LEN + 8].copy_from_slice(&self.payload_len.to_le_bytes());
        h[RH_ACTIVATION_EPOCH..RH_ACTIVATION_EPOCH + 8]
            .copy_from_slice(&self.activation_epoch.to_le_bytes());
        h[RH_MARKER_OFFSET..RH_MARKER_OFFSET + 8]
            .copy_from_slice(&self.marker_offset.to_le_bytes());
        h[RH_CONSTITUENT_RANGE..RH_CONSTITUENT_RANGE + 8]
            .copy_from_slice(&self.constituent_range.to_le_bytes());
        h[RH_SHARD_ID..RH_SHARD_ID + 4].copy_from_slice(&self.shard_id.to_le_bytes());
        h[RH_INDEX_VALIDITY_OFFSET..RH_INDEX_VALIDITY_OFFSET + 8]
            .copy_from_slice(&self.index_validity_offset.to_le_bytes());
        // RH_RESERVED_PAD..+4 bleibt 0 (durch `resize(.., 0)`).
        let _ = RH_RESERVED_PAD;
    }

    /// Liest die festen 64 Header-Bytes streng (§Durability: Korruption wird
    /// **nie** still überschritten). Prüft Magic, `format-version`,
    /// `checksum-algo-id`. Gibt [`KernelError::Inconsistent`] bei jeder Abweichung
    /// (truncierter Header, falsches Magic, unbekannte Version/Algo).
    fn read_fixed_head(head: &[u8]) -> Result<Self, KernelError> {
        if head.len() < RECORD_HEADER_LEN {
            return Err(KernelError::Inconsistent);
        }
        if head[RH_MAGIC..RH_MAGIC + 4] != RECORD_MAGIC {
            return Err(KernelError::Inconsistent);
        }
        let format_version = u16_le(&head[RH_FORMAT_VERSION..RH_FORMAT_VERSION + 2]);
        if format_version != RECORD_FORMAT_VERSION {
            // Read-all-formats-forever (§7.1): künftig per match auf weitere
            // Versionen erweiterbar; in v1 ist nur 1 bekannt.
            return Err(KernelError::Inconsistent);
        }
        let checksum_algo = u16_le(&head[RH_CHECKSUM_ALGO..RH_CHECKSUM_ALGO + 2]);
        if checksum_algo != CHECKSUM_ALGO_BLAKE3 {
            return Err(KernelError::Inconsistent);
        }
        Ok(RecordHeader {
            seq: u64_le(&head[RH_SEQ..RH_SEQ + 8]),
            payload_len: u64_le(&head[RH_PAYLOAD_LEN..RH_PAYLOAD_LEN + 8]),
            activation_epoch: u64_le(&head[RH_ACTIVATION_EPOCH..RH_ACTIVATION_EPOCH + 8]),
            marker_offset: u64_le(&head[RH_MARKER_OFFSET..RH_MARKER_OFFSET + 8]),
            constituent_range: u64_le(&head[RH_CONSTITUENT_RANGE..RH_CONSTITUENT_RANGE + 8]),
            shard_id: u32_le(&head[RH_SHARD_ID..RH_SHARD_ID + 4]),
            index_validity_offset: u64_le(
                &head[RH_INDEX_VALIDITY_OFFSET..RH_INDEX_VALIDITY_OFFSET + 8],
            ),
        })
    }
}

/// Ein **dekodierter** gerahmter Record: der verifizierte Header und eine Sicht
/// auf seine Nutzlast (die kanonischen CBOR-Bytes, §K5). Die Prüfsumme ist beim
/// Dekodieren bereits **verifiziert** worden (§Durability).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecodedRecord<'a> {
    /// Der verifizierte Record-Header.
    pub header: RecordHeader,
    /// Die Nutzlast-Bytes (kanonisches CBOR des Daten, §K5). Sie gehen **nicht**
    /// ins Framing ein und sind das einzige, was in den `ContentId`-Preimage
    /// fließt.
    pub payload: &'a [u8],
    /// Gesamtlänge des Records auf der Platte (`64 + payload_len + 32`) — der
    /// Reader rückt damit zum nächsten Record vor.
    pub total_len: usize,
}

/// Kodiert einen Record (Header ‖ Payload ‖ Prüfsumme) **in-memory** in `out`.
///
/// Die Prüfsumme (§`checksum-algo-id = 1`) wird über `Header ‖ Payload` gebildet
/// und **nach** der Nutzlast angehängt. Es findet **keine** Datei-I/O statt.
pub fn encode_record(seq: u64, payload: &[u8], out: &mut Vec<u8>) {
    let header = RecordHeader::new(seq, payload.len() as u64);
    let frame_start = out.len();
    header.write_fixed_head(out);
    out.extend_from_slice(payload);
    // Prüfsumme über Header ‖ Payload (alles seit `frame_start`).
    let digest = checksum(&out[frame_start..]);
    out.extend_from_slice(&digest);
}

/// Bequemer Wrapper: kodiert einen Record in einen frischen `Vec<u8>`.
pub fn encode_record_to_vec(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len() + CHECKSUM_LEN);
    encode_record(seq, payload, &mut out);
    out
}

/// Kodiert einen Record (Header ‖ Payload ‖ Prüfsumme) **in-memory** in `out`,
/// mit einem **bereits befüllten** [`RecordHeader`] — so können die §13-
/// Sichtbarkeitsfelder (`marker_offset`/`constituent_range`) gesetzt werden.
///
/// `header.payload_len` wird vor dem Schreiben **autoritativ** auf `payload.len()`
/// gesetzt (der Header darf keine abweichende Länge tragen). Die Prüfsumme deckt —
/// genau wie [`encode_record`] — `Header ‖ Payload` ab, also auch die gesetzten
/// reservierten Felder: ein gekipptes `marker_offset`/`constituent_range` ist damit
/// ein Prüfsummen-Defekt (§Durability). Keine Datei-I/O.
pub fn encode_record_with(mut header: RecordHeader, payload: &[u8], out: &mut Vec<u8>) {
    header.payload_len = payload.len() as u64;
    let frame_start = out.len();
    header.write_fixed_head(out);
    out.extend_from_slice(payload);
    let digest = checksum(&out[frame_start..]);
    out.extend_from_slice(&digest);
}

/// Dekodiert **einen** gerahmten Record vom Anfang von `bytes` **streng**.
///
/// Verifiziert Magic/Version/Algo (Header), prüft auf Trunkierung von Header,
/// Nutzlast und Prüfsumme und **verifiziert die Prüfsumme** über `Header ‖
/// Payload`. Jede Abweichung (zu kurz, falsches Magic, unbekannte Version,
/// Prüfsummen-Verletzung) ⇒ [`KernelError::Inconsistent`] — **nie** stilles
/// Überspringen (§Durability).
///
/// Bei Erfolg liefert es einen [`DecodedRecord`] mit Nutzlast-Sicht und der
/// Gesamtlänge ([`DecodedRecord::total_len`]), sodass ein Reader zum nächsten
/// Record vorrücken kann (`&bytes[total_len..]`).
pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord<'_>, KernelError> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(KernelError::Inconsistent);
    }
    let header = RecordHeader::read_fixed_head(&bytes[..RECORD_HEADER_LEN])?;

    // payload_len muss in usize passen und die Nutzlast + Prüfsumme müssen
    // vollständig vorliegen (Trunkierungs-Erkennung von Payload/Footer-Checksum).
    let payload_len = usize::try_from(header.payload_len).map_err(|_| KernelError::Inconsistent)?;
    let total_len = RECORD_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(CHECKSUM_LEN))
        .ok_or(KernelError::Inconsistent)?;
    if bytes.len() < total_len {
        return Err(KernelError::Inconsistent);
    }

    let payload = &bytes[RECORD_HEADER_LEN..RECORD_HEADER_LEN + payload_len];
    let stored = &bytes[RECORD_HEADER_LEN + payload_len..total_len];

    // Prüfsumme über Header ‖ Payload (alles vor der Prüfsumme).
    let computed = checksum(&bytes[..RECORD_HEADER_LEN + payload_len]);
    // Konstantzeit-unabhängiger Byte-Vergleich genügt hier (keine Geheimnisse):
    // ein Mismatch ist Korruption (§Durability), kein Geheimnis-Leck.
    if stored != computed {
        return Err(KernelError::Inconsistent);
    }

    Ok(DecodedRecord {
        header,
        payload,
        total_len,
    })
}

/// Der **Batch-Footer** (Group-Commit, §Durability): benennt die Records seines
/// Batches (Anzahl + erste/letzte seq). Ein Batch ist genau dann durabel, wenn
/// sein Footer durabel ist (WAL-Commit-Record).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchFooter {
    /// Anzahl der Records im Batch.
    pub record_count: u64,
    /// Erste seq des Batches.
    pub first_seq: u64,
    /// Letzte seq des Batches.
    pub last_seq: u64,
    /// RESERVIERT (§13): Aktiv-Marker-Epoche; in v1 stets `0`.
    pub activation_epoch: u64,
    /// RESERVIERT (Sharding, §2.3/§12): gepackte Shard-ID; in v1 stets `0`.
    pub shard_id_packed: u64,
    /// RESERVIERT: Index-Gültigkeits-Wasserzeichen; in v1 stets `0`.
    pub index_validity_offset: u64,
}

impl BatchFooter {
    /// Erzeugt einen Footer für einen Batch mit `record_count` Records und der
    /// seq-Spanne `[first_seq, last_seq]`. Alle reservierten Felder sind **NULL**
    /// (v1, §K5.1).
    pub fn new(record_count: u64, first_seq: u64, last_seq: u64) -> Self {
        BatchFooter {
            record_count,
            first_seq,
            last_seq,
            activation_epoch: 0,
            shard_id_packed: 0,
            index_validity_offset: 0,
        }
    }

    /// Schreibt den Footer (Rumpf ‖ Prüfsumme) **in-memory** in `out`. Die
    /// Prüfsumme (§`checksum-algo-id = 1`) wird über den Footer-Rumpf gebildet und
    /// angehängt. Keine Datei-I/O.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + BATCH_FOOTER_LEN, 0);
        let f = &mut out[start..start + BATCH_FOOTER_LEN];
        f[BF_MAGIC..BF_MAGIC + 4].copy_from_slice(&FOOTER_MAGIC);
        f[BF_FORMAT_VERSION..BF_FORMAT_VERSION + 2]
            .copy_from_slice(&RECORD_FORMAT_VERSION.to_le_bytes());
        f[BF_CHECKSUM_ALGO..BF_CHECKSUM_ALGO + 2]
            .copy_from_slice(&CHECKSUM_ALGO_BLAKE3.to_le_bytes());
        f[BF_RECORD_COUNT..BF_RECORD_COUNT + 8].copy_from_slice(&self.record_count.to_le_bytes());
        f[BF_FIRST_SEQ..BF_FIRST_SEQ + 8].copy_from_slice(&self.first_seq.to_le_bytes());
        f[BF_LAST_SEQ..BF_LAST_SEQ + 8].copy_from_slice(&self.last_seq.to_le_bytes());
        f[BF_ACTIVATION_EPOCH..BF_ACTIVATION_EPOCH + 8]
            .copy_from_slice(&self.activation_epoch.to_le_bytes());
        f[BF_SHARD_ID_PACKED..BF_SHARD_ID_PACKED + 8]
            .copy_from_slice(&self.shard_id_packed.to_le_bytes());
        f[BF_INDEX_VALIDITY_OFFSET..BF_INDEX_VALIDITY_OFFSET + 8]
            .copy_from_slice(&self.index_validity_offset.to_le_bytes());
        // BF_RESERVED_PAD..+8 bleibt 0.
        let _ = BF_RESERVED_PAD;
        let digest = checksum(&out[start..start + BATCH_FOOTER_LEN]);
        out.extend_from_slice(&digest);
    }

    /// Bequemer Wrapper: kodiert den Footer in einen frischen `Vec<u8>`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BATCH_FOOTER_LEN + CHECKSUM_LEN);
        self.encode_into(&mut out);
        out
    }

    /// Gesamtlänge eines kodierten Footers auf der Platte (Rumpf ‖ Prüfsumme).
    pub const fn encoded_len() -> usize {
        BATCH_FOOTER_LEN + CHECKSUM_LEN
    }

    /// Dekodiert **einen** Batch-Footer vom Anfang von `bytes` **streng**.
    ///
    /// Verifiziert Magic/Version/Algo, prüft auf Trunkierung (Rumpf + Prüfsumme)
    /// und **verifiziert die Prüfsumme** über den Rumpf. Jede Abweichung ⇒
    /// [`KernelError::Inconsistent`] (§Durability).
    pub fn decode(bytes: &[u8]) -> Result<BatchFooter, KernelError> {
        let total = Self::encoded_len();
        if bytes.len() < total {
            return Err(KernelError::Inconsistent);
        }
        let body = &bytes[..BATCH_FOOTER_LEN];
        if body[BF_MAGIC..BF_MAGIC + 4] != FOOTER_MAGIC {
            return Err(KernelError::Inconsistent);
        }
        let format_version = u16_le(&body[BF_FORMAT_VERSION..BF_FORMAT_VERSION + 2]);
        if format_version != RECORD_FORMAT_VERSION {
            return Err(KernelError::Inconsistent);
        }
        let checksum_algo = u16_le(&body[BF_CHECKSUM_ALGO..BF_CHECKSUM_ALGO + 2]);
        if checksum_algo != CHECKSUM_ALGO_BLAKE3 {
            return Err(KernelError::Inconsistent);
        }
        let stored = &bytes[BATCH_FOOTER_LEN..total];
        let computed = checksum(body);
        if stored != computed {
            return Err(KernelError::Inconsistent);
        }
        Ok(BatchFooter {
            record_count: u64_le(&body[BF_RECORD_COUNT..BF_RECORD_COUNT + 8]),
            first_seq: u64_le(&body[BF_FIRST_SEQ..BF_FIRST_SEQ + 8]),
            last_seq: u64_le(&body[BF_LAST_SEQ..BF_LAST_SEQ + 8]),
            activation_epoch: u64_le(&body[BF_ACTIVATION_EPOCH..BF_ACTIVATION_EPOCH + 8]),
            shard_id_packed: u64_le(&body[BF_SHARD_ID_PACKED..BF_SHARD_ID_PACKED + 8]),
            index_validity_offset: u64_le(
                &body[BF_INDEX_VALIDITY_OFFSET..BF_INDEX_VALIDITY_OFFSET + 8],
            ),
        })
    }
}

/// Die **Prüfsummen-Funktion** (`checksum-algo-id = 1`): die volle 32-Byte-
/// Default-Ausgabe von **BLAKE3** über `bytes`.
///
/// Bewusst BLAKE3 (statt einer CRC): es ist bereits eine Kern-Abhängigkeit (für
/// die `ContentId`, §K5), erkennt jeden Ein-Bit-Flip sicher und ist schnell. Die
/// Prüfsumme ist **nur** Integritäts-Schutz des Framings — sie ist **kein** Teil
/// des `ContentId`-Preimage (§K5) und urteilt nicht (§1.4).
pub fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    *blake3::hash(bytes).as_bytes()
}

// --- kleine, panik-freie Little-Endian-Leser über fixe Slice-Längen --------
//
// Jeder Aufrufer übergibt einen Slice exakter Länge (durch die festen Offsets
// oben garantiert). `try_into` über einen Slice fixer Länge kann nicht fehlen;
// `unwrap_or` mit dem Null-Default bleibt dennoch **panik-frei** (§Stil: kein
// `unwrap`/`expect`/`panic` im Bibliotheks-Pfad). Ein falsch dimensionierter
// Slice wäre ein interner Programmierfehler, der hier konservativ als 0 gelesen
// würde; die festen Offset-Konstanten schließen ihn aus.

fn u16_le(s: &[u8]) -> u16 {
    u16::from_le_bytes(s.try_into().unwrap_or([0u8; 2]))
}

fn u32_le(s: &[u8]) -> u32 {
    u32::from_le_bytes(s.try_into().unwrap_or([0u8; 4]))
}

fn u64_le(s: &[u8]) -> u64 {
    u64::from_le_bytes(s.try_into().unwrap_or([0u8; 8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------------
    // Round-Trip des Record-Framings.
    // ----------------------------------------------------------------------

    #[test]
    fn record_round_trips_header_and_payload() {
        let payload = b"A1 00 43 01 02 03 (kanonisches CBOR-Beispiel)".to_vec();
        let frame = encode_record_to_vec(7, &payload);
        // Gesamtlänge = 64 + payload + 32.
        assert_eq!(frame.len(), RECORD_HEADER_LEN + payload.len() + CHECKSUM_LEN);

        let decoded = decode_record(&frame).expect("gültiger Record");
        assert_eq!(decoded.header.seq, 7);
        assert_eq!(decoded.header.payload_len, payload.len() as u64);
        assert_eq!(decoded.payload, &payload[..]);
        assert_eq!(decoded.total_len, frame.len());
    }

    #[test]
    fn record_magic_and_versions_are_in_the_header() {
        let frame = encode_record_to_vec(0, b"x");
        assert_eq!(&frame[RH_MAGIC..RH_MAGIC + 4], &RECORD_MAGIC);
        assert_eq!(
            u16_le(&frame[RH_FORMAT_VERSION..RH_FORMAT_VERSION + 2]),
            RECORD_FORMAT_VERSION
        );
        assert_eq!(
            u16_le(&frame[RH_CHECKSUM_ALGO..RH_CHECKSUM_ALGO + 2]),
            CHECKSUM_ALGO_BLAKE3
        );
    }

    #[test]
    fn empty_payload_round_trips() {
        // Ein Record mit leerer Nutzlast ist wohlgeformt (Header + 0 + Prüfsumme).
        let frame = encode_record_to_vec(1, &[]);
        assert_eq!(frame.len(), RECORD_HEADER_LEN + CHECKSUM_LEN);
        let decoded = decode_record(&frame).expect("gültiger leerer Record");
        assert_eq!(decoded.header.payload_len, 0);
        assert_eq!(decoded.payload, &[][..]);
    }

    #[test]
    fn two_records_can_be_walked_back_to_back() {
        // Reader-Vorgehen: total_len rückt zum nächsten Record vor.
        let mut log = Vec::new();
        encode_record(10, b"erster", &mut log);
        encode_record(11, b"zweiter-laenger", &mut log);

        let first = decode_record(&log).expect("erster");
        assert_eq!(first.header.seq, 10);
        assert_eq!(first.payload, b"erster");

        let second = decode_record(&log[first.total_len..]).expect("zweiter");
        assert_eq!(second.header.seq, 11);
        assert_eq!(second.payload, b"zweiter-laenger");
    }

    // ----------------------------------------------------------------------
    // Reservierte Felder runden als NULL (v1, §K5.1).
    // ----------------------------------------------------------------------

    #[test]
    fn reserved_record_header_fields_round_trip_as_zero() {
        let frame = encode_record_to_vec(3, b"payload");
        let decoded = decode_record(&frame).expect("gültig");
        assert_eq!(decoded.header.activation_epoch, 0);
        assert_eq!(decoded.header.marker_offset, 0);
        assert_eq!(decoded.header.constituent_range, 0);
        assert_eq!(decoded.header.shard_id, 0);
        assert_eq!(decoded.header.index_validity_offset, 0);
        // Auch das Auffüll-Wort ist physisch NULL.
        assert_eq!(&frame[RH_RESERVED_PAD..RH_RESERVED_PAD + 4], &[0u8; 4]);
    }

    #[test]
    fn marker_and_constituent_range_fields_round_trip() {
        // §13: ein Record mit gesetztem marker_offset/constituent_range round-trippt
        // die Felder und bleibt prüfsummen-gültig (die Felder sind durch die
        // Prüfsumme über Header ‖ Payload gedeckt).
        let header = RecordHeader::new(7, 0)
            .with_marker_offset(4096)
            .with_constituent_range(128);
        let mut out = Vec::new();
        encode_record_with(header, b"constituent", &mut out);
        let decoded = decode_record(&out).expect("gültig");
        assert_eq!(decoded.header.seq, 7);
        assert_eq!(decoded.header.payload_len, b"constituent".len() as u64);
        assert_eq!(decoded.header.marker_offset, 4096);
        assert_eq!(decoded.header.constituent_range, 128);
        assert_eq!(decoded.payload, b"constituent");
    }

    #[test]
    fn encode_record_with_overwrites_payload_len_field() {
        // Eine vom Aufrufer gesetzte payload_len wird autoritativ auf die echte
        // Länge gesetzt (kein abweichendes Längenfeld kann durchrutschen).
        let mut header = RecordHeader::new(1, 9999);
        header.payload_len = 9999; // bewusst falsch.
        let mut out = Vec::new();
        encode_record_with(header, b"abc", &mut out);
        let decoded = decode_record(&out).expect("gültig");
        assert_eq!(decoded.header.payload_len, 3);
    }

    #[test]
    fn flip_in_marker_offset_field_is_detected_by_checksum() {
        // Ein gekipptes Bit im marker_offset-Feld eines Konstituenten ist ein
        // Prüfsummen-Defekt (§Durability) — nie stilles Überspringen.
        let header = RecordHeader::new(2, 0).with_marker_offset(64);
        let mut frame = Vec::new();
        encode_record_with(header, b"x", &mut frame);
        frame[RH_MARKER_OFFSET] ^= 0b0000_0001;
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn reserved_footer_fields_round_trip_as_zero() {
        let footer = BatchFooter::new(5, 100, 104);
        let bytes = footer.encode_to_vec();
        let decoded = BatchFooter::decode(&bytes).expect("gültig");
        assert_eq!(decoded.activation_epoch, 0);
        assert_eq!(decoded.shard_id_packed, 0);
        assert_eq!(decoded.index_validity_offset, 0);
        assert_eq!(&bytes[BF_RESERVED_PAD..BF_RESERVED_PAD + 8], &[0u8; 8]);
    }

    // ----------------------------------------------------------------------
    // Prüfsumme erkennt Ein-Bit-Flips (Korruption, nie still übersprungen).
    // ----------------------------------------------------------------------

    #[test]
    fn checksum_detects_single_bit_flip_in_payload() {
        let mut frame = encode_record_to_vec(2, b"important payload bytes");
        // Ein Bit in der Nutzlast kippen.
        let flip_at = RECORD_HEADER_LEN + 3;
        frame[flip_at] ^= 0b0000_0001;
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn checksum_detects_single_bit_flip_in_header() {
        let mut frame = encode_record_to_vec(2, b"payload");
        // Ein Bit in einem reservierten Header-Feld kippen (nicht Magic/Version).
        frame[RH_ACTIVATION_EPOCH] ^= 0b0000_0001;
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn checksum_detects_single_bit_flip_in_seq() {
        let mut frame = encode_record_to_vec(0x42, b"payload");
        frame[RH_SEQ] ^= 0b0000_0001; // seq 0x42 -> 0x43
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn checksum_detects_flip_in_checksum_itself() {
        let mut frame = encode_record_to_vec(2, b"payload");
        let last = frame.len() - 1;
        frame[last] ^= 0b1000_0000;
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn checksum_function_changes_on_single_bit_flip() {
        let a = checksum(b"abc");
        let b = checksum(b"abd");
        assert_ne!(a, b);
        // Determinismus: gleiche Eingabe ⇒ gleiche Prüfsumme.
        assert_eq!(checksum(b"abc"), a);
    }

    // ----------------------------------------------------------------------
    // Trunkierung von Header / Payload / Footer wird erkannt.
    // ----------------------------------------------------------------------

    #[test]
    fn truncated_header_is_detected() {
        let frame = encode_record_to_vec(1, b"payload");
        // Weniger als der feste Header.
        assert!(matches!(
            decode_record(&frame[..RECORD_HEADER_LEN - 1]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn truncated_payload_is_detected() {
        let frame = encode_record_to_vec(1, b"a longer payload here");
        // Header vollständig, aber Payload+Prüfsumme abgeschnitten.
        let cut = RECORD_HEADER_LEN + 2;
        assert!(matches!(
            decode_record(&frame[..cut]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn truncated_checksum_is_detected() {
        let frame = encode_record_to_vec(1, b"payload");
        // Alles bis auf das letzte Prüfsummen-Byte.
        assert!(matches!(
            decode_record(&frame[..frame.len() - 1]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn wrong_record_magic_is_rejected() {
        let mut frame = encode_record_to_vec(1, b"payload");
        frame[RH_MAGIC] = b'X';
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn unknown_record_format_version_is_rejected() {
        let mut frame = encode_record_to_vec(1, b"payload");
        // format_version = 2 (unbekannt) — und Prüfsumme neu, damit NICHT die
        // Prüfsumme, sondern die Versions-Prüfung greift.
        frame[RH_FORMAT_VERSION..RH_FORMAT_VERSION + 2].copy_from_slice(&2u16.to_le_bytes());
        let payload_len = RECORD_HEADER_LEN + b"payload".len();
        let new_ck = checksum(&frame[..payload_len]);
        frame[payload_len..].copy_from_slice(&new_ck);
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn unknown_checksum_algo_is_rejected() {
        let mut frame = encode_record_to_vec(1, b"payload");
        frame[RH_CHECKSUM_ALGO..RH_CHECKSUM_ALGO + 2].copy_from_slice(&9u16.to_le_bytes());
        let payload_len = RECORD_HEADER_LEN + b"payload".len();
        let new_ck = checksum(&frame[..payload_len]);
        frame[payload_len..].copy_from_slice(&new_ck);
        assert!(matches!(
            decode_record(&frame),
            Err(KernelError::Inconsistent)
        ));
    }

    // ----------------------------------------------------------------------
    // Batch-Footer Round-Trip + Korruption.
    // ----------------------------------------------------------------------

    #[test]
    fn footer_round_trips() {
        let footer = BatchFooter::new(3, 42, 44);
        let bytes = footer.encode_to_vec();
        assert_eq!(bytes.len(), BatchFooter::encoded_len());
        let decoded = BatchFooter::decode(&bytes).expect("gültiger Footer");
        assert_eq!(decoded, footer);
        assert_eq!(decoded.record_count, 3);
        assert_eq!(decoded.first_seq, 42);
        assert_eq!(decoded.last_seq, 44);
    }

    #[test]
    fn footer_magic_is_distinct_from_record_magic() {
        // Ein Footer darf beim Record-Scan nie als Record fehlgedeutet werden.
        assert_ne!(FOOTER_MAGIC, RECORD_MAGIC);
        let footer = BatchFooter::new(1, 0, 0).encode_to_vec();
        // decode_record auf einen Footer ⇒ falsches Magic ⇒ Fehler.
        assert!(matches!(
            decode_record(&footer),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn footer_checksum_detects_single_bit_flip() {
        let mut bytes = BatchFooter::new(3, 42, 44).encode_to_vec();
        bytes[BF_RECORD_COUNT] ^= 0b0000_0001; // record_count 3 -> 2
        assert!(matches!(
            BatchFooter::decode(&bytes),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn truncated_footer_is_detected() {
        let bytes = BatchFooter::new(1, 0, 0).encode_to_vec();
        assert!(matches!(
            BatchFooter::decode(&bytes[..bytes.len() - 1]),
            Err(KernelError::Inconsistent)
        ));
        // Auch ein abgeschnittener Rumpf (vor der Prüfsumme).
        assert!(matches!(
            BatchFooter::decode(&bytes[..BATCH_FOOTER_LEN - 1]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn wrong_footer_format_version_is_rejected() {
        let mut bytes = BatchFooter::new(1, 0, 0).encode_to_vec();
        bytes[BF_FORMAT_VERSION..BF_FORMAT_VERSION + 2].copy_from_slice(&2u16.to_le_bytes());
        let new_ck = checksum(&bytes[..BATCH_FOOTER_LEN]);
        bytes[BATCH_FOOTER_LEN..].copy_from_slice(&new_ck);
        assert!(matches!(
            BatchFooter::decode(&bytes),
            Err(KernelError::Inconsistent)
        ));
    }

    // ----------------------------------------------------------------------
    // Framing ist NICHT Teil des ContentId-Preimage (Doku-Invariante als Test).
    // ----------------------------------------------------------------------

    #[test]
    fn framing_does_not_alter_payload_bytes() {
        // Die Nutzlast (kanonisches CBOR) kommt bit-identisch wieder heraus —
        // das Framing wrappt sie nur, es geht nicht in den ContentId-Preimage ein.
        let canonical = vec![0xA1u8, 0x00, 0x40]; // GV-1: leeres Blatt
        let frame = encode_record_to_vec(99, &canonical);
        let decoded = decode_record(&frame).expect("gültig");
        assert_eq!(decoded.payload, &canonical[..]);
    }

    // ----------------------------------------------------------------------
    // Feste Layout-Größen sind eingefroren.
    // ----------------------------------------------------------------------

    #[test]
    fn fixed_layout_sizes_are_frozen() {
        assert_eq!(RECORD_HEADER_LEN, 64);
        assert_eq!(BATCH_FOOTER_LEN, 64);
        assert_eq!(CHECKSUM_LEN, 32);
        assert_eq!(RECORD_MAGIC, *b"LKR1");
        assert_eq!(FOOTER_MAGIC, *b"LKF1");
        assert_eq!(RECORD_FORMAT_VERSION, 1);
        assert_eq!(CHECKSUM_ALGO_BLAKE3, 1);
    }
}
