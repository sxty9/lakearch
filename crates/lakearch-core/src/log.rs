//! Das **Append-Segment-Log** (§7.1) — die *alleinige* Durability-Wahrheit
//! (§8.4). Höchstrisiko-Modul; deshalb rigoros gefasst.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§7.1 append-only, nie
//! geändert/gelöscht; §8.4 Log = alleinige Wahrheit) und der gehärtete Plan
//! (Abschnitte „Durability, Recovery & Atomarität"). Das Record-/Footer-Framing
//! lebt in [`crate::format`]; dieses Modul fügt die **Datei-I/O**, das
//! **Group-Commit**, die **Durability-on-Ack** und die **Recovery** hinzu.
//!
//! ## Was dieses Modul garantiert
//!
//! - **Schreibpfad `pwrite(2)`** ([`std::os::unix::fs::FileExt::write_at`]): nie
//!   `mmap`-Stores fürs Log.
//! - **Lesepfad read-only `mmap`** — gemappt **nur bis zum letzten committeten
//!   Batch-Footer-Offset** (der committed offset / Watermark `W`). Nie in den
//!   gerade geschriebenen Bereich oder über EOF (kein Torn-Read/SIGBUS).
//! - **Group-Commit:** ein Batch endet mit einem geprüfsummten **Footer**
//!   ([`crate::format::BatchFooter`]); ein Batch ist durabel **genau dann**, wenn
//!   sein Footer durabel (gefsynct) ist (WAL-Commit-Record).
//! - **Durability-on-Ack:** ein `append` ist erst **nach** dem einschließenden
//!   Group-Commit-`fsync` aufgelöst (ackt); vorher ist es nur *gepuffert* und
//!   für Leser **unsichtbar**.
//! - **fsync-Fehler = fatal** (Linux errseq/„fsyncgate"): das Log wird
//!   **vergiftet** ([`KernelError::Poisoned`]); ein Retry-als-Erfolg ist
//!   verboten.
//! - **monotone seq** pro **physisch geschriebenem** Record (ein Content-Dedup-
//!   Treffer §5.3 schreibt nichts und verbraucht keine seq — die Dedup-Logik
//!   liegt über diesem Modul, hier wird seq strikt fortlaufend vergeben).
//! - **Prüfsumme vor Herausgabe:** ein gelesener Record wird **erst** nach
//!   verifizierter Prüfsumme als Bytes herausgegeben (§Durability;
//!   [`crate::format::decode_record`] prüft sie).
//!
//! ## `unsafe`-Kapselung
//!
//! Dies ist das **Leaf-Modul** für `mmap`. Alles `unsafe` (genau **ein**
//! `MmapOptions::map`-Aufruf) ist hier mit `#[deny(unsafe_op_in_unsafe_fn)]` und
//! SAFETY-Kommentaren gekapselt. Die Tor-/Modell-/Traversier-Module bleiben
//! `#![forbid(unsafe_code)]`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use memmap2::{Mmap, MmapOptions};

use crate::error::KernelError;
use crate::format::{
    decode_record, encode_record, encode_record_with, BatchFooter, RecordHeader, CHECKSUM_LEN,
    RECORD_HEADER_LEN, RECORD_MAGIC,
};

/// Dateiname des (in v1 einzigen) Segments im Log-Verzeichnis.
///
/// In Phase 1 nutzt das Log **ein** Segment. Der Name ist null-gepolstert und
/// lexikographisch sortierbar, damit spätere Phasen (Roll-over, mehrere
/// Segmente) ihn ohne Format-Bruch erweitern können. Das **Erstellen** eines
/// neuen Segments löst einen Verzeichnis-`fsync` aus (§Durability).
const SEGMENT_FILE_NAME: &str = "000000000000.seg";

/// Ein durables Such-Ergebnis: die kanonischen Nutzlast-Bytes eines Records und
/// seine monotone `seq`. Die Prüfsumme ist beim Lesen bereits **verifiziert**
/// (§Durability) — die Bytes werden nie unverifiziert herausgegeben.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoggedRecord {
    /// Monotone Sequenznummer des physischen Records (§Durability).
    pub seq: u64,
    /// Die Nutzlast (kanonisches CBOR des Daten, §K5). Geht **nicht** ins Framing
    /// ein; ist das einzige, was in den `ContentId`-Preimage fließt.
    pub payload: Vec<u8>,
    /// Byte-Offset des Record-Frame-Anfangs im Segment (Speicher-Adresse §5.2;
    /// urteilt nicht). Stabiler Lese-Handle innerhalb dieses Bestands.
    pub offset: u64,
    /// **§13-Sichtbarkeit:** Offset des regierenden Aktiv-Markers, falls dieser
    /// Record ein **bedingter Konstituent** ist; sonst `0` (= **unbedingt**, ein
    /// gewöhnlicher Einzel-Append). Ein Konstituent ist erst sichtbar, wenn sein
    /// Marker durabel committet ist ([`SegmentLog::visible`]).
    pub marker_offset: u64,
    /// **§13-Audit:** auf einem **Marker-Record** der Anfangs-Offset des ersten
    /// Konstituenten (gepackter Bereich, vgl. [`RecordHeader::with_constituent_range`]);
    /// auf gewöhnlichen Records `0`. Nur Audit/Rekonstruktion — **keine**
    /// Sichtbarkeits-Autorität.
    pub constituent_range: u64,
}

/// Handle eines **gestageten Umbaus** (§13): die durablen Offsets der bedingten
/// Konstituenten und der (gemeinsame) Offset ihres regierenden Markers.
///
/// Zwischen [`SegmentLog::stage_constituents`] und [`SegmentLog::commit_marker`]
/// sind die Konstituenten **durabel, aber inaktiv** (ihr `marker_offset == marker_offset`
/// dieses Handles liegt **über** dem Watermark `W`); der Marker-Commit flippt sie
/// gemeinsam sichtbar.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StagedRestructuring {
    /// Die Frame-Anfangs-Offsets der Konstituenten-Records, in Schreib-Reihenfolge.
    constituent_offsets: Vec<u64>,
    /// Anfangs-Offset des **ersten** Konstituenten (= Beginn des inklusiven
    /// Bereichs `[first_constituent_offset, marker_offset)`).
    first_constituent_offset: u64,
    /// Offset des regierenden **Markers** (jeder Konstituent trägt ihn in
    /// `marker_offset`). Solange `marker_offset > W`, sind die Konstituenten inaktiv.
    marker_offset: u64,
}

impl StagedRestructuring {
    /// Die Frame-Anfangs-Offsets der Konstituenten-Records (Speicher-Adressen §5.2;
    /// urteilt nicht), in Schreib-Reihenfolge.
    pub fn constituent_offsets(&self) -> &[u64] {
        &self.constituent_offsets
    }

    /// Der Offset des regierenden **Markers** (§13): solange das Snapshot-Watermark
    /// `W < marker_offset`, sind alle Konstituenten inaktiv ([`SegmentLog::visible`]).
    pub fn marker_offset(&self) -> u64 {
        self.marker_offset
    }

    /// Anfangs-Offset des ersten Konstituenten (Beginn des inklusiven
    /// Konstituenten-Bereichs `[first_constituent_offset, marker_offset)`, Audit §13).
    pub fn first_constituent_offset(&self) -> u64 {
        self.first_constituent_offset
    }
}

/// Leichtgewichtige **Betriebs-Zähler** des Logs (§Betrieb). Reine Mechanik-
/// Signale (§1.4): keine Wertung, keine sichtbaren Daten/IDs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LogMetrics {
    /// Anzahl **physisch geschriebener** Records (ohne Dedup-Treffer — die liegen
    /// über diesem Modul).
    pub append_count: u64,
    /// Anzahl committeter Batches (= Group-Commit-`fsync`s der Daten).
    pub batch_count: u64,
    /// Anzahl `fsync`-Aufrufe (Daten **und** Verzeichnis).
    pub fsync_count: u64,
    /// Anzahl Segmente (in v1 stets 1).
    pub segment_count: u64,
    /// Committete Log-Bytes (= Watermark `W`, der committed offset).
    pub committed_bytes: u64,
}

/// Das **Append-Segment-Log**: öffnet ein Verzeichnis, hängt gerahmte Records per
/// `pwrite` an, gruppiert sie in Batches mit geprüfsummtem Footer, `fsync`t Daten
/// (und bei neuem Segment das Verzeichnis) und gibt Lesern nur den **committeten**
/// Präfix per read-only `mmap` frei.
///
/// **Nebenläufigkeit (Phase 1).** Dieses Struct ist der **eine** Append-Pfad
/// (`&mut self` für jede Mutation); MVCC-Leser und die volle Pipeline folgen in
/// späteren Phasen. Es ist `Send` (besitzt nur `File`/`PathBuf`/`Vec`), aber
/// nicht zur gleichzeitigen Mutation aus mehreren Threads gedacht.
pub struct SegmentLog {
    /// Pfad des Log-Verzeichnisses (für Verzeichnis-`fsync`).
    dir: PathBuf,
    /// Das (in v1 einzige) Segment, schreib-/lesegeöffnet.
    segment: File,
    /// Byte-Offset des **nächsten** zu schreibenden Bytes (Schreib-Front). Liegt
    /// stets ≥ [`Self::committed_offset`]; der Bereich
    /// `[committed_offset, write_offset)` ist gepuffert/un-geacked.
    write_offset: u64,
    /// Der **committed offset** (Watermark `W`): Offset **nach** dem letzten
    /// durablen Batch-Footer. Leser sehen ausschließlich `[0, committed_offset)`.
    committed_offset: u64,
    /// Die nächste zu vergebende monotone `seq` (§Durability). Beginnt bei 0.
    next_seq: u64,
    /// Read-only-Mapping des committeten Präfixes `[0, mmap_len)`. Lazy (re-)gemappt
    /// bis [`Self::committed_offset`]; nie über EOF / in den Schreibbereich.
    mmap: Option<Mmap>,
    /// Länge des aktuellen Mappings in Bytes (= der committed offset zur Map-Zeit).
    mmap_len: u64,
    /// **Gift-Flag** (§Durability): nach einem fatalen Fehler (fsync-Fehler,
    /// Korruption) schlägt jede weitere Operation mit [`KernelError::Poisoned`]
    /// fehl, statt auf einem halb-gültigen Zustand fortzufahren.
    poisoned: bool,
    /// Pending-Batch-Puffer: gerahmte Record-Bytes seit dem letzten Commit. Wird
    /// beim Commit per `pwrite` ab [`Self::committed_offset`] geschrieben.
    pending: Vec<u8>,
    /// seq des **ersten** Records im aktuellen Pending-Batch (für den Footer).
    pending_first_seq: u64,
    /// Anzahl Records im aktuellen Pending-Batch (für den Footer).
    pending_count: u64,
    /// Betriebs-Zähler (§Betrieb).
    metrics: LogMetrics,
}

impl SegmentLog {
    /// **Öffnet** (oder erstellt) ein Segment-Log im Verzeichnis `dir`.
    ///
    /// Existiert das Segment, läuft **Recovery** (siehe [`Self::recover`]): bis
    /// zum letzten gültigen Footer wird der durable Präfix bestätigt, der un-ackte
    /// Tail **danach** abgeschnitten; eine Prüfsummen-Verletzung oder seq-Lücke
    /// **vor** dem letzten Footer ⇒ [`KernelError::Corruption`] (HALT, **kein**
    /// Auto-Truncate). Existiert es nicht, wird es erstellt und das Verzeichnis
    /// gefsynct (§Durability).
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KernelError> {
        let dir = dir.as_ref().to_path_buf();
        let seg_path = dir.join(SEGMENT_FILE_NAME);
        let existed = seg_path.exists();

        let segment = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&seg_path)
            .map_err(|_| KernelError::Io)?;

        let mut log = SegmentLog {
            dir,
            segment,
            write_offset: 0,
            committed_offset: 0,
            next_seq: 0,
            mmap: None,
            mmap_len: 0,
            poisoned: false,
            pending: Vec::new(),
            pending_first_seq: 0,
            pending_count: 0,
            metrics: LogMetrics {
                segment_count: 1,
                ..LogMetrics::default()
            },
        };

        if existed {
            // Recovery über das vorhandene Segment.
            log.recover()?;
        } else {
            // Frisches Segment: das Verzeichnis fsyncen, damit der Datei-Eintrag
            // selbst einen Crash überlebt (§Durability: Directory-fsync nach
            // Segment-Erstellung).
            log.fsync_dir()?;
        }

        // Mapping auf den committeten Präfix bringen (kann 0 sein → kein Mapping).
        log.remap_committed()?;
        Ok(log)
    }

    /// Hängt einen Record (die kanonischen Nutzlast-Bytes) an den **aktuellen
    /// Batch** an und gibt seine `seq` zurück.
    ///
    /// **Noch nicht durabel/ackbar:** der Record ist nur **gepuffert** und für
    /// Leser **unsichtbar**, bis [`Self::commit`] ihn (und den Batch) per
    /// `fsync` durabel macht (Durability-on-Ack). Die `seq` ist die nächste
    /// monotone Sequenznummer über physische Records (§Durability).
    ///
    /// Der Aufrufer (die schreibende Schicht / Dedup-Logik darüber) entscheidet,
    /// **ob** überhaupt geschrieben wird (§5.3-Dedup); dieses Modul schreibt
    /// jeden übergebenen Record physisch und vergibt eine seq.
    pub fn append_record(&mut self, payload: &[u8]) -> Result<u64, KernelError> {
        self.ensure_live()?;
        let seq = self.next_seq;
        if self.pending_count == 0 {
            self.pending_first_seq = seq;
        }
        // Den gerahmten Record (Header ‖ Payload ‖ Prüfsumme) in den Pending-Puffer
        // kodieren. Noch **kein** pwrite — das macht der Commit gebündelt.
        encode_record(seq, payload, &mut self.pending);
        self.pending_count += 1;
        self.next_seq += 1;
        Ok(seq)
    }

    /// **Group-Commit** (§Durability): schreibt den aktuellen Batch (alle seit dem
    /// letzten Commit gepufferten Records) per `pwrite` ab dem committed offset,
    /// hängt einen geprüfsummten **Footer** an, `fsync`t die Daten und veröffentlicht
    /// erst **danach** den neuen committed offset (Watermark `W`).
    ///
    /// **Durability-on-Ack:** erst nach Rückkehr dieser Funktion gelten die
    /// Records des Batches als geackt und werden für Leser sichtbar. Ein leerer
    /// Batch (kein `append_record` seit dem letzten Commit) ist ein No-op.
    ///
    /// Ein `fsync`-Fehler ist **fatal**: das Log wird vergiftet und der Fehler
    /// hart zurückgegeben (§Durability — nie Retry-als-Erfolg).
    pub fn commit(&mut self) -> Result<(), KernelError> {
        self.ensure_live()?;
        if self.pending_count == 0 {
            // Leerer Batch: kein Footer, kein fsync, keine seq verbraucht.
            return Ok(());
        }

        let last_seq = self.next_seq - 1; // pending_count ≥ 1 ⇒ next_seq ≥ 1.
        let footer = BatchFooter::new(self.pending_count, self.pending_first_seq, last_seq);
        footer.encode_into(&mut self.pending);

        // 1) Records ‖ Footer per pwrite ab dem committed offset schreiben. Wir
        //    schreiben **immer** ab `committed_offset` (nicht `write_offset`):
        //    ein vorhergehender Teil-Write/Crash hat den committed offset nicht
        //    bewegt, also überschreiben wir einen etwaigen un-ackten Tail sauber.
        let start = self.committed_offset;
        if let Err(e) = self.segment.write_all_at(&self.pending, start) {
            // Teil-Write: der committed offset bleibt unverändert → der Batch ist
            // nicht durabel; Recovery/erneuter Commit räumt den Tail auf.
            return Err(self.poison_from_io(e));
        }

        // 2) fsync der Daten: der Batch ist genau dann durabel, wenn sein Footer
        //    durabel ist. Ein fsync-Fehler ist FATAL (errseq) → vergiften.
        self.fsync_data()?;

        // 3) Erst JETZT den committed offset (Watermark) veröffentlichen.
        let committed_len = self.pending.len() as u64;
        self.write_offset = start + committed_len;
        self.committed_offset = self.write_offset;
        self.metrics.batch_count += 1;
        self.metrics.append_count += self.pending_count;
        self.metrics.committed_bytes = self.committed_offset;

        // Pending zurücksetzen.
        self.pending.clear();
        self.pending_count = 0;
        self.pending_first_seq = self.next_seq;

        // Read-Mapping auf den neuen committeten Präfix nachziehen.
        self.remap_committed()?;
        Ok(())
    }

    /// Bequemer Ein-Record-Pfad: hängt einen Record an und committet ihn sofort
    /// als eigenen Batch (Records ‖ Footer ‖ `fsync`). Liefert die `seq`.
    ///
    /// Erst nach Rückkehr ist der Record geackt/sichtbar (Durability-on-Ack).
    pub fn append_and_commit(&mut self, payload: &[u8]) -> Result<u64, KernelError> {
        let seq = self.append_record(payload)?;
        self.commit()?;
        Ok(seq)
    }

    // -- §13 Aktiv-Marker: Staging inaktiv → ein Marker-Commit flippt sichtbar ---

    /// **stage_constituents** (§13) — schreibt eine Menge **bedingter Konstituenten**
    /// als eigenen Group-Commit-Batch und gibt einen [`StagedRestructuring`]-Handle
    /// zurück. Die Konstituenten sind danach zwar **durabel**, aber **inaktiv**: jeder
    /// trägt im Header den Offset seines noch nicht geschriebenen **Markers**
    /// (`marker_offset`), und der ist (per Konstruktion) **größer** als das aktuelle
    /// Watermark `W`. Bis [`SegmentLog::commit_marker`] den Marker durabel macht,
    /// ignoriert [`SegmentLog::visible`] sie also (§13.2).
    ///
    /// **Eine Linearisierungsstelle, ein Watermark.** Es gibt **keine** zweite Epoche:
    /// der Marker-Offset wird **deterministisch vorausberechnet** (der Marker folgt
    /// unmittelbar auf den Konstituenten-Batch), in jeden Konstituenten gestempelt,
    /// der Konstituenten-Batch ge-`fsync`t (W rückt über die Konstituenten vor) — und
    /// **erst** ein späterer `commit_marker` rückt W über den Marker. Ein Crash
    /// **zwischen** beiden Commits lässt die Konstituenten durabel, aber für immer
    /// inaktiv (ihr `marker_offset > W`), denn der Marker wurde nie durabel.
    ///
    /// `constituent_payloads` darf **nicht leer** sein (ein Umbau betrifft mindestens
    /// ein Daten, §13.1); sonst [`KernelError::Inconsistent`]. Ein etwaiger offener
    /// Pending-Batch wird zuerst committet, damit die Konstituenten an einer sauberen
    /// Commit-Grenze beginnen (so ist ihr Offset wohldefiniert).
    pub fn stage_constituents(
        &mut self,
        constituent_payloads: &[&[u8]],
    ) -> Result<StagedRestructuring, KernelError> {
        self.ensure_live()?;
        if constituent_payloads.is_empty() {
            // Ein Umbau betrifft mindestens ein Daten (§13.1).
            return Err(KernelError::Inconsistent);
        }
        // Etwaigen offenen Einzel-Append-Batch zuerst committen, damit die
        // Konstituenten an einer sauberen committeten Grenze beginnen (ihr Offset
        // ist sonst nicht wohldefiniert).
        if self.pending_count != 0 {
            self.commit()?;
        }

        // Offsets DETERMINISTISCH vorausberechnen: die Konstituenten liegen
        // contiguous ab dem aktuellen committed offset; der Marker folgt unmittelbar
        // nach dem Konstituenten-Batch (dessen Records ‖ Footer).
        let first_constituent_offset = self.committed_offset;
        let mut constituent_offsets: Vec<u64> = Vec::with_capacity(constituent_payloads.len());
        let mut cursor = first_constituent_offset;
        for p in constituent_payloads {
            constituent_offsets.push(cursor);
            cursor = cursor
                .checked_add(record_frame_len(p.len())?)
                .ok_or(KernelError::Inconsistent)?;
        }
        // Ende des Konstituenten-Batches = nach allen Records + dem Batch-Footer.
        let marker_offset = cursor
            .checked_add(BatchFooter::encoded_len() as u64)
            .ok_or(KernelError::Inconsistent)?;

        // Die Konstituenten in den Pending-Puffer kodieren — jeder mit seinem
        // `marker_offset` gestempelt (bedingter Record, §13).
        for p in constituent_payloads {
            self.append_constituent_record(p, marker_offset);
        }
        // Den Konstituenten-Batch durabel machen (fsync, W rückt über sie hinaus).
        self.commit()?;
        // Sanity: der vorausberechnete Marker-Offset MUSS exakt am neuen committed
        // offset liegen (sonst stimmte die Offset-Arithmetik nicht — interner Bruch).
        if self.committed_offset != marker_offset {
            self.poisoned = true;
            return Err(KernelError::Inconsistent);
        }

        Ok(StagedRestructuring {
            constituent_offsets,
            first_constituent_offset,
            marker_offset,
        })
    }

    /// **commit_marker** (§13) — schreibt den **einen abschließenden Marker-Record**
    /// und macht ihn durabel; **dieser eine Commit** flippt alle Konstituenten des
    /// Umbaus **gemeinsam sichtbar** (§13.1, „gemeinsame Sichtbarkeit durch ein
    /// einziges abschließendes Aktiv-Schreiben"). Erst nach Rückkehr ist das
    /// Watermark `W` über den Marker hinaus, womit für jeden Konstituenten
    /// `marker_offset <= W` gilt — die Atomarität **ohne Transaktions-Maschinerie**
    /// (§13.3).
    ///
    /// Der Marker MUSS am vom `handle` vorhergesagten Offset landen (der
    /// Konstituenten-Batch darf seit dem Staging nicht weitergeschrieben worden sein);
    /// sonst [`KernelError::Inconsistent`]. Der Marker trägt im Header den
    /// Anfangs-Offset des ersten Konstituenten (`constituent_range`) als
    /// Audit-/Rekonstruktions-Information (§13) — die Sichtbarkeits-Autorität bleibt
    /// allein der Offset-Vergleich. Liefert den (durablen) Offset des Markers.
    pub fn commit_marker(
        &mut self,
        handle: &StagedRestructuring,
        marker_payload: &[u8],
    ) -> Result<u64, KernelError> {
        self.ensure_live()?;
        // Der Marker muss exakt an der vorhergesagten Stelle landen (keine fremden
        // Appends zwischen Staging und Marker-Commit).
        if self.committed_offset != handle.marker_offset || self.pending_count != 0 {
            return Err(KernelError::Inconsistent);
        }
        self.append_marker_record(marker_payload, handle.first_constituent_offset);
        let marker_offset = handle.marker_offset;
        // Genau dieser Commit (fsync) flippt den Umbau gemeinsam sichtbar.
        self.commit()?;
        Ok(marker_offset)
    }

    /// **append_restructuring** (§13) — der **vollständige** Pfad: stage die
    /// Konstituenten (inaktiv) **und** committe sofort ihren Marker, sodass der
    /// ganze Umbau am Ende gemeinsam sichtbar ist (§13.1). Bequemer Wrapper über
    /// [`stage_constituents`](SegmentLog::stage_constituents) +
    /// [`commit_marker`](SegmentLog::commit_marker); liefert den Handle (er trägt die
    /// Konstituenten-Offsets **und** den Marker-Offset).
    ///
    /// Crash-Atomarität bleibt gewahrt: scheitert/crasht es **nach** den
    /// Konstituenten, aber **vor** dem Marker-`fsync`, sind die Konstituenten zwar
    /// durabel, aber für immer inaktiv (ihr `marker_offset > W`).
    pub fn append_restructuring(
        &mut self,
        constituent_payloads: &[&[u8]],
        marker_payload: &[u8],
    ) -> Result<StagedRestructuring, KernelError> {
        let handle = self.stage_constituents(constituent_payloads)?;
        self.commit_marker(&handle, marker_payload)?;
        Ok(handle)
    }

    /// **§13-Sichtbarkeits-Prädikat** — der **einzige** Sichtbarkeits-Maßstab: ein
    /// Record an `offset` mit Marker-Bezug `marker_offset` ist gegenüber dem
    /// Snapshot-Watermark `w` sichtbar ⇔
    ///
    /// > `offset < w  ∧  (marker_offset == 0  ∨  marker_offset < w)`.
    ///
    /// Also: der Record selbst muss durabel sein (`offset < w`) **und** er ist
    /// entweder **unbedingt** (`marker_offset == 0`, gewöhnlicher Einzel-Append) oder
    /// sein **regierender Marker** ist ebenfalls durabel (`marker_offset < w`).
    ///
    /// **Striktes `<`** (nicht `<=`): das Watermark `w` ([`committed_offset`]) zeigt
    /// **hinter** den letzten durablen Batch-Footer (Ende-des-Batches-Konvention,
    /// vgl. [`read_at`], das `offset >= committed_offset` ablehnt). Ein Record/Marker,
    /// der bei `o` **beginnt**, ist also genau dann durabel, wenn `o < w` (sein Frame
    /// liegt vollständig im committeten Präfix). Wäre der Marker nur **gestaget** (sein
    /// Konstituenten-Batch committet, der Marker selbst noch nicht), gilt
    /// `w == marker_offset` — und `marker_offset < w` ist **falsch**, der Konstituent
    /// also korrekt **inaktiv** (§13.2). Erst der Marker-Commit rückt `w` strikt über
    /// `marker_offset` und flippt gemeinsam sichtbar (§13.1).
    ///
    /// Reiner Offset-Vergleich — **keine** zweite Epoche, **kein** Wall-Clock
    /// (§1.4/§13). Ein über-frisches Watermark ist harmlos; ein unter-frisches kommt
    /// per Konstruktion nicht vor (W wird erst **nach** dem fsync veröffentlicht).
    pub fn visible(offset: u64, marker_offset: u64, w: u64) -> bool {
        offset < w && (marker_offset == 0 || marker_offset < w)
    }

    /// `true`, wenn `rec` unter dem Snapshot-Watermark `w` sichtbar ist (§13) —
    /// Bequem-Hülle um [`SegmentLog::visible`] über die Felder eines
    /// [`LoggedRecord`].
    pub fn record_visible(rec: &LoggedRecord, w: u64) -> bool {
        Self::visible(rec.offset, rec.marker_offset, w)
    }

    /// Hängt einen **bedingten Konstituenten** (§13) in den aktuellen Pending-Batch
    /// an: ein gerahmter Record mit gestempeltem `marker_offset`. Vergibt die nächste
    /// monotone `seq` (wie [`append_record`](SegmentLog::append_record)). Noch nicht
    /// durabel — das macht der Commit.
    fn append_constituent_record(&mut self, payload: &[u8], marker_offset: u64) {
        let seq = self.next_seq;
        if self.pending_count == 0 {
            self.pending_first_seq = seq;
        }
        let header = RecordHeader::new(seq, payload.len() as u64).with_marker_offset(marker_offset);
        encode_record_with(header, payload, &mut self.pending);
        self.pending_count += 1;
        self.next_seq += 1;
    }

    /// Hängt den **Marker-Record** (§13) in den aktuellen Pending-Batch an: ein
    /// gerahmter Record mit gesetztem `constituent_range` (Anfangs-Offset des ersten
    /// Konstituenten, Audit). Der Marker selbst ist **unbedingt** (`marker_offset ==
    /// 0`): er wird sichtbar, sobald er durabel ist (`offset <= W`), und flippt damit
    /// seine Konstituenten mit.
    fn append_marker_record(&mut self, payload: &[u8], first_constituent_offset: u64) {
        let seq = self.next_seq;
        if self.pending_count == 0 {
            self.pending_first_seq = seq;
        }
        let header = RecordHeader::new(seq, payload.len() as u64)
            .with_constituent_range(first_constituent_offset);
        encode_record_with(header, payload, &mut self.pending);
        self.pending_count += 1;
        self.next_seq += 1;
    }

    /// Der **committed offset** (Watermark `W`): Offset nach dem letzten durablen
    /// Batch-Footer. Leser sehen ausschließlich `[0, committed_offset)`.
    pub fn committed_offset(&self) -> u64 {
        self.committed_offset
    }

    /// Die nächste zu vergebende `seq` (= Anzahl bisher physisch geschriebener +
    /// gepufferter Records).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Betriebs-Zähler (§Betrieb). Reine Mechanik (§1.4).
    pub fn metrics(&self) -> LogMetrics {
        self.metrics
    }

    /// Liest **alle committeten** Records in seq-Reihenfolge über das read-only-
    /// `mmap` und gibt sie owned zurück. Jede Prüfsumme wird **vor** der Herausgabe
    /// der Bytes verifiziert (§Durability); ein Defekt im committeten Bereich ist
    /// [`KernelError::Corruption`] (sollte nach erfolgreicher Recovery nie
    /// auftreten, wird aber nie still übersprungen).
    ///
    /// Das Mapping reicht **nur** bis [`Self::committed_offset`] — nie in den
    /// gerade geschriebenen Bereich oder über EOF (kein Torn-Read/SIGBUS).
    pub fn read_all(&self) -> Result<Vec<LoggedRecord>, KernelError> {
        if self.poisoned {
            return Err(KernelError::Poisoned);
        }
        let mut out = Vec::new();
        self.for_each_committed_record(|rec| {
            out.push(rec);
            Ok(())
        })?;
        Ok(out)
    }

    /// Liest einen einzelnen committeten Record an `offset` (Frame-Anfang) über das
    /// read-only-`mmap`. Verifiziert die Prüfsumme **vor** der Herausgabe
    /// (§Durability). `offset` muss innerhalb `[0, committed_offset)` und auf einem
    /// Record-Frame-Anfang liegen; sonst [`KernelError::Inconsistent`].
    pub fn read_at(&self, offset: u64) -> Result<LoggedRecord, KernelError> {
        if self.poisoned {
            return Err(KernelError::Poisoned);
        }
        let committed = self.committed_offset;
        let off = usize::try_from(offset).map_err(|_| KernelError::Inconsistent)?;
        let committed_us = usize::try_from(committed).map_err(|_| KernelError::Inconsistent)?;
        if offset >= committed {
            return Err(KernelError::Inconsistent);
        }
        let map = match &self.mmap {
            Some(m) => m,
            // committed > 0, aber kein Mapping: interner Widerspruch.
            None => return Err(KernelError::Inconsistent),
        };
        // SAFETY-frei: `map` ist ein `&[u8]` (Deref); wir slicen nur innerhalb
        // `[off, committed)`. `decode_record` verifiziert die Prüfsumme.
        let window = &map[off..committed_us];
        // Beim Einzel-Lesen darf der Frame nicht über `committed` hinausragen; das
        // garantiert die Footer-/seq-validierte Recovery. `decode_record` prüft
        // zusätzlich Trunkierung relativ zum übergebenen Slice.
        if window.len() >= 4 && window[..4] != RECORD_MAGIC {
            // Ein Footer-Magic o. Ä. an dieser Stelle ⇒ kein Record-Frame-Anfang.
            return Err(KernelError::Inconsistent);
        }
        let decoded = decode_record(window).map_err(|_| KernelError::Inconsistent)?;
        Ok(LoggedRecord {
            seq: decoded.header.seq,
            payload: decoded.payload.to_vec(),
            offset,
            marker_offset: decoded.header.marker_offset,
            constituent_range: decoded.header.constituent_range,
        })
    }

    // -- intern: Recovery -----------------------------------------------------

    /// **Recovery** (§Durability) über das geöffnete Segment.
    ///
    /// Scannt **Record für Record** ab Offset 0: jeder Record-Frame wird streng
    /// dekodiert (Prüfsumme + Magic, [`decode_record`]) und die `seq`-Kette auf
    /// **Lückenlosigkeit** geprüft; ein angetroffener **Batch-Footer** schließt
    /// einen Batch ab — sein `record_count`/`first_seq`/`last_seq` muss zum gerade
    /// gescannten Batch passen. Der Offset **nach** dem letzten **gültigen** Footer
    /// ist der committed offset.
    ///
    /// - Defekt (Prüfsumme/seq-Lücke/Trunkierung) **im** Tail **nach** dem letzten
    ///   gültigen Footer ⇒ nur un-ackte Daten: der Tail wird auf den committed
    ///   offset **trunkiert** (§7.1-konform: nur un-geackte Daten weg).
    /// - Defekt **vor**/**innerhalb** eines bereits gültig abgeschlossenen Batches
    ///   ⇒ beschädigte **durable** Daten ⇒ [`KernelError::Corruption`] (HALT,
    ///   **kein** Auto-Truncate).
    fn recover(&mut self) -> Result<(), KernelError> {
        // Den Segment-Inhalt vollständig lesen (Recovery ist ein einmaliger Scan;
        // ein read-only-mmap des gesamten Files wäre hier riskant, weil der Tail
        // un-ackt/torn sein darf — wir lesen daher in einen Vec).
        let file_len = self.segment.metadata().map_err(|_| KernelError::Io)?.len();
        let file_len_us = usize::try_from(file_len).map_err(|_| KernelError::Inconsistent)?;
        let mut buf = vec![0u8; file_len_us];
        // pread des gesamten Files ab 0.
        self.segment
            .read_exact_at(&mut buf, 0)
            .map_err(|_| KernelError::Io)?;

        let scan = scan_segment(&buf)?;

        // committed offset = Ende des letzten gültigen Footers.
        self.committed_offset = scan.committed_offset;
        self.write_offset = scan.committed_offset;
        self.next_seq = scan.next_seq;
        self.metrics.append_count = scan.committed_record_count;
        self.metrics.batch_count = scan.committed_batch_count;
        self.metrics.committed_bytes = scan.committed_offset;
        self.pending_first_seq = self.next_seq;

        // Den un-ackten Tail nach dem committed offset abschneiden (nur un-geackte
        // Daten — §7.1-konform). Falls die Datei bereits exakt am committed offset
        // endet, ist das ein No-op.
        if file_len > scan.committed_offset {
            self.segment
                .set_len(scan.committed_offset)
                .map_err(|_| KernelError::Io)?;
            // Eine Truncation ändert Metadaten/Größe → fsyncen, damit die
            // Verkürzung selbst durabel ist (sonst kann ein erneuter Crash den
            // alten Tail zurückbringen).
            self.fsync_data()?;
        }
        Ok(())
    }

    // -- intern: I/O-Primitive (fsync, Mapping) -------------------------------

    /// `fsync` der Segment-Daten. Ein Fehler ist **fatal** (errseq): vergiften und
    /// hart zurückgeben (§Durability — nie Retry-als-Erfolg).
    fn fsync_data(&mut self) -> Result<(), KernelError> {
        match self.segment.sync_all() {
            Ok(()) => {
                self.metrics.fsync_count += 1;
                Ok(())
            }
            Err(e) => Err(self.poison_from_io(e)),
        }
    }

    /// `fsync` des Log-Verzeichnisses (nach Segment-Erstellung/Rename; §Durability).
    /// Ein Fehler ist **fatal**.
    fn fsync_dir(&mut self) -> Result<(), KernelError> {
        let dir = match File::open(&self.dir) {
            Ok(d) => d,
            Err(e) => return Err(self.poison_from_io(e)),
        };
        match dir.sync_all() {
            Ok(()) => {
                self.metrics.fsync_count += 1;
                Ok(())
            }
            Err(e) => Err(self.poison_from_io(e)),
        }
    }

    /// (Re-)mappt den committeten Präfix `[0, committed_offset)` **read-only**.
    /// Ist der committed offset 0, gibt es kein Mapping. Das Mapping reicht **nie**
    /// über den committed offset hinaus (kein Torn-Read/SIGBUS).
    fn remap_committed(&mut self) -> Result<(), KernelError> {
        if self.committed_offset == 0 {
            self.mmap = None;
            self.mmap_len = 0;
            return Ok(());
        }
        if self.mmap.is_some() && self.mmap_len == self.committed_offset {
            // Mapping ist schon aktuell.
            return Ok(());
        }
        let len = usize::try_from(self.committed_offset).map_err(|_| KernelError::Inconsistent)?;
        // Vor dem Mapping das alte fallenlassen, damit kein doppeltes Mapping
        // gleichzeitig lebt.
        self.mmap = None;
        // SAFETY: Wir mappen das Segment read-only mit **fester Länge `len` =
        // committed_offset**, also ausschließlich den durablen, gefsynct-en
        // Präfix `[0, committed_offset)`. Wir mappen NIE den gerade geschriebenen
        // Bereich oder über EOF hinaus (die Datei ist nach jedem Commit mindestens
        // `committed_offset` lang), womit Torn-Reads/SIGBUS auf wachsenden/
        // un-ackten Bytes ausgeschlossen sind. Das Mapping ist `PROT_READ`
        // (memmap2 `Mmap` ist immutabel); wir geben Bytes erst nach verifizierter
        // Prüfsumme heraus. Out-of-Band-Truncation durch Dritte ist ein Operator-
        // Vertragsbruch (§Sicherheit) und außerhalb dieser Garantie.
        let map = unsafe { MmapOptions::new().offset(0).len(len).map(&self.segment) };
        match map {
            Ok(m) => {
                self.mmap = Some(m);
                self.mmap_len = self.committed_offset;
                Ok(())
            }
            Err(e) => Err(self.poison_from_io(e)),
        }
    }

    /// Iteriert über alle **committeten** Records (`[0, committed_offset)`) in
    /// seq-Reihenfolge und ruft `f` mit jedem. Verifiziert jede Prüfsumme **vor**
    /// dem Callback (§Durability). Footer werden übersprungen (sie sind keine
    /// Records). Ein Defekt im committeten Bereich ⇒ [`KernelError::Corruption`].
    fn for_each_committed_record<F>(&self, mut f: F) -> Result<(), KernelError>
    where
        F: FnMut(LoggedRecord) -> Result<(), KernelError>,
    {
        let committed = match usize::try_from(self.committed_offset) {
            Ok(c) => c,
            Err(_) => return Err(KernelError::Inconsistent),
        };
        if committed == 0 {
            return Ok(());
        }
        let map = match &self.mmap {
            Some(m) => m,
            None => return Err(KernelError::Inconsistent),
        };
        let bytes = &map[..committed];
        let mut pos = 0usize;
        while pos < committed {
            // Footer? (Magic-Vergleich; Footer trägt FOOTER_MAGIC, Record RECORD_MAGIC.)
            if bytes[pos..].len() >= 4 && bytes[pos..pos + 4] == crate::format::FOOTER_MAGIC {
                match BatchFooter::decode(&bytes[pos..]) {
                    Ok(_) => {
                        pos += BatchFooter::encoded_len();
                        continue;
                    }
                    // Ein Footer im committeten Bereich, der nicht dekodiert,
                    // ist beschädigte durable Daten.
                    Err(_) => return Err(KernelError::Corruption),
                }
            }
            let decoded = match decode_record(&bytes[pos..]) {
                Ok(d) => d,
                Err(_) => return Err(KernelError::Corruption),
            };
            let rec = LoggedRecord {
                seq: decoded.header.seq,
                payload: decoded.payload.to_vec(),
                offset: pos as u64,
                marker_offset: decoded.header.marker_offset,
                constituent_range: decoded.header.constituent_range,
            };
            pos += decoded.total_len;
            f(rec)?;
        }
        Ok(())
    }

    // -- intern: Hilfen -------------------------------------------------------

    /// Stellt sicher, dass das Log lebt (nicht vergiftet), bevor eine Mutation
    /// beginnt.
    fn ensure_live(&self) -> Result<(), KernelError> {
        if self.poisoned {
            Err(KernelError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Vergiftet das Log nach einem fatalen I/O-Fehler und liefert den passenden
    /// [`KernelError`]. Ein `fsync`/`pwrite`-Fehler darf **nie** als Erfolg geackt
    /// werden (§Durability).
    fn poison_from_io(&mut self, _e: std::io::Error) -> KernelError {
        self.poisoned = true;
        // Das Mapping fallenlassen — der Dateizustand ist nun unsicher.
        self.mmap = None;
        self.mmap_len = 0;
        KernelError::Io
    }
}

/// Das Resultat eines Recovery-Scans über die rohen Segment-Bytes.
struct ScanResult {
    /// Offset **nach** dem letzten gültigen Batch-Footer (= committed offset).
    committed_offset: u64,
    /// Die nächste zu vergebende seq nach allen committeten Records.
    next_seq: u64,
    /// Anzahl committeter Records (über alle gültigen Batches).
    committed_record_count: u64,
    /// Anzahl committeter (gültig abgeschlossener) Batches.
    committed_batch_count: u64,
}

/// Scannt `buf` (die rohen Segment-Bytes) und ermittelt den **committed offset**
/// (Ende des letzten gültigen Batch-Footers) gemäß §Durability-Recovery.
///
/// ## Der Footer ist die **Commit-Autorität**
///
/// Ein Batch ist durabel **genau dann**, wenn sein Footer durabel ist (WAL-Commit-
/// Record). Daraus folgt die einzige Quelle der Wahrheit für „committed":
///
/// > Ein **prüfsummen-gültiger** Batch-Footer beweist, dass der Byte-Bereich, der
/// > mit diesem Footer endet, durable **committete** Daten enthält. Sein Ende ist
/// > ein Commit-Punkt.
///
/// Die committed offset ist damit das Ende des **letzten** prüfsummen-gültigen
/// Footers — **nicht** ein strukturell aus (unverifizierten) Längen abgeleiteter
/// Wert.
///
/// ## Zwei strikt getrennte Begriffe an jeder Frame-Grenze
///
/// 1. **Vorrücken über einen Frame.** Nur ein Frame mit **verifizierter**
///    Prüfsumme darf über seine im Header genannte Länge vorgerückt werden. Ein
///    prüfsummen-**defekter** Record (z. B. ein gekipptes `payload_length`-Byte!)
///    hat einen **nicht vertrauenswürdigen** Header — seine Länge darf **nicht**
///    benutzt werden (sonst überspränge der Scan den nachfolgenden Footer und
///    verlöre ihn). Stattdessen wird **byteweise** zum nächsten Frame-Magic
///    (`LKR1`/`LKF1`) weitergesucht ([`next_frame_magic`]), um spätere gültige
///    Footer trotzdem zu finden.
/// 2. **Integritäts-Validierung** — Prüfsumme, lückenlose seq-Kette und (bei
///    skip-freien Batches) passende Footer-Felder. Der **erste** Verstoß wird an
///    seiner Position vermerkt (`first_defect`).
///
/// ## Politik (§Durability)
///
/// - committed offset = Ende des **letzten** prüfsummen-gültigen Footers;
/// - liegt der **erste** Defekt **strikt vor** dem committed offset ⇒ beschädigte
///   **durable** Daten ⇒ [`KernelError::Corruption`] (HALT, **kein** Truncate) —
///   einschließlich des Falls, dass der gekippte Record der **allererste** vor
///   einem ansonsten gültigen Footer ist;
/// - liegt er **am/nach** dem committed offset (oder gibt es keinen Commit) ⇒ nur
///   un-ackter Tail; der committed offset bleibt am letzten gültigen Footer (der
///   Tail wird später trunkiert).
fn scan_segment(buf: &[u8]) -> Result<ScanResult, KernelError> {
    let mut pos: usize = 0;

    // Letzter bestätigter Commit-Punkt (= Ende des letzten gültigen Footers).
    let mut committed_offset: u64 = 0;
    let mut committed_next_seq: u64 = 0;
    let mut committed_record_count: u64 = 0;
    let mut committed_batch_count: u64 = 0;

    // Position des ERSTEN beobachteten Integritäts-Defekts (None = bisher sauber).
    let mut first_defect: Option<u64> = None;

    // Laufender STRUKTURELLER Zustand des aktuellen (noch nicht committeten)
    // Batches. Nur über prüfsummen-GÜLTIGE Records gezählt.
    let mut next_seq: u64 = 0; // nächste erwartete seq über alle gültigen Records.
    let mut batch_first_seq: u64 = 0;
    let mut batch_count: u64 = 0;
    let mut batch_open = false;
    // Wurde in diesem Batch ein prüfsummen-defekter Record byteweise übersprungen?
    // Dann sind die strukturell gezählten Felder unvollständig und der Footer-Feld-
    // Abgleich wird unterdrückt (der Footer bleibt dennoch Commit-Autorität).
    let mut batch_had_skip = false;

    /// Vermerkt den ersten Defekt an `at`, falls noch keiner bekannt ist.
    fn note_defect(first_defect: &mut Option<u64>, at: u64) {
        if first_defect.is_none() {
            *first_defect = Some(at);
        }
    }

    while pos < buf.len() {
        let rest = &buf[pos..];
        let frame_pos = pos as u64;

        // Weniger als ein Magic übrig: struktureller Tail-Rest, nicht weiter
        // parsebar. Defekt vermerken und Scan beenden.
        if rest.len() < 4 {
            note_defect(&mut first_defect, frame_pos);
            break;
        }

        if rest[..4] == FOOTER_MAGIC_BYTES {
            // --- Footer-Frame -------------------------------------------------
            match BatchFooter::decode(rest) {
                Ok(f) => {
                    // Prüfsummen-gültiger Footer ⇒ COMMIT-AUTORITÄT: der Bereich,
                    // der hier endet, ist durable committet.
                    //
                    // Zusatz-Integrität: war der Batch skip-frei (alle Records
                    // prüfsummen-gültig + strukturell gezählt), müssen die Footer-
                    // Felder zur gezählten Spanne passen; sonst ist es ein Defekt
                    // (z. B. ein still passender, aber inhaltlich falscher Footer).
                    if !batch_had_skip {
                        let fields_ok = if batch_open {
                            batch_count >= 1
                                && f.record_count == batch_count
                                && f.first_seq == batch_first_seq
                                && f.last_seq == next_seq - 1
                        } else {
                            // Leerer Batch (kommt im Schreibpfad nie vor): nur ein
                            // 0-Record-Footer wäre feld-konsistent.
                            f.record_count == 0
                        };
                        if !fields_ok {
                            note_defect(&mut first_defect, frame_pos);
                        }
                    }
                    pos += BatchFooter::encoded_len();
                    committed_offset = pos as u64;
                    committed_next_seq = next_seq;
                    committed_record_count += batch_count;
                    committed_batch_count += 1;
                    // Batch-Akkumulator nach der Commit-Grenze zurücksetzen.
                    batch_open = false;
                    batch_count = 0;
                    batch_had_skip = false;
                }
                Err(_) => {
                    // Footer-Prüfsumme/Trunkierung: kein Commit-Punkt. Der Footer
                    // ist nicht vertrauenswürdig; byteweise zum nächsten Magic.
                    note_defect(&mut first_defect, frame_pos);
                    match next_frame_magic(buf, pos + 1) {
                        Some(next) => pos = next,
                        None => break,
                    }
                }
            }
            continue;
        }

        if rest[..4] != RECORD_MAGIC_BYTES {
            // Weder Footer- noch Record-Magic: byteweise zum nächsten Frame-Magic
            // weitersuchen (es könnte ein späterer gültiger Footer folgen).
            note_defect(&mut first_defect, frame_pos);
            match next_frame_magic(buf, pos + 1) {
                Some(next) => pos = next,
                None => break,
            }
            continue;
        }

        // --- Record-Frame -----------------------------------------------------
        // Strikt dekodieren: NUR ein prüfsummen-gültiger Record darf über seine im
        // Header genannte Länge vorgerückt werden. Ein defekter Header (inkl. eines
        // gekippten `payload_length`) ist NICHT vertrauenswürdig.
        match decode_record(rest) {
            Ok(decoded) => {
                // Batch strukturell öffnen (erste seq merken).
                if !batch_open {
                    batch_open = true;
                    batch_first_seq = decoded.header.seq;
                    batch_count = 0;
                }
                if decoded.header.seq != next_seq {
                    // seq-Lücke: Integritäts-Defekt. Der Footer bleibt Autorität;
                    // die seq-Erwartung ziehen wir auf den gelesenen Stand nach.
                    note_defect(&mut first_defect, frame_pos);
                    next_seq = decoded.header.seq;
                }
                batch_count += 1;
                next_seq += 1;
                pos += decoded.total_len;
            }
            Err(_) => {
                // Prüfsummen-/Längen-/Versions-Defekt: Header UNVERTRAUENSWÜRDIG.
                // NICHT über `payload_length` vorrücken (das könnte den folgenden
                // Footer verschlucken und committete Daten verlieren). Stattdessen
                // byteweise zum nächsten Frame-Magic.
                note_defect(&mut first_defect, frame_pos);
                batch_had_skip = true;
                match next_frame_magic(buf, pos + 1) {
                    Some(next) => pos = next,
                    None => break,
                }
            }
        }
    }

    // HALT, wenn der erste Defekt STRIKT VOR dem committed offset liegt:
    // beschädigte durable Daten (§Durability — nie Auto-Truncate).
    if let Some(d) = first_defect {
        if d < committed_offset {
            return Err(KernelError::Corruption);
        }
    }

    Ok(ScanResult {
        committed_offset,
        next_seq: committed_next_seq,
        committed_record_count,
        committed_batch_count,
    })
}

/// Sucht ab `from` **byteweise** das nächste Frame-Magic (`LKR1` Record oder
/// `LKF1` Footer) in `buf` und gibt seinen absoluten Offset zurück; `None`, wenn
/// keines mehr folgt.
///
/// Dies ist der **sichere** Weg, über einen prüfsummen-defekten Frame
/// hinwegzukommen, **ohne** dessen unvertrauenswürdige Header-Länge zu benutzen.
/// Ein zufälliges Magic *innerhalb* einer Nutzlast führt höchstens zu einem
/// weiteren (prüfsummen-)Defekt-Treffer und erneuter Suche — die Commit-Autorität
/// liegt allein beim prüfsummen-gültigen Footer, sodass ein solcher Fehlalarm das
/// committed offset nie fälschlich vorrückt.
fn next_frame_magic(buf: &[u8], from: usize) -> Option<usize> {
    if from >= buf.len() {
        return None;
    }
    // Ein Magic braucht 4 Bytes; der letzte mögliche Startindex ist len-4.
    let last_start = buf.len().checked_sub(4)?;
    let mut i = from;
    while i <= last_start {
        let w = &buf[i..i + 4];
        if w == RECORD_MAGIC_BYTES || w == FOOTER_MAGIC_BYTES {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Die On-Disk-Gesamtlänge eines gerahmten Records mit Nutzlast-Länge
/// `payload_len` (`Header ‖ Payload ‖ Prüfsumme` = `64 + payload_len + 32`), als
/// `u64`. Wird beim Staging gebraucht, um den Marker-Offset **deterministisch**
/// vorauszuberechnen (§13). Überlauf ⇒ [`KernelError::Inconsistent`].
fn record_frame_len(payload_len: usize) -> Result<u64, KernelError> {
    let total = RECORD_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(CHECKSUM_LEN))
        .ok_or(KernelError::Inconsistent)?;
    u64::try_from(total).map_err(|_| KernelError::Inconsistent)
}

// Magic-Bytes als `[u8;4]` für die schnellen Slice-Vergleiche im Scan.
const RECORD_MAGIC_BYTES: [u8; 4] = RECORD_MAGIC;
const FOOTER_MAGIC_BYTES: [u8; 4] = crate::format::FOOTER_MAGIC;

// Den ungenutzten Header-Längen-Import dokumentieren (Frame-Mindestgröße).
const _: () = {
    // Ein Record-Frame ist mindestens HEADER + CHECKSUM groß; diese Konstante
    // hält den Import sichtbar und dokumentiert die Mindestgröße.
    assert!(RECORD_HEADER_LEN >= 64);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{checksum, CHECKSUM_LEN};
    use std::io::Write;
    use tempfile::tempdir;

    fn payloads(recs: &[LoggedRecord]) -> Vec<Vec<u8>> {
        recs.iter().map(|r| r.payload.clone()).collect()
    }

    // ------------------------------------------------------------------------
    // Roundtrip: append + commit + reopen.
    // ------------------------------------------------------------------------

    #[test]
    fn append_commit_reopen_roundtrip() {
        let dir = tempdir().expect("tempdir");
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"alpha").expect("a");
            log.append_and_commit(b"beta").expect("b");
            // Ein Multi-Record-Batch.
            log.append_record(b"gamma").expect("g");
            log.append_record(b"delta").expect("d");
            log.commit().expect("commit batch");
            let recs = log.read_all().expect("read");
            assert_eq!(
                payloads(&recs),
                vec![
                    b"alpha".to_vec(),
                    b"beta".to_vec(),
                    b"gamma".to_vec(),
                    b"delta".to_vec()
                ]
            );
        }
        // Reopen: dieselben Records, in derselben Reihenfolge, durabel.
        let log = SegmentLog::open(dir.path()).expect("reopen");
        let recs = log.read_all().expect("read after reopen");
        assert_eq!(
            payloads(&recs),
            vec![
                b"alpha".to_vec(),
                b"beta".to_vec(),
                b"gamma".to_vec(),
                b"delta".to_vec()
            ]
        );
        // seq ist 0..=3, lückenlos.
        let seqs: Vec<u64> = recs.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3]);
        // next_seq zeigt hinter den letzten Record.
        assert_eq!(log.next_seq(), 4);
    }

    #[test]
    fn empty_log_reads_nothing() {
        let dir = tempdir().expect("tempdir");
        let log = SegmentLog::open(dir.path()).expect("open");
        assert!(log.read_all().expect("read").is_empty());
        assert_eq!(log.committed_offset(), 0);
        assert_eq!(log.next_seq(), 0);
    }

    // ------------------------------------------------------------------------
    // Durability-on-Ack: ein un-committeter Record ist nicht sichtbar; erst der
    // Commit (fsync) ackt ihn. Der committed offset bewegt sich erst beim Commit.
    // ------------------------------------------------------------------------

    #[test]
    fn uncommitted_append_is_invisible_until_commit() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_record(b"pending").expect("append");
        // Vor dem Commit: nichts sichtbar, committed offset = 0.
        assert_eq!(log.committed_offset(), 0);
        assert!(log.read_all().expect("read").is_empty());
        // Nach dem Commit: sichtbar, committed offset > 0.
        log.commit().expect("commit");
        assert!(log.committed_offset() > 0);
        assert_eq!(payloads(&log.read_all().unwrap()), vec![b"pending".to_vec()]);
    }

    #[test]
    fn uncommitted_tail_is_dropped_on_reopen() {
        // Durability-on-Ack: ein appendeter, aber NICHT committeter Record darf
        // nach einem Crash (= Reopen ohne Commit) NICHT erscheinen.
        let dir = tempdir().expect("tempdir");
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"durable").expect("durable");
            // Dieser Record wird gepuffert, aber nie committet → un-ackt.
            log.append_record(b"lost").expect("append");
            // `log` wird gedroppt ohne commit; der Pending-Puffer war nie auf Platte.
        }
        let log = SegmentLog::open(dir.path()).expect("reopen");
        // Nur der durable Record ist da.
        assert_eq!(payloads(&log.read_all().unwrap()), vec![b"durable".to_vec()]);
    }

    // ------------------------------------------------------------------------
    // seq-Monotonie über Batches hinweg.
    // ------------------------------------------------------------------------

    #[test]
    fn seq_is_monotonic_across_batches() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        for i in 0..5u8 {
            log.append_and_commit(&[i]).expect("commit");
        }
        let recs = log.read_all().expect("read");
        let seqs: Vec<u64> = recs.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }

    // ------------------------------------------------------------------------
    // mmap-Lesen überschreitet nie den committed offset.
    // ------------------------------------------------------------------------

    #[test]
    fn mmap_reads_never_exceed_committed_offset() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_and_commit(b"committed").expect("c");
        let committed = log.committed_offset();
        // Einen weiteren Record puffern (nicht committen): er liegt im Pending-
        // Puffer, ist NICHT auf Platte und damit nie im Mapping.
        log.append_record(b"beyond-the-watermark").expect("append");
        // Das Mapping reicht exakt bis committed; ein read_at am committed offset
        // (= jenseits des sichtbaren Bereichs) wird abgelehnt.
        assert_eq!(log.committed_offset(), committed);
        assert!(matches!(
            log.read_at(committed),
            Err(KernelError::Inconsistent)
        ));
        // Der mmap-len-Beweis: das interne Mapping ist genau committed lang.
        assert_eq!(log.mmap_len, committed);
        // read_at(0) liefert den committeten Record (Prüfsumme verifiziert).
        let r0 = log.read_at(0).expect("read first");
        assert_eq!(r0.payload, b"committed");
        assert_eq!(r0.seq, 0);
    }

    // ------------------------------------------------------------------------
    // Recovery trunkiert einen torn Tail (mitten im Footer abgeschnitten).
    // ------------------------------------------------------------------------

    #[test]
    fn recovery_truncates_tail_torn_mid_footer() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"keep-1").expect("k1");
            log.append_and_commit(b"keep-2").expect("k2");
        }
        // Einen un-ackten Tail anhängen: Record-Bytes + ein HALBER Footer (torn
        // mid-footer). Wir simulieren genau das, was ein Crash mitten im Group-
        // Commit-Write hinterlässt.
        let committed_before = SegmentLog::open(dir.path()).unwrap().committed_offset();
        {
            let mut f = OpenOptions::new().append(true).open(&seg).expect("append-open");
            let rec = crate::format::encode_record_to_vec(99, b"torn-record");
            f.write_all(&rec).expect("write rec");
            // Halber Footer.
            let footer = BatchFooter::new(1, 99, 99).encode_to_vec();
            f.write_all(&footer[..footer.len() / 2]).expect("write half footer");
            f.sync_all().expect("sync");
        }
        // Reopen: der torn Tail wird verworfen, nur die committeten Records bleiben.
        let log = SegmentLog::open(dir.path()).expect("reopen");
        assert_eq!(log.committed_offset(), committed_before);
        assert_eq!(
            payloads(&log.read_all().unwrap()),
            vec![b"keep-1".to_vec(), b"keep-2".to_vec()]
        );
        // Die Datei wurde physisch auf den committed offset trunkiert.
        let file_len = std::fs::metadata(&seg).unwrap().len();
        assert_eq!(file_len, committed_before);
    }

    #[test]
    fn recovery_truncates_tail_torn_mid_record() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"survivor").expect("s");
        }
        let committed_before = SegmentLog::open(dir.path()).unwrap().committed_offset();
        {
            // Ein Record-Frame, aber mitten in der Nutzlast abgeschnitten.
            let rec = crate::format::encode_record_to_vec(1, b"a fairly long payload to cut");
            let cut = RECORD_HEADER_LEN + 4; // mitten in der Payload.
            let mut f = OpenOptions::new().append(true).open(&seg).expect("append-open");
            f.write_all(&rec[..cut]).expect("write torn record");
            f.sync_all().expect("sync");
        }
        let log = SegmentLog::open(dir.path()).expect("reopen");
        assert_eq!(log.committed_offset(), committed_before);
        assert_eq!(payloads(&log.read_all().unwrap()), vec![b"survivor".to_vec()]);
        assert_eq!(std::fs::metadata(&seg).unwrap().len(), committed_before);
    }

    #[test]
    fn recovery_drops_uncommitted_record_without_footer() {
        // Ein vollständiger Record OHNE Footer (Crash vor dem Footer-Write) ist
        // un-ackt und muss verschwinden.
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"acked").expect("a");
        }
        let committed_before = SegmentLog::open(dir.path()).unwrap().committed_offset();
        {
            let rec = crate::format::encode_record_to_vec(1, b"no-footer");
            let mut f = OpenOptions::new().append(true).open(&seg).expect("append-open");
            f.write_all(&rec).expect("write full record, no footer");
            f.sync_all().expect("sync");
        }
        let log = SegmentLog::open(dir.path()).expect("reopen");
        assert_eq!(log.committed_offset(), committed_before);
        assert_eq!(payloads(&log.read_all().unwrap()), vec![b"acked".to_vec()]);
    }

    // ------------------------------------------------------------------------
    // Recovery HÄLT bei Korruption VOR dem letzten Footer (gekipptes Byte in
    // einem committeten Record).
    // ------------------------------------------------------------------------

    #[test]
    fn recovery_halts_on_corruption_before_last_footer() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            // Zwei committete Batches: der zweite Footer ist der „letzte gültige".
            log.append_and_commit(b"first-committed").expect("c1");
            log.append_and_commit(b"second-committed").expect("c2");
        }
        // Ein Byte in der Nutzlast des ERSTEN (committeten) Records kippen — also
        // VOR dem letzten gültigen Footer. Das sind beschädigte durable Daten.
        {
            let mut data = std::fs::read(&seg).expect("read seg");
            let flip_at = RECORD_HEADER_LEN + 2; // in der Payload des ersten Records.
            data[flip_at] ^= 0b0000_0001;
            std::fs::write(&seg, &data).expect("write back");
        }
        // Reopen MUSS HALTen (Corruption), NICHT auto-truncaten.
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
        // Die Datei wurde NICHT verändert/trunkiert (durable Daten bleiben).
        let len_after = std::fs::metadata(&seg).unwrap().len();
        assert!(len_after > 0);
    }

    #[test]
    fn recovery_halts_on_corrupt_committed_footer() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        let committed_first;
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"batch-one").expect("c1");
            committed_first = log.committed_offset();
            log.append_and_commit(b"batch-two").expect("c2");
        }
        // Den ERSTEN Footer (innerhalb des committeten Präfixes, vor dem letzten
        // Footer) beschädigen: ein Byte im Footer-Rumpf kippen.
        {
            let mut data = std::fs::read(&seg).expect("read seg");
            // Der erste Footer beginnt bei `committed_first - encoded_len`.
            let footer_start = committed_first as usize - BatchFooter::encoded_len();
            data[footer_start + 8] ^= 0b0000_0001; // im record_count-Feld.
            std::fs::write(&seg, &data).expect("write back");
        }
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
    }

    // ------------------------------------------------------------------------
    // Metriken: append/fsync/batch zählen plausibel.
    // ------------------------------------------------------------------------

    #[test]
    fn metrics_count_appends_and_fsyncs() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        // Ein frisches Segment → ein Directory-fsync beim Erstellen.
        let after_open = log.metrics();
        assert_eq!(after_open.segment_count, 1);
        assert_eq!(after_open.fsync_count, 1, "directory fsync on create");

        log.append_record(b"x").unwrap();
        log.append_record(b"y").unwrap();
        log.commit().unwrap(); // 1 data fsync, 2 records, 1 batch.
        log.append_and_commit(b"z").unwrap(); // 1 data fsync, 1 record, 1 batch.

        let m = log.metrics();
        assert_eq!(m.append_count, 3);
        assert_eq!(m.batch_count, 2);
        // 1 dir-fsync + 2 data-fsyncs.
        assert_eq!(m.fsync_count, 3);
        assert_eq!(m.committed_bytes, log.committed_offset());
    }

    #[test]
    fn empty_commit_is_noop() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        let before = log.metrics();
        log.commit().expect("noop commit");
        let after = log.metrics();
        // Kein zusätzlicher Batch, kein zusätzlicher data-fsync, keine seq.
        assert_eq!(before.batch_count, after.batch_count);
        assert_eq!(before.fsync_count, after.fsync_count);
        assert_eq!(log.next_seq(), 0);
    }

    // ------------------------------------------------------------------------
    // read_at verifiziert die Prüfsumme vor Herausgabe (Defekt → Fehler).
    // ------------------------------------------------------------------------

    #[test]
    fn read_at_rejects_offset_at_or_past_committed() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_and_commit(b"only").unwrap();
        let committed = log.committed_offset();
        assert!(matches!(log.read_at(committed), Err(KernelError::Inconsistent)));
        assert!(matches!(
            log.read_at(committed + 100),
            Err(KernelError::Inconsistent)
        ));
    }

    // ------------------------------------------------------------------------
    // Sanity: das committed offset endet exakt nach einem Footer (Footer ist im
    // committeten Bereich enthalten, aber wird beim read_all übersprungen).
    // ------------------------------------------------------------------------

    #[test]
    fn committed_region_includes_footer_but_read_skips_it() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_and_commit(b"r").unwrap();
        // committed offset = header + payload(1) + checksum + footer + checksum.
        let expected = (RECORD_HEADER_LEN + 1 + CHECKSUM_LEN) as u64
            + BatchFooter::encoded_len() as u64;
        assert_eq!(log.committed_offset(), expected);
        // read_all sieht genau 1 Record (den Footer überspringt es).
        assert_eq!(log.read_all().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------------
    // Nach Reopen weiterschreiben: seq läuft lückenlos fort, alte + neue Records
    // sind nach erneutem Reopen alle durabel.
    // ------------------------------------------------------------------------

    #[test]
    fn appends_continue_with_monotonic_seq_after_reopen() {
        let dir = tempdir().expect("tempdir");
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"r0").unwrap();
            log.append_and_commit(b"r1").unwrap();
        }
        {
            let mut log = SegmentLog::open(dir.path()).expect("reopen");
            // next_seq nimmt nach Recovery den committeten Stand wieder auf.
            assert_eq!(log.next_seq(), 2);
            let s2 = log.append_and_commit(b"r2").unwrap();
            assert_eq!(s2, 2, "seq läuft lückenlos fort");
        }
        let log = SegmentLog::open(dir.path()).expect("reopen2");
        let recs = log.read_all().unwrap();
        assert_eq!(
            payloads(&recs),
            vec![b"r0".to_vec(), b"r1".to_vec(), b"r2".to_vec()]
        );
        assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    // ------------------------------------------------------------------------
    // Nach einem torn Tail (Reopen trunkiert) lassen sich neue Batches sauber
    // anhängen — der überschriebene Bereich startet am committed offset.
    // ------------------------------------------------------------------------

    #[test]
    fn can_append_again_after_tail_truncation() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"kept").unwrap();
        }
        // Un-ackten Tail anhängen (voller Record ohne Footer).
        {
            let rec = crate::format::encode_record_to_vec(1, b"unacked");
            let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(&rec).unwrap();
            f.sync_all().unwrap();
        }
        // Reopen trunkiert den Tail; danach erneut schreiben.
        let mut log = SegmentLog::open(dir.path()).expect("reopen");
        assert_eq!(log.next_seq(), 1, "seq des verworfenen Tails wird wiederverwendet");
        log.append_and_commit(b"fresh").unwrap();
        let recs = log.read_all().unwrap();
        assert_eq!(payloads(&recs), vec![b"kept".to_vec(), b"fresh".to_vec()]);
    }

    // ------------------------------------------------------------------------
    // Korruption eines NICHT-ersten Records in einem committeten Multi-Record-
    // Batch wird ebenfalls als Korruption VOR dem Footer erkannt.
    // ------------------------------------------------------------------------

    #[test]
    fn recovery_halts_on_corrupt_non_first_record_in_committed_batch() {
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            // Ein committeter Batch mit drei Records, gefolgt von einem zweiten
            // committeten Batch (damit ein „letzter gültiger Footer" dahinter liegt).
            log.append_record(b"m0").unwrap();
            log.append_record(b"m1").unwrap();
            log.append_record(b"m2").unwrap();
            log.commit().unwrap();
            log.append_and_commit(b"tail-batch").unwrap();
        }
        // Ein Byte im ZWEITEN Record (m1) der ersten Batch kippen.
        {
            let mut data = std::fs::read(&seg).unwrap();
            let r0_len = RECORD_HEADER_LEN + 2 + CHECKSUM_LEN; // "m0"
            let flip = r0_len + RECORD_HEADER_LEN + 1; // in der Payload von m1.
            data[flip] ^= 0b0000_0001;
            std::fs::write(&seg, &data).unwrap();
        }
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
    }

    // ------------------------------------------------------------------------
    // Recovery HÄLT bei gekipptem `payload_length`-FELD eines committeten Records
    // (NICHT nur gekippter Nutzlast). Das ist der Defekt, der einen unverifizierten
    // strukturellen Vorlauf den nachfolgenden Footer **verschlucken** ließe und so
    // geackte Daten still verlöre. Der Footer ist Commit-Autorität ⇒ HALT, **kein**
    // Auto-Truncate. (Findings-Szenario A/B/C.)
    // ------------------------------------------------------------------------

    /// Hilfe: kippt das `payload_length`-Feld (Header-Offset 16..24) des Record-
    /// Frames, der bei `frame_start` beginnt — ein Defekt, der die im Header
    /// genannte Frame-Länge verfälscht.
    fn flip_payload_len_field(data: &mut [u8], frame_start: usize) {
        // payload_length liegt little-endian bei Header-Offset 16..24 (format.rs).
        data[frame_start + 16] ^= 0b0000_0001;
    }

    #[test]
    fn recovery_halts_on_corrupt_payload_len_in_single_committed_batch() {
        // Szenario A: EIN committeter Batch [R0][F0]. Das `payload_length`-Feld von
        // R0 kippen. Ein naiver struktureller Vorlauf über die (jetzt falsche) Länge
        // verschluckte F0 und verlöre den committeten Batch still — verboten.
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"only-committed-record").expect("c0");
        }
        let len_before = std::fs::metadata(&seg).unwrap().len();
        {
            let mut data = std::fs::read(&seg).expect("read seg");
            flip_payload_len_field(&mut data, 0); // R0 beginnt bei Offset 0.
            std::fs::write(&seg, &data).expect("write back");
        }
        // MUSS HALTen (Corruption), NICHT auto-truncaten.
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
        // Die Datei wurde NICHT trunkiert (durable Daten bleiben unangetastet).
        assert_eq!(std::fs::metadata(&seg).unwrap().len(), len_before);
    }

    #[test]
    fn recovery_halts_on_corrupt_payload_len_in_first_of_two_committed_batches() {
        // Szenario B: ZWEI committete Batches [R0][F0][R1][F1]. Das
        // `payload_length`-Feld des ERSTEN Records kippen. Beide Batches sind
        // geackt; der Defekt liegt VOR dem letzten gültigen Footer ⇒ HALT.
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"first-committed").expect("c0");
            log.append_and_commit(b"second-committed").expect("c1");
        }
        let len_before = std::fs::metadata(&seg).unwrap().len();
        {
            let mut data = std::fs::read(&seg).expect("read seg");
            flip_payload_len_field(&mut data, 0); // R0 beginnt bei Offset 0.
            std::fs::write(&seg, &data).expect("write back");
        }
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
        assert_eq!(std::fs::metadata(&seg).unwrap().len(), len_before);
    }

    #[test]
    fn recovery_halts_on_shrunk_payload_len_in_committed_record() {
        // Szenario C: `payload_length` VERKLEINERT (nicht nur ein Bit gekippt),
        // damit der naive Vorlauf MITTEN in den committeten Record zielte. Auch das
        // muss HALTen statt still zu verlieren.
        let dir = tempdir().expect("tempdir");
        let seg = dir.path().join(SEGMENT_FILE_NAME);
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"a payload long enough to shrink")
                .expect("c0");
            log.append_and_commit(b"tail-batch").expect("c1");
        }
        let len_before = std::fs::metadata(&seg).unwrap().len();
        {
            let mut data = std::fs::read(&seg).expect("read seg");
            // payload_length von R0 auf 1 setzen (verkleinern).
            data[16..24].copy_from_slice(&1u64.to_le_bytes());
            std::fs::write(&seg, &data).expect("write back");
        }
        assert!(matches!(
            SegmentLog::open(dir.path()),
            Err(KernelError::Corruption)
        ));
        assert_eq!(std::fs::metadata(&seg).unwrap().len(), len_before);
    }

    // ------------------------------------------------------------------------
    // Operationen auf einem vergifteten Log schlagen definiert fehl.
    // ------------------------------------------------------------------------

    #[test]
    fn poisoned_log_rejects_operations() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_and_commit(b"x").unwrap();
        // Künstlich vergiften (simuliert einen vorausgegangenen fatalen Fehler).
        log.poisoned = true;
        assert!(matches!(log.append_record(b"y"), Err(KernelError::Poisoned)));
        assert!(matches!(log.commit(), Err(KernelError::Poisoned)));
        assert!(matches!(log.read_all(), Err(KernelError::Poisoned)));
        assert!(matches!(log.read_at(0), Err(KernelError::Poisoned)));
    }

    // ------------------------------------------------------------------------
    // checksum-Import-Smoke: die Framing-Prüfsumme ist deterministisch (hier nur
    // genutzt, um den Test-Import zu rechtfertigen).
    // ------------------------------------------------------------------------

    #[test]
    fn checksum_is_used_in_framing() {
        assert_eq!(checksum(b"abc"), checksum(b"abc"));
    }

    // ========================================================================
    // §13 Aktiv-Marker: Staging inaktiv → ein Marker-Commit flippt gemeinsam
    // sichtbar. Einziges Sichtbarkeits-Maß ist der Offset-Vergleich (eine
    // Linearisierungsstelle, ein Watermark; KEIN zweiter Epochenzähler).
    // ========================================================================

    /// Liest alle committeten Records und sammelt jene, die unter dem Watermark `w`
    /// **sichtbar** sind (§13-Prädikat).
    fn visible_payloads(log: &SegmentLog, w: u64) -> Vec<Vec<u8>> {
        log.read_all()
            .expect("read")
            .into_iter()
            .filter(|r| SegmentLog::record_visible(r, w))
            .map(|r| r.payload)
            .collect()
    }

    #[test]
    fn staged_constituents_invisible_until_marker_then_flip_together() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");

        // Ein gewöhnlicher, unbedingter Append vorab — der ist sofort sichtbar.
        log.append_and_commit(b"plain").expect("plain");

        // Konstituenten stagen (inaktiv): durabel committet, aber ihr Marker fehlt.
        let staged = log
            .stage_constituents(&[b"c0".as_slice(), b"c1".as_slice(), b"c2".as_slice()])
            .expect("stage");
        let w_after_stage = log.committed_offset();

        // Die Konstituenten sind PHYSISCH committet (W über sie hinaus) …
        assert!(w_after_stage > staged.constituent_offsets()[2]);
        // … aber INAKTIV: W zeigt GENAU auf den (noch nicht durablen) Marker-Anfang,
        // also ist `marker_offset < W` falsch ⇒ NICHT sichtbar (§13.2).
        assert_eq!(w_after_stage, staged.marker_offset());
        assert_eq!(
            visible_payloads(&log, w_after_stage),
            vec![b"plain".to_vec()],
            "nur der unbedingte Append ist sichtbar; die Konstituenten sind inaktiv"
        );

        // Der EINE Marker-Commit flippt alle Konstituenten gemeinsam sichtbar (§13.1).
        let marker_off = log.commit_marker(&staged, b"MARK").expect("marker");
        assert_eq!(marker_off, staged.marker_offset());
        let w_after_marker = log.committed_offset();
        assert!(w_after_marker > staged.marker_offset());

        let visible = visible_payloads(&log, w_after_marker);
        // EIN einziger atomarer Flip: alle drei Konstituenten + der Marker + der
        // unbedingte Append sind nun sichtbar.
        assert_eq!(
            visible,
            vec![
                b"plain".to_vec(),
                b"c0".to_vec(),
                b"c1".to_vec(),
                b"c2".to_vec(),
                b"MARK".to_vec()
            ]
        );
    }

    #[test]
    fn each_constituent_references_the_marker_offset() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        let staged = log
            .stage_constituents(&[b"a".as_slice(), b"b".as_slice()])
            .expect("stage");
        // Jeder Konstituent trägt im Header den Offset SEINES Markers.
        for &off in staged.constituent_offsets() {
            let rec = log.read_at(off).expect("read constituent");
            assert_eq!(rec.marker_offset, staged.marker_offset());
            assert_eq!(rec.constituent_range, 0, "Konstituent trägt keinen Bereich");
        }
        log.commit_marker(&staged, b"M").expect("marker");
        // Der Marker selbst ist unbedingt und trägt den Bereich-Anfang (Audit).
        let marker = log.read_at(staged.marker_offset()).expect("read marker");
        assert_eq!(marker.marker_offset, 0, "Marker ist unbedingt");
        assert_eq!(marker.constituent_range, staged.first_constituent_offset());
    }

    #[test]
    fn unconditional_append_is_visible_as_before() {
        // Ein gewöhnlicher Append (marker_offset == 0) ist sichtbar, sobald er
        // durabel ist — genau wie vor §13.
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_and_commit(b"x").expect("x");
        let w = log.committed_offset();
        let recs = log.read_all().expect("read");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].marker_offset, 0);
        assert!(SegmentLog::record_visible(&recs[0], w));
        assert_eq!(visible_payloads(&log, w), vec![b"x".to_vec()]);
    }

    #[test]
    fn watermark_advances_only_post_fsync_for_restructuring() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        let w0 = log.committed_offset();
        let fsync0 = log.metrics().fsync_count;

        let staged = log
            .stage_constituents(&[b"c0".as_slice(), b"c1".as_slice()])
            .expect("stage");
        // Nach dem Konstituenten-fsync: W ist über die Konstituenten, aber NICHT
        // über den Marker (der ist noch nicht geschrieben).
        let w1 = log.committed_offset();
        assert!(w1 > w0);
        assert_eq!(w1, staged.marker_offset(), "W = Beginn des (noch fehlenden) Markers");
        assert!(log.metrics().fsync_count > fsync0, "Konstituenten-Batch ge-fsync't");
        let fsync1 = log.metrics().fsync_count;

        log.commit_marker(&staged, b"M").expect("marker");
        let w2 = log.committed_offset();
        // Erst der Marker-fsync rückt W über den Marker (post-fsync-Veröffentlichung).
        assert!(w2 > w1);
        assert!(log.metrics().fsync_count > fsync1);
    }

    #[test]
    fn crashed_restructuring_stays_invisible_forever_after_reopen() {
        // Konstituenten geschrieben, Marker NICHT committet (Crash mid-Umbau):
        // nach dem Reopen rückt Recovery W auf den letzten voll-durablen Record
        // (= Ende des Konstituenten-Batches). Die Konstituenten referenzieren einen
        // Marker-Offset > W ⇒ FÜR IMMER inaktiv.
        let dir = tempdir().expect("tempdir");
        let constituent_offsets;
        let marker_offset;
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            log.append_and_commit(b"durable-plain").expect("plain");
            let staged = log
                .stage_constituents(&[b"c0".as_slice(), b"c1".as_slice()])
                .expect("stage");
            constituent_offsets = staged.constituent_offsets().to_vec();
            marker_offset = staged.marker_offset();
            // KEIN commit_marker: `log` wird gedroppt (simuliert Crash mid-Umbau).
        }

        let log = SegmentLog::open(dir.path()).expect("reopen");
        let w = log.committed_offset();
        // Die Konstituenten sind durabel (committet vor dem Crash) …
        assert!(w > constituent_offsets[1]);
        // … aber der Marker wurde nie durabel: W zeigt höchstens AUF den Marker-Anfang
        // (Ende des Konstituenten-Batches), nie darüber hinaus ⇒ `marker_offset < W`
        // bleibt für immer falsch.
        assert_eq!(w, marker_offset, "W am nie-durablen Marker-Anfang, nie darüber");

        // Folglich sind die Konstituenten für IMMER inaktiv; nur der unbedingte
        // Append ist sichtbar (§13.3: ein halb-vollzogener Umbau bleibt unsichtbar).
        assert_eq!(visible_payloads(&log, w), vec![b"durable-plain".to_vec()]);
        // Auch direkt am Prädikat: jeder Konstituent ist unsichtbar.
        for &off in &constituent_offsets {
            let rec = log.read_at(off).expect("read constituent");
            assert!(!SegmentLog::record_visible(&rec, w), "Konstituent inaktiv");
        }
    }

    #[test]
    fn restructuring_survives_reopen_when_marker_committed() {
        // Vollständiger Umbau (append_restructuring): nach Reopen sind die
        // Konstituenten + Marker sichtbar (W über den Marker hinaus, durabel).
        let dir = tempdir().expect("tempdir");
        let marker_offset;
        {
            let mut log = SegmentLog::open(dir.path()).expect("open");
            let staged = log
                .append_restructuring(&[b"m0".as_slice(), b"m1".as_slice()], b"DONE")
                .expect("restructuring");
            marker_offset = staged.marker_offset();
        }
        let log = SegmentLog::open(dir.path()).expect("reopen");
        let w = log.committed_offset();
        assert!(w > marker_offset, "Marker durabel über den Reopen hinaus");
        assert_eq!(
            visible_payloads(&log, w),
            vec![b"m0".to_vec(), b"m1".to_vec(), b"DONE".to_vec()]
        );
    }

    #[test]
    fn empty_constituent_set_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        assert!(matches!(
            log.stage_constituents(&[]),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn commit_marker_rejects_intervening_append() {
        // Ein fremder Append zwischen Staging und Marker-Commit verschiebt den
        // Marker-Offset ⇒ commit_marker MUSS ablehnen (kein stiller Drift).
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        let staged = log
            .stage_constituents(&[b"c0".as_slice()])
            .expect("stage");
        // Dazwischengeschobener Append (z. B. ein paralleler Schreibvorgang).
        log.append_and_commit(b"intruder").expect("intruder");
        assert!(matches!(
            log.commit_marker(&staged, b"M"),
            Err(KernelError::Inconsistent)
        ));
    }

    #[test]
    fn staging_flushes_open_pending_batch_first() {
        // Ein offener Pending-Append wird vor dem Staging committet (saubere Grenze).
        let dir = tempdir().expect("tempdir");
        let mut log = SegmentLog::open(dir.path()).expect("open");
        log.append_record(b"pending-plain").expect("append");
        // committed offset ist noch 0 (Pending nicht committet).
        assert_eq!(log.committed_offset(), 0);
        let staged = log
            .stage_constituents(&[b"c0".as_slice()])
            .expect("stage");
        // Der Pending-Append wurde committet → der erste Konstituent beginnt NACH ihm.
        assert!(staged.first_constituent_offset() > 0);
        log.commit_marker(&staged, b"M").expect("marker");
        let w = log.committed_offset();
        assert_eq!(
            visible_payloads(&log, w),
            vec![b"pending-plain".to_vec(), b"c0".to_vec(), b"M".to_vec()]
        );
    }
}
