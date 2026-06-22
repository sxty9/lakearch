//! **Compaction & physische Erasure** (§15/§9.5, Plan „Compaction/DSGVO") — das
//! *physische* Entfernen Überholter/Verborgener/Eraster aus dem append-only Log
//! (§7.1), als **neue, unveränderliche Generation**, die die alte per **Generation-
//! Epoche** (§13-Analogon) ersetzt — **ohne** je ein Segment zu unmappen, das ein
//! Leser gerade hält.
//!
//! Maßgeblich: der gehärtete Plan (Abschnitt „Storage-Engine, Compaction/DSGVO,
//! Scale-out") und das Gesetzbuch `semantics/lakearch.md` (§15 Compaction; §9.5
//! Kuratierung; §6.3 Ersetzung; §3.6 referenzielle Geschlossenheit; §13 Aktiv-
//! Marker; §12.3 Föderation).
//!
//! ## Die fünf Bausteine (Plan „Compaction/DSGVO")
//!
//! 1. **Stabile logische ID, nie roher Byte-Offset.** Eine compactierte Generation
//!    referenziert jedes Daten über seine [`ContentId`] **plus** die
//!    `(Segment-Generation)` — **nie** einen rohen Byte-Offset des Vor-Generation-
//!    Logs. Ein Segment-Rewrite verschiebt damit **keine** logische Referenz und
//!    bricht **keinen** in-flight MVCC-Snapshot (der Snapshot hält seine
//!    Generation; die neue ist eine andere Epoche).
//! 2. **Compaction rewritet ein Segment** in eine **neue, unveränderliche**
//!    [`CompactedSegment`] (nächste Generation), die Überholte (§6.3) / kuratorisch
//!    Verborgene (§9.5) / Eraste physisch **weglässt**, und schaltet sie **atomar**
//!    über den `CURRENT`-Generation-Marker (§13-Epoche) live — die alte Generation
//!    bleibt auf Platte, bis kein Leser sie mehr hält (drop-after-quiesce).
//! 3. **Refcount/Reachability** ([`Refcounts`]): ein per Dedup (§5.3) **mehrfach**
//!    referenziertes Daten wird **nicht** physisch fallengelassen, solange **eine**
//!    rechtmäßig gehaltene Referenz es behält — die Löschung einer Referenz zerstört
//!    **nicht** die Daten einer anderen.
//! 4. **Crypto-Shredding** ([`crate::crypto`]): erasbare Nutzlasten werden in der
//!    compactierten Generation mit einem **pro-Lösch-Schlüssel** versiegelt; das
//!    Zerstören des Schlüssels ([`Keystore::destroy`]) macht die Bytes unrückholbar,
//!    während die [`ContentId`] und alle Kanten **intakt** bleiben (§3.6).
//! 5. **Erasure ist gegatet + auditiert + nicht-transitiv** — siehe
//!    [`crate::kernel::LakearchKernel::erase`]: sie verlangt das **Erasure-Recht**
//!    ([`Datum::is_erasure_right`]), **hängt ihr eigenes Audit-Daten an**
//!    ([`Datum::erasure_audit`]) und wirkt **nur lokal** (§12.3).
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: die compactierte Generation wird per
//! `pwrite`/`pread` (sichere `std::fs`-API) geschrieben/gelesen; das einzige
//! `unsafe` (mmap) bleibt dem [`crate::log`]-Leaf vorbehalten.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{self, ErasureKey};
use crate::error::KernelError;
use crate::id::ContentId;
use crate::model::Datum;
use crate::serialize::strict_decode;

/// Generation einer compactierten Segment-Reihe (§15, Plan: „stabile logische ID =
/// ContentId / segment-id+generation"). Monoton steigend; jede Compaction erzeugt
/// die nächste. Ein in-flight MVCC-Snapshot hält **seine** Generation — eine neue
/// Compaction ist eine **andere** Epoche und bricht ihn nicht.
pub type Generation = u64;

/// Magic der compactierten Segment-Datei (`LKC1` = lakearch compacted v1) — bewusst
/// verschieden vom Append-Log-Record-Magic (`LKR1`)/Footer (`LKF1`), damit kein
/// Format verwechselt wird.
const COMPACTED_MAGIC: &[u8; 4] = b"LKC1";

/// Datei-Name der compactierten Segment-Datei in einem Generations-Verzeichnis.
const COMPACTED_SEGMENT_FILE: &str = "segment.lkc";

/// Datei-Name des Keystores (die crypto-shred-Schlüssel) in einem Generations-
/// Verzeichnis. **Kein** Log-Bestandteil (§8.4): der Keystore ist das **zerstörbare**
/// Geheimnis — er wird **nie** repliziert wie der unveränderliche Log-Inhalt.
const KEYSTORE_FILE: &str = "keystore.lkk";

/// Wie ein Record in der compactierten Generation abgelegt ist (§Crypto-Shredding).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecordKind {
    /// **Klartext** — die kanonischen CBOR-Bytes (§K4) liegen unverschlüsselt vor
    /// (der Normalfall: ein retained, nicht-erastes Daten).
    Plain = 0,
    /// **Versiegelt** (§Crypto-Shred) — die Nutzlast ist eine AEAD-Chiffre unter
    /// einem pro-Lösch-Schlüssel; nur mit dem **lebenden** Schlüssel entsiegelbar.
    /// Ist der Schlüssel zerstört, bleibt ein **Tombstone** (Adresse + Kanten, §3.6).
    Sealed = 1,
}

impl RecordKind {
    fn from_u8(b: u8) -> Result<Self, KernelError> {
        match b {
            0 => Ok(RecordKind::Plain),
            1 => Ok(RecordKind::Sealed),
            _ => Err(KernelError::Inconsistent),
        }
    }
}

/// Ein Eintrag der compactierten Generation: die **stabile logische ID**
/// ([`ContentId`], nie ein roher Offset), die Ablage-Art und die Bytes
/// (Klartext **oder** Chiffre).
#[derive(Clone, PartialEq, Eq, Debug)]
struct CompactedEntry {
    /// Die **stabile logische ID** (§15) — das Daten wird **hierüber** referenziert,
    /// nie über einen Byte-Offset des Vor-Generation-Logs.
    id: ContentId,
    /// Ob die Bytes Klartext oder eine crypto-shred-Chiffre sind.
    kind: RecordKind,
    /// Klartext-CBOR (Plain) **oder** AEAD-Chiffre (Sealed).
    bytes: Vec<u8>,
}

/// Ergebnis einer Compaction (§15) — reine **Mechanik-Zähler** (§1.4),
/// sichtbarkeits-blind (§11.3): keine sichtbaren Daten/IDs/Bereiche.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CompactionReport {
    /// Generation der **neu** geschriebenen compactierten Segment-Reihe.
    pub generation: Generation,
    /// Anzahl **behaltener** (retained) Records in der neuen Generation.
    pub retained: u64,
    /// Anzahl physisch **fallengelassener** Records (überholt §6.3 / verborgen §9.5 /
    /// erast §15) gegenüber der Eingabe.
    pub dropped: u64,
    /// Anzahl **versiegelter** (crypto-geschredderter) Records in der neuen
    /// Generation (eraste Daten, deren Klartext nun nicht mehr im Segment liegt).
    pub sealed: u64,
}

/// Persistenter **Keystore** der crypto-shred-Schlüssel (§Crypto-Shredding) — eine
/// `ContentId → ErasureKey`-Karte je Generation. Das **Zerstören** eines Schlüssels
/// ([`Keystore::destroy`]) ist die O(1)-Löschung: ab dann ist die zugehörige Chiffre
/// unentsiegelbar (die Bytes sind weg), die `ContentId`/Kanten bleiben (§3.6).
///
/// **Nicht Teil des Logs (§8.4):** der Keystore ist das **zerstörbare Geheimnis**;
/// er wird **nie** wie der unveränderliche Log-Inhalt repliziert/gesichert. Backup-
/// Politik (ob Schlüssel überhaupt gesichert werden) liegt im Daemon/der Schicht
/// darüber.
#[derive(Default)]
pub struct Keystore {
    keys: HashMap<ContentId, ErasureKey>,
}

impl Keystore {
    /// Ein leerer Keystore.
    pub fn new() -> Self {
        Keystore { keys: HashMap::new() }
    }

    /// Hinterlegt den Lösch-Schlüssel für das erasbare Daten `id` (idempotent: ein
    /// erneutes Hinterlegen mit demselben Schlüssel ändert nichts). Reine
    /// Schlüssel-Verwaltung; der Kernel **erzeugt** den Schlüssel nicht (die Schicht
    /// darüber kennt die Schlüssel-Politik, §1.4/§8.4).
    pub fn put(&mut self, id: ContentId, key: ErasureKey) {
        self.keys.insert(id, key);
    }

    /// Der Lösch-Schlüssel für `id`, falls (noch) vorhanden; `None`, wenn er
    /// **zerstört** wurde (die Bytes sind dann unrückholbar).
    pub fn get(&self, id: ContentId) -> Option<&ErasureKey> {
        self.keys.get(&id)
    }

    /// **Zerstört** den Lösch-Schlüssel von `id` (§Crypto-Shredding) — die O(1)-
    /// Löschung des „Rechts auf Vergessen". Ab jetzt ist die zugehörige Chiffre
    /// **unentsiegelbar**; die `ContentId` bleibt als Tombstone (Adresse + Kanten,
    /// §3.6). Liefert `true`, wenn ein Schlüssel entfernt wurde.
    pub fn destroy(&mut self, id: ContentId) -> bool {
        self.keys.remove(&id).is_some()
    }

    /// `true`, wenn für `id` ein **lebender** Schlüssel vorliegt.
    pub fn has_key(&self, id: ContentId) -> bool {
        self.keys.contains_key(&id)
    }

    /// Persistiert den Keystore in `path` (eigene Datei je Generation; **kein**
    /// Log-Bestandteil, §8.4). Format: `count(u64-le)` gefolgt von `count` Einträgen
    /// `id(32) || key(32)`. Reines Datei-I/O (sichere `std::fs`-API).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), KernelError> {
        let mut buf = Vec::with_capacity(8 + self.keys.len() * 64);
        buf.extend_from_slice(&(self.keys.len() as u64).to_le_bytes());
        // Deterministische Ordnung (aufsteigende ContentId, §5.2/§1.4) — reproduzierbar.
        let mut ids: Vec<ContentId> = self.keys.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(self.keys[&id].as_bytes());
        }
        atomic_write(path.as_ref(), &buf)
    }

    /// Lädt einen Keystore aus `path`; eine fehlende Datei ⇒ leerer Keystore (eine
    /// frische Generation ohne Erasures).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KernelError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Keystore::new());
        }
        let mut f = File::open(path).map_err(|_| KernelError::Io)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|_| KernelError::Io)?;
        if buf.len() < 8 {
            return Err(KernelError::Inconsistent);
        }
        let count = u64::from_le_bytes(buf[..8].try_into().map_err(|_| KernelError::Inconsistent)?);
        let mut pos = 8usize;
        let mut keys = HashMap::new();
        for _ in 0..count {
            if pos + 64 > buf.len() {
                return Err(KernelError::Inconsistent);
            }
            let id = ContentId::from_bytes(
                buf[pos..pos + 32].try_into().map_err(|_| KernelError::Inconsistent)?,
            );
            let mut kb = [0u8; 32];
            kb.copy_from_slice(&buf[pos + 32..pos + 64]);
            keys.insert(id, ErasureKey::from_bytes(kb));
            pos += 64;
        }
        Ok(Keystore { keys })
    }
}

/// **Refcounts / Reachability** (§5.3-Dedup-Sicherheit, Plan „Refcount für Dedup-
/// Sicherheit"): wie oft ein Daten `K` als **besessener Kontext** anderer (retained)
/// Daten referenziert wird. Ein Daten mit Refcount > 0 (oder eine explizite Wurzel)
/// ist **erreichbar** und darf **nicht** physisch fallengelassen werden — selbst wenn
/// eine einzelne Referenz erast/verborgen wird, hält eine **andere** Referenz es
/// rechtmäßig (die Löschung einer Referenz zerstört nicht die Daten einer anderen).
#[derive(Default)]
pub struct Refcounts {
    counts: HashMap<ContentId, u64>,
}

impl Refcounts {
    fn new() -> Self {
        Refcounts { counts: HashMap::new() }
    }

    fn incr(&mut self, id: ContentId) {
        *self.counts.entry(id).or_insert(0) += 1;
    }

    /// Wie oft `id` von (retained) Besitzern referenziert wird.
    pub fn count(&self, id: ContentId) -> u64 {
        self.counts.get(&id).copied().unwrap_or(0)
    }
}

/// Welche Daten eine Compaction **physisch fallenlässt** und welche sie **erast**
/// (crypto-shreddet) — die Politik-Eingabe (§15). Reine Mengen (§1.3); der Kernel
/// **wertet nicht** (§1.4): die Schicht darüber/der Daemon bestimmt die Mengen aus
/// den expliziten Ersetzungs-/Verbergen-/Erasure-Kontexten.
#[derive(Default, Clone)]
pub struct CompactionPlan {
    /// **Eraste** Daten (§15): ihre Nutzlast wird in der neuen Generation
    /// crypto-versiegelt (statt Klartext). `ContentId → Lösch-Schlüssel`. Die
    /// `ContentId`/Kanten bleiben intakt (§3.6).
    erase: HashMap<ContentId, ErasureKey>,
}

impl CompactionPlan {
    /// Ein leerer Plan (eine reine Garbage-Compaction ohne Erasure).
    pub fn new() -> Self {
        CompactionPlan { erase: HashMap::new() }
    }

    /// Plant die **Erasure** (Crypto-Shred) des Daten `id` unter `key`: in der neuen
    /// Generation wird seine Nutzlast versiegelt. Wird der `key` später aus dem
    /// Keystore zerstört, sind die Bytes unrückholbar (§Crypto-Shred).
    pub fn erase(&mut self, id: ContentId, key: ErasureKey) {
        self.erase.insert(id, key);
    }

    fn is_erased(&self, id: ContentId) -> bool {
        self.erase.contains_key(&id)
    }
}

/// Eine **unveränderliche compactierte Segment-Generation** (§15) — die neue,
/// physisch verdichtete Reihe, die die Vor-Generation per Epoche ersetzt. Sie hält
/// ihre Records über die **stabile logische ID** ([`ContentId`]); erasbare Nutzlasten
/// liegen crypto-versiegelt vor. Eine [`CompactedSegment`] wird **einmal** geschrieben
/// und nie mutiert (append-only-Geist, §7.1) — eine spätere Compaction erzeugt die
/// **nächste** Generation, statt diese zu ändern.
pub struct CompactedSegment {
    /// Die Generation dieser Segment-Reihe (§15).
    generation: Generation,
    /// Records in **deterministischer** Adress-Order (aufsteigende `ContentId`,
    /// §5.2/§1.4) — föderationsstabil und reproduzierbar.
    entries: Vec<CompactedEntry>,
    /// Schnelle ID→Index-Auflösung (rein abgeleitet; die `entries` sind die Wahrheit).
    by_id: HashMap<ContentId, usize>,
}

impl CompactedSegment {
    /// Die Generation dieses Segments (§15).
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Anzahl retained Records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true`, wenn keine Records enthalten sind.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `true`, wenn `id` in dieser Generation **vorhanden** ist (als Klartext **oder**
    /// als Tombstone/Chiffre) — das Daten ist als **Adresse** (§5.2) und über seine
    /// Kanten weiter erreichbar (§3.6), unabhängig davon, ob die Bytes (noch) lesbar
    /// sind.
    pub fn contains(&self, id: ContentId) -> bool {
        self.by_id.contains_key(&id)
    }

    /// `true`, wenn `id` ein **erastes** (crypto-versiegeltes) Daten ist (§Crypto-Shred).
    pub fn is_sealed(&self, id: ContentId) -> bool {
        match self.by_id.get(&id) {
            Some(&i) => self.entries[i].kind == RecordKind::Sealed,
            None => false,
        }
    }

    /// Liefert die **kanonischen Bytes** (§K4) des Daten `id`, gegen den `keystore`
    /// aufgelöst:
    ///
    /// - **Plain:** die Klartext-Bytes direkt.
    /// - **Sealed + lebender Schlüssel:** entsiegelt (AEAD), Bytes zurück.
    /// - **Sealed + zerstörter Schlüssel:** `Ok(None)` — die Bytes sind **unrückholbar**
    ///   (crypto-geschreddert), das Daten ist ein **Tombstone** (§3.6: die Adresse +
    ///   Kanten bleiben, der Verweis ist geschlossen, die Nutzlast ist weg).
    /// - **nicht vorhanden:** `Ok(None)`.
    ///
    /// Reines Mechanik-Lesen (§1.4); die Integrität jeder Chiffre ist per Poly1305-Tag
    /// geprüft (fail-closed §11: ein verfälschtes Tag ⇒ [`KernelError::Inconsistent`]).
    pub fn canonical_bytes(
        &self,
        id: ContentId,
        keystore: &Keystore,
    ) -> Result<Option<Vec<u8>>, KernelError> {
        let i = match self.by_id.get(&id) {
            Some(i) => *i,
            None => return Ok(None),
        };
        let e = &self.entries[i];
        match e.kind {
            RecordKind::Plain => Ok(Some(e.bytes.clone())),
            RecordKind::Sealed => match keystore.get(id) {
                // Lebender Schlüssel: entsiegeln.
                Some(key) => Ok(Some(crypto::open(key, id, &e.bytes)?)),
                // Schlüssel zerstört ⇒ Tombstone (Bytes unrückholbar, §Crypto-Shred).
                None => Ok(None),
            },
        }
    }

    /// Liefert das strikt dekodierte [`Datum`] zu `id` (gegen `keystore`), falls die
    /// Bytes (noch) lesbar sind; `None` für einen Tombstone (geschreddert) oder ein
    /// nicht vorhandenes Daten. Für ein **Plain**-Daten prüft sie defensiv, dass die
    /// zurückgelesene Form dieselbe `ContentId` trägt (Content-Adressierung intakt,
    /// §5.2) — ein Bruch ⇒ [`KernelError::Inconsistent`].
    pub fn datum(&self, id: ContentId, keystore: &Keystore) -> Result<Option<Datum>, KernelError> {
        let bytes = match self.canonical_bytes(id, keystore)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let datum = strict_decode(&bytes)?;
        // Content-Adressierung: die zurückgelesene Form MUSS dieselbe ID tragen
        // (auch nach Entsiegeln — die Bytes sind unverändert, §5.2/§Crypto-Shred).
        if ContentId::of_datum(&datum) != id {
            return Err(KernelError::Inconsistent);
        }
        Ok(Some(datum))
    }

    /// Alle **logischen IDs** dieser Generation, aufsteigend in Adress-Order
    /// (§5.2/§1.4) — Tombstones (geschredderte) eingeschlossen (sie bleiben als
    /// Adresse/Kante erreichbar, §3.6).
    pub fn ids(&self) -> Vec<ContentId> {
        self.entries.iter().map(|e| e.id).collect()
    }

    /// Schreibt die Generation **unveränderlich** in das Verzeichnis `gen_dir`
    /// (Datei `segment.lkc`) — atomar (Temp-Datei + Rename + Verzeichnis-
    /// `fsync`), sodass eine halb-geschriebene Generation **nie** sichtbar wird (§13-
    /// Atomarität-Analogon).
    ///
    /// Datei-Layout (alle Mehrbyte-Integer little-endian, analog [`crate::format`]):
    /// `magic(4) || generation(u64) || count(u64) ||` dann je Eintrag
    /// `id(32) || kind(u8) || byte_len(u64) || bytes`.
    pub fn write_to(&self, gen_dir: impl AsRef<Path>) -> Result<(), KernelError> {
        let gen_dir = gen_dir.as_ref();
        std::fs::create_dir_all(gen_dir).map_err(|_| KernelError::Io)?;
        let mut buf = Vec::new();
        buf.extend_from_slice(COMPACTED_MAGIC);
        buf.extend_from_slice(&self.generation.to_le_bytes());
        buf.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            buf.extend_from_slice(e.id.as_bytes());
            buf.push(e.kind as u8);
            buf.extend_from_slice(&(e.bytes.len() as u64).to_le_bytes());
            buf.extend_from_slice(&e.bytes);
        }
        atomic_write(&gen_dir.join(COMPACTED_SEGMENT_FILE), &buf)?;
        Ok(())
    }

    /// Liest eine compactierte Generation aus `gen_dir` (read-only `pread` in einen
    /// `Vec`; die Generation ist unveränderlich, also kein torn-tail-Risiko). Prüft
    /// Magic und strukturelle Konsistenz; ein Defekt ⇒ [`KernelError::Inconsistent`].
    pub fn read_from(gen_dir: impl AsRef<Path>) -> Result<Self, KernelError> {
        let path = gen_dir.as_ref().join(COMPACTED_SEGMENT_FILE);
        let mut f = File::open(&path).map_err(|_| KernelError::Io)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|_| KernelError::Io)?;
        if buf.len() < 20 || &buf[..4] != COMPACTED_MAGIC {
            return Err(KernelError::Inconsistent);
        }
        let generation =
            u64::from_le_bytes(buf[4..12].try_into().map_err(|_| KernelError::Inconsistent)?);
        let count =
            u64::from_le_bytes(buf[12..20].try_into().map_err(|_| KernelError::Inconsistent)?);
        let mut pos = 20usize;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if pos + 41 > buf.len() {
                return Err(KernelError::Inconsistent);
            }
            let id = ContentId::from_bytes(
                buf[pos..pos + 32].try_into().map_err(|_| KernelError::Inconsistent)?,
            );
            let kind = RecordKind::from_u8(buf[pos + 32])?;
            let byte_len = u64::from_le_bytes(
                buf[pos + 33..pos + 41].try_into().map_err(|_| KernelError::Inconsistent)?,
            ) as usize;
            pos += 41;
            if pos + byte_len > buf.len() {
                return Err(KernelError::Inconsistent);
            }
            let bytes = buf[pos..pos + byte_len].to_vec();
            pos += byte_len;
            entries.push(CompactedEntry { id, kind, bytes });
        }
        if pos != buf.len() {
            return Err(KernelError::Inconsistent); // Rest-Bytes ⇒ Defekt.
        }
        let by_id = entries.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
        Ok(CompactedSegment {
            generation,
            entries,
            by_id,
        })
    }
}

/// Der **Compactor** (§15) — baut aus einer Eingabe-Daten-Menge die nächste
/// compactierte Generation: lässt Überholte/Verborgene/Eraste fallen, versiegelt
/// Eraste (Crypto-Shred), führt die Refcounts/Reachability mit und schreibt die
/// **unveränderliche** Generation + den Keystore atomar.
///
/// **Eingabe statt Vor-Generation-Offsets (§15-Plan):** der Compactor arbeitet über
/// `(ContentId, Datum)`-Paare (die **stabilen logischen IDs**, nie rohe Offsets), wie
/// sie [`crate::store::ContentStore::iter_active_data`] (oder eine vorige Generation)
/// liefert. So ist der Rewrite vom physischen Layout der Quelle entkoppelt.
pub struct Compactor {
    /// `ContentId`s, die physisch **fallengelassen** werden (überholt §6.3 / verborgen
    /// §9.5) — **sofern** sie nicht von einem retained Daten referenziert werden
    /// (Refcount-Schutz, s. u.).
    drop: HashSet<ContentId>,
    /// Der Erasure-/Crypto-Shred-Plan (§15).
    plan: CompactionPlan,
}

impl Compactor {
    /// Ein Compactor mit der Fallenlass-Menge `drop` (überholte §6.3 / verborgene
    /// §9.5 Daten, von der Schicht darüber/dem Daemon aus den expliziten Kontexten
    /// bestimmt) und dem Erasure-Plan `plan` (§15). Der Kernel **wertet nicht** (§1.4)
    /// — er lässt genau die übergebenen Mengen fallen/versiegelt sie.
    pub fn new(drop: HashSet<ContentId>, plan: CompactionPlan) -> Self {
        Compactor { drop, plan }
    }

    /// Baut die nächste Generation `generation` aus `data` (`(ContentId, Datum)`-Paare
    /// in Abhängigkeits-Reihenfolge: Kontexte vor Besitzern — wie
    /// [`crate::store::ContentStore::iter_active_data`]).
    ///
    /// **Refcount/Reachability-Schutz (§5.3/Plan).** Ein Daten in `drop` wird **nur
    /// dann** physisch fallengelassen, wenn **kein** retained Daten es als besessenen
    /// Kontext referenziert (Refcount 0). Wird es noch referenziert (eine andere
    /// Dedup-Referenz hält es rechtmäßig), **bleibt** es — die Löschung einer Referenz
    /// zerstört **nicht** die Daten einer anderen. Ein erastes Daten (im `plan`) wird
    /// **nie** fallengelassen (seine `ContentId`/Kanten bleiben, §3.6), sondern
    /// **versiegelt**.
    ///
    /// Liefert die [`CompactedSegment`], den befüllten [`Keystore`] (die Lösch-
    /// Schlüssel der erasten Daten) und die [`Refcounts`] (Beleg der Reachability) plus
    /// einen [`CompactionReport`].
    pub fn compact(
        &self,
        generation: Generation,
        data: &[(ContentId, Datum)],
    ) -> Result<(CompactedSegment, Keystore, Refcounts, CompactionReport), KernelError> {
        let input_len = data.len() as u64;

        // 1) **Closure-erhaltender Drop-Fixpunkt** (§3.6/§5.3-Dedup-Sicherheit): ein
        //    Daten aus `drop` wird **tatsächlich** nur fallengelassen, wenn **kein
        //    behaltenes** Daten es als besessenen Kontext referenziert. Ein erastes
        //    Daten (im `plan`) wird **nie** fallengelassen (es bleibt als versiegelter
        //    Tombstone, §3.6). Wir iterieren: solange ein Drop-Kandidat noch von einem
        //    (vorläufig) behaltenen Daten referenziert wird, bleibt er behalten; sein
        //    Wegfall kann weitere Kandidaten freigeben (Kette). Der Fixpunkt erhält die
        //    referenzielle Geschlossenheit (§3.6: kein behaltenes Daten verweist je auf
        //    ein fallengelassenes) **und** schützt jede rechtmäßig gehaltene Dedup-
        //    Referenz (§5.3: die Löschung einer Referenz zerstört nicht die Daten einer
        //    anderen).
        let mut dropped: HashSet<ContentId> = HashSet::new();
        loop {
            // Refcounts über die aktuell BEHALTENEN Daten (nicht-dropped) bestimmen.
            let mut refs_now = Refcounts::new();
            for (id, datum) in data {
                if dropped.contains(id) {
                    continue;
                }
                if let Some(owns) = datum.owns() {
                    for ctx in owns {
                        refs_now.incr(*ctx);
                    }
                }
            }
            // Einen weiteren Kandidaten fallenlassen, der in `drop`, nicht erast, noch
            // nicht gedroppt und von keinem BEHALTENEN Daten referenziert ist.
            let mut progressed = false;
            for (id, _) in data {
                let id = *id;
                if dropped.contains(&id) {
                    continue;
                }
                if self.drop.contains(&id) && !self.plan.is_erased(id) && refs_now.count(id) == 0 {
                    dropped.insert(id);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }

        // Finale Refcounts über die behaltenen Daten (Beleg der Reachability §5.3).
        let mut refs = Refcounts::new();
        for (id, datum) in data {
            if dropped.contains(id) {
                continue;
            }
            if let Some(owns) = datum.owns() {
                for ctx in owns {
                    refs.incr(*ctx);
                }
            }
        }

        // 2) Retained-Menge schreiben: alles außer dem fallengelassenen Fixpunkt. Ein
        //    erastes Daten wird versiegelt (Crypto-Shred), der Rest bleibt Klartext.
        let mut entries: Vec<CompactedEntry> = Vec::new();
        let mut keystore = Keystore::new();
        let mut sealed = 0u64;
        for (id, datum) in data {
            let id = *id;
            let erased = self.plan.is_erased(id);
            if dropped.contains(&id) {
                // Physisch fallenlassen (Fixpunkt: weder erast noch von Behaltenem
                // referenziert, §3.6/§5.3).
                continue;
            }
            if erased {
                // Crypto-Shred: die Nutzlast versiegeln; die ContentId/Kanten bleiben.
                let key = self
                    .plan
                    .erase
                    .get(&id)
                    .ok_or(KernelError::Inconsistent)?
                    .clone();
                let plaintext = crate::serialize::canonical_cbor(datum);
                let ciphertext = crypto::seal(&key, id, &plaintext)?;
                keystore.put(id, key);
                entries.push(CompactedEntry {
                    id,
                    kind: RecordKind::Sealed,
                    bytes: ciphertext,
                });
                sealed += 1;
            } else {
                // Klartext behalten (kanonische Bytes, §K4).
                let plaintext = crate::serialize::canonical_cbor(datum);
                entries.push(CompactedEntry {
                    id,
                    kind: RecordKind::Plain,
                    bytes: plaintext,
                });
            }
        }

        // Deterministische Adress-Order (§5.2/§1.4) — föderationsstabil, reproduzierbar.
        entries.sort_by_key(|e| e.id);
        let by_id = entries.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
        let retained = entries.len() as u64;
        let segment = CompactedSegment {
            generation,
            entries,
            by_id,
        };
        let report = CompactionReport {
            generation,
            retained,
            dropped: input_len - retained,
            sealed,
        };
        Ok((segment, keystore, refs, report))
    }
}

/// Pfad der **Keystore-Datei** einer Generation (im Generations-Verzeichnis). Der
/// Keystore ist **kein** Log-Bestandteil (§8.4): das zerstörbare Geheimnis.
pub fn keystore_path(gen_dir: impl AsRef<Path>) -> PathBuf {
    gen_dir.as_ref().join(KEYSTORE_FILE)
}

/// Pfad des Generations-Verzeichnisses `base/compacted/gen-NNNNNNNNNNNNNNNNNNNN`
/// (null-gepolstert, lexikographisch sortierbar). Eine Generation lebt vollständig
/// in **ihrem eigenen** Verzeichnis (Segment + Keystore), sodass eine alte Generation
/// auf Platte bleibt, bis kein Leser sie mehr hält (drop-after-quiesce).
pub fn generation_dir(base: impl AsRef<Path>, generation: Generation) -> PathBuf {
    base.as_ref()
        .join("compacted")
        .join(format!("gen-{generation:020}"))
}

/// Datei, die die **aktuell live** Generation benennt (§13-Epoche-Analogon): der
/// `CURRENT`-Marker. Ein **atomarer** Rewrite dieser Datei (Temp + Rename + fsync)
/// schaltet eine neu geschriebene Generation **gemeinsam** live — analog zum
/// abschließenden Aktiv-Schreiben eines §13-Umbaus. Ein Crash vor dem Rewrite lässt
/// die alte Generation live (die neue ist nie sichtbar geworden).
pub fn current_marker_path(base: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join("compacted").join("CURRENT")
}

/// Liest die aktuell live Generation aus dem `CURRENT`-Marker; fehlt er, gibt es noch
/// keine compactierte Generation (`None`).
pub fn read_current_generation(base: impl AsRef<Path>) -> Result<Option<Generation>, KernelError> {
    let path = current_marker_path(base);
    if !path.exists() {
        return Ok(None);
    }
    let mut s = String::new();
    File::open(&path)
        .map_err(|_| KernelError::Io)?
        .read_to_string(&mut s)
        .map_err(|_| KernelError::Io)?;
    let g: Generation = s.trim().parse().map_err(|_| KernelError::Inconsistent)?;
    Ok(Some(g))
}

/// Schaltet die Generation `generation` **atomar** live: schreibt den `CURRENT`-
/// Marker (Temp + Rename + Verzeichnis-`fsync`) — der **eine** Linearisierungspunkt,
/// der die zuvor geschriebene Generation gemeinsam sichtbar macht (§13-Analogon). Die
/// **alte** Generation wird **nicht** entfernt (drop-after-quiesce: ein Leser darf sie
/// noch halten; das Aufräumen ist eine separate, gequiescte Operation).
pub fn publish_generation(
    base: impl AsRef<Path>,
    generation: Generation,
) -> Result<(), KernelError> {
    let base = base.as_ref();
    let dir = base.join("compacted");
    std::fs::create_dir_all(&dir).map_err(|_| KernelError::Io)?;
    atomic_write(&current_marker_path(base), generation.to_string().as_bytes())?;
    Ok(())
}

/// **Atomares** Schreiben einer Datei (Temp-Datei im selben Verzeichnis → `fsync` →
/// Rename → Verzeichnis-`fsync`), sodass ein Crash nie eine halb-geschriebene Datei
/// hinterlässt (§Durability-Geist). Reines, sicheres `std::fs`-I/O.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), KernelError> {
    let dir = path.parent().ok_or(KernelError::Inconsistent)?;
    std::fs::create_dir_all(dir).map_err(|_| KernelError::Io)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|_| KernelError::Io)?;
        f.write_all(bytes).map_err(|_| KernelError::Io)?;
        f.sync_all().map_err(|_| KernelError::Io)?;
    }
    std::fs::rename(&tmp, path).map_err(|_| KernelError::Io)?;
    // Verzeichnis-fsync, damit der Rename selbst durabel ist.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Baut die Abhängigkeits-geordneten `(ContentId, Datum)`-Eingabedaten für einen
    /// kleinen Graphen: zwei Blätter `a`, `b` und ein Knoten `n = { a, b }`.
    fn small_graph() -> (ContentId, ContentId, ContentId, Vec<(ContentId, Datum)>) {
        let a = Datum::leaf(b"alpha".to_vec());
        let b = Datum::leaf(b"beta".to_vec());
        let a_id = ContentId::of_datum(&a);
        let b_id = ContentId::of_datum(&b);
        let n = Datum::node([a_id, b_id]).unwrap();
        let n_id = ContentId::of_datum(&n);
        let data = vec![(a_id, a), (b_id, b), (n_id, n)];
        (a_id, b_id, n_id, data)
    }

    #[test]
    fn compaction_drops_unreferenced_superseded_record() {
        // §15/§6.3: ein überholtes, NICHT referenziertes Daten wird physisch
        // fallengelassen; Content-Adressierung der behaltenen bleibt intakt.
        let (a_id, b_id, n_id, data) = small_graph();
        let extra = Datum::leaf(b"ueberholt".to_vec());
        let extra_id = ContentId::of_datum(&extra);
        let mut data = data;
        data.push((extra_id, extra));

        let mut drop = HashSet::new();
        drop.insert(extra_id); // überholt + nicht referenziert ⇒ fallenlassen.
        let c = Compactor::new(drop, CompactionPlan::new());
        let (seg, ks, _refs, report) = c.compact(1, &data).unwrap();

        assert_eq!(report.dropped, 1);
        assert!(!seg.contains(extra_id), "überholtes Daten physisch weg");
        // Content-Adressierung der behaltenen intakt.
        assert!(seg.datum(a_id, &ks).unwrap().is_some());
        assert!(seg.datum(b_id, &ks).unwrap().is_some());
        assert_eq!(seg.datum(n_id, &ks).unwrap(), Some(Datum::node([a_id, b_id]).unwrap()));
    }

    #[test]
    fn refcount_protects_a_dedup_shared_datum_from_drop() {
        // Plan „Refcount für Dedup-Sicherheit": `a` ist in `drop`, wird aber von `n`
        // referenziert ⇒ es BLEIBT (eine andere Referenz hält es rechtmäßig).
        let (a_id, b_id, n_id, data) = small_graph();
        let mut drop = HashSet::new();
        drop.insert(a_id);
        let c = Compactor::new(drop, CompactionPlan::new());
        let (seg, ks, refs, _r) = c.compact(1, &data).unwrap();
        assert!(refs.count(a_id) >= 1, "von n referenziert");
        assert!(seg.contains(a_id), "referenziertes Daten NICHT fallengelassen");
        assert_eq!(seg.datum(a_id, &ks).unwrap(), Some(Datum::leaf(b"alpha".to_vec())));
        let _ = (b_id, n_id);
    }

    #[test]
    fn crypto_shred_bytes_unrecoverable_after_key_destroyed_refs_stay_closed() {
        // §15/§Crypto-Shred/§3.6: ein erastes Daten wird versiegelt; nach Zerstören
        // des Schlüssels sind die BYTES unrückholbar, aber die ContentId/Kanten
        // bleiben (Tombstone, geschlossener Verweis), und ANDERE Dedup-Referenzen
        // überleben (Refcount).
        let (a_id, b_id, n_id, data) = small_graph();
        // `b` wird erast; `n = { a, b }` referenziert `b` weiter (Kante bleibt §3.6).
        let key = ErasureKey::from_bytes([0x9a; 32]);
        let mut plan = CompactionPlan::new();
        plan.erase(b_id, key);
        let c = Compactor::new(HashSet::new(), plan);
        let (seg, mut ks, _refs, report) = c.compact(1, &data).unwrap();
        assert_eq!(report.sealed, 1);

        // Mit dem lebenden Schlüssel: die Bytes von `b` sind (noch) lesbar.
        assert_eq!(seg.datum(b_id, &ks).unwrap(), Some(Datum::leaf(b"beta".to_vec())));

        // Schlüssel ZERSTÖREN ⇒ die Bytes von `b` sind unrückholbar (Tombstone).
        assert!(ks.destroy(b_id));
        assert_eq!(seg.canonical_bytes(b_id, &ks).unwrap(), None, "Bytes geschreddert");
        // Aber: die ContentId bleibt als Adresse erreichbar (§3.6 — Verweis geschlossen).
        assert!(seg.contains(b_id), "Tombstone: ContentId/Kante bleibt (§3.6)");
        assert!(seg.is_sealed(b_id));
        // Und `a` (eine andere, NICHT erasterte Referenz) überlebt unverändert (Refcount).
        assert_eq!(seg.datum(a_id, &ks).unwrap(), Some(Datum::leaf(b"alpha".to_vec())));
        // Der besitzende Knoten `n` referenziert `b` strukturell weiter (Kante intakt).
        assert_eq!(seg.datum(n_id, &ks).unwrap(), Some(Datum::node([a_id, b_id]).unwrap()));
    }

    #[test]
    fn compacted_segment_round_trips_on_disk_with_keystore() {
        // §15: die unveränderliche Generation + Keystore round-trippen auf Platte;
        // ein nach dem Reopen ZERSTÖRTER Schlüssel schreddert die Bytes weiterhin.
        let (a_id, b_id, _n_id, data) = small_graph();
        let key = ErasureKey::from_bytes([0x7c; 32]);
        let mut plan = CompactionPlan::new();
        plan.erase(b_id, key);
        let c = Compactor::new(HashSet::new(), plan);
        let (seg, ks, _refs, _r) = c.compact(3, &data).unwrap();

        let dir = tempdir().unwrap();
        let gdir = generation_dir(dir.path(), 3);
        seg.write_to(&gdir).unwrap();
        ks.save(gdir.join(KEYSTORE_FILE)).unwrap();
        publish_generation(dir.path(), 3).unwrap();

        // Reopen.
        assert_eq!(read_current_generation(dir.path()).unwrap(), Some(3));
        let seg2 = CompactedSegment::read_from(&gdir).unwrap();
        let mut ks2 = Keystore::load(gdir.join(KEYSTORE_FILE)).unwrap();
        assert_eq!(seg2.generation(), 3);
        assert_eq!(seg2.datum(a_id, &ks2).unwrap(), Some(Datum::leaf(b"alpha".to_vec())));
        assert_eq!(seg2.datum(b_id, &ks2).unwrap(), Some(Datum::leaf(b"beta".to_vec())));
        // Schreddern nach Reopen.
        assert!(ks2.destroy(b_id));
        assert_eq!(seg2.canonical_bytes(b_id, &ks2).unwrap(), None);
        assert!(seg2.contains(b_id), "Tombstone bleibt nach Reopen");
    }
}
