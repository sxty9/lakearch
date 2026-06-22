//! Das abstrakte Daten-Modell (was kanonisiert und gehasht wird).
//!
//! Maßgeblich: `semantics/canonical-encoding.md` §K2 und das Gesetzbuch
//! `semantics/lakearch.md` §2–§5. Es gibt genau **eine** Entität: das Daten
//! (§2.1). Struktur entsteht **allein durch Kontexte** (§4.3); es gibt **keine
//! zweite Entitätsklasse** (§2.2) und **kein** privilegiertes „Inhalts"-Feld
//! neben den Kontexten.
//!
//! Ein Daten hat für die Zwecke der Kanonik genau **zwei** mögliche Klassen
//! (§K2.1):
//!
//! - **Blatt (atomar):** eine opake atomare Nutzlast (`payload`), **keine**
//!   besessenen Kontexte. Dedupliziert auf seinen atomaren Bytes allein
//!   (§5.3 „ein primitives Daten existiert genau einmal").
//! - **Knoten (besitzend):** **keine** atomare Nutzlast, eine nicht-leere,
//!   **sortiert-deduplizierte Menge** der `ContentId`s seiner besessenen
//!   Kontexte (§3.1/§K2.3). Identität entsteht vollständig aus dieser Menge
//!   (§4.3).
//!
//! Die gemischte Klasse (payload **und** owns) und das „leere Nichts" (weder
//! payload noch owns) sind **wohlgeformtheits-fehlerhaft** (§K2.1) und werden
//! durch die Konstruktoren dieses Moduls schon im Typ verhindert.
//!
//! Ein **Kontext** ist keine eigene Entität, sondern die **Rolle** eines
//! besessenen Daten (§3.1). Er wird daher **nicht** als separater adressierbarer
//! Typ modelliert; in der `owns`-Menge erscheint Besitz **ausschließlich** als
//! die `ContentId` des besessenen Daten (§K2.2). Die Kante `A ⊳ K` bekommt
//! **keine** eigene `ContentId` und existiert physisch nur als später
//! abgeleiteter Index-Eintrag.
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]` (das Daten-Modell muss beweisbar
//! sicheres Rust sein; das `unsafe` lebt allein im `mmap`-Leaf [`crate::log`]).

#![forbid(unsafe_code)]

use crate::id::ContentId;

/// Ein Daten (§2.1) — die einzige Entität. Entweder ein atomares Blatt oder ein
/// besitzender Knoten; nie beides, nie keines (§K2.1).
///
/// Floats sind im v1-Modell **modell-weit verboten** (§K3.4); deshalb gibt es
/// hier keinen Float-Bestandteil. Atomare Nutzlast ist stets ein **opaker
/// Byte-String** (§K3.7) — lakearch interpretiert ihn nicht (§1.4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Datum {
    inner: DatumKind,
}

/// Die zwei wohlgeformten Klassen eines Daten (§K2.1). Privat, damit die
/// Invarianten (Sortierung/Deduplizierung der `owns`-Menge, Nicht-Leere des
/// Knotens, Ausschluss der gemischten Klasse) **ausschließlich** über die
/// Konstruktoren hergestellt werden können.
#[derive(Clone, PartialEq, Eq, Debug)]
enum DatumKind {
    /// Primitives Blatt: opake atomare Nutzlast, keine Kontexte (§K2.1).
    Leaf { payload: Vec<u8> },
    /// Besitzender Knoten: nicht-leere, aufsteigend sortierte, deduplizierte
    /// Menge der `ContentId`s der besessenen Kontexte (§K2.3). Die Invariante
    /// „sortiert + dedupliziert + nicht leer" gilt für jeden konstruierbaren
    /// Wert.
    Node { owns: Vec<ContentId> },
}

impl Datum {
    /// Erzeugt ein **atomares Blatt** aus opaken Bytes (§K2.1). Ein leeres Blatt
    /// (`payload = []`) ist wohlgeformt und von „kein payload" (= Knoten)
    /// verschieden (§K3.5).
    pub fn leaf(payload: impl Into<Vec<u8>>) -> Self {
        Datum {
            inner: DatumKind::Leaf {
                payload: payload.into(),
            },
        }
    }

    /// Erzeugt einen **besitzenden Knoten** aus einer beliebig sortierten,
    /// möglicherweise Duplikate enthaltenden Sammlung besessener Kontext-IDs.
    ///
    /// Der Konstruktor stellt die kanonische Invariante her (§K2.3): die IDs
    /// werden **aufsteigend in 32-Byte-lexikographischer Reihenfolge** sortiert
    /// und **dedupliziert**. Die Einfüge-Reihenfolge und Vielfachheit haben
    /// damit **keine** Bedeutung — zwei Knoten mit derselben Kontext-Menge
    /// tragen dieselbe `ContentId` (§5.3-Erhalt).
    ///
    /// Gibt `None` zurück, wenn nach der Deduplizierung **keine** Kontext-ID
    /// übrig bleibt: ein Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1) —
    /// das wäre entweder ein Blatt oder gar kein Daten. (Der Kernel **validiert**
    /// keine fachliche Eingabe, §1.4; dies ist allein die mechanische Wahrung
    /// der Konstruktions-Invariante, nicht eine inhaltliche Wertung.)
    pub fn node(owned_contexts: impl IntoIterator<Item = ContentId>) -> Option<Self> {
        let mut owns: Vec<ContentId> = owned_contexts.into_iter().collect();
        // Sortierung ist rein adressbasiert (32-Byte-Order), kein Wert-Sort
        // (§1.4/§5.2): sie ordnet Adressen, nicht Werte, und ist
        // föderationsstabil.
        owns.sort_unstable();
        owns.dedup();
        if owns.is_empty() {
            return None;
        }
        Some(Datum {
            inner: DatumKind::Node { owns },
        })
    }

    /// Die atomare Nutzlast, falls dies ein Blatt ist (§K2.1).
    pub fn payload(&self) -> Option<&[u8]> {
        match &self.inner {
            DatumKind::Leaf { payload } => Some(payload),
            DatumKind::Node { .. } => None,
        }
    }

    /// Die kanonisch sortiert-deduplizierte Menge der besessenen Kontext-IDs,
    /// falls dies ein Knoten ist (§K2.3). Die Reihenfolge ist die kanonische
    /// (aufsteigende 32-Byte-Order).
    pub fn owns(&self) -> Option<&[ContentId]> {
        match &self.inner {
            DatumKind::Node { owns } => Some(owns),
            DatumKind::Leaf { .. } => None,
        }
    }

    /// `true`, wenn dies ein primitives Blatt ist (§K2.1).
    pub fn is_leaf(&self) -> bool {
        matches!(self.inner, DatumKind::Leaf { .. })
    }

    /// `true`, wenn dies ein besitzender Knoten ist (§K2.1).
    pub fn is_node(&self) -> bool {
        matches!(self.inner, DatumKind::Node { .. })
    }
}

/// Platzhalter-Daten (§3.6) — referenzielle Geschlossenheit ohne baumelnde
/// Verweise.
///
/// **Konvention (§3.6).** Ein Verweis zeigt **stets auf ein vorhandenes Daten**.
/// Ein noch nicht eingetroffenes Ziel wird durch ein **Platzhalter-Daten**
/// dargestellt: ein **gewöhnliches** Daten (ein Knoten, §K2.1) mit einem
/// Kontext, der es als *unaufgelöst/erwartet* ausweist. So ist jeder Verweis
/// geschlossen — es gibt **keine** baumelnden Verweise, nur explizit als
/// unaufgelöst markierte Daten.
///
/// **Grenze (§1.4/§7.2).** Der **Kernel** materialisiert Platzhalter **nicht**
/// und validiert die Geschlossenheit **nicht** — das erzwingt die *schreibende
/// Schicht*. Dieses Modul stellt allein die **Konvention** bereit (welches Atom
/// markiert „unaufgelöst", wie sieht ein Platzhalter-Knoten aus), damit Indizes
/// und Traversierung (spätere Phasen) auf der geschlossenen-Verweis-Invariante
/// bauen können. Die **volle** Platzhalter-Behandlung (Ersetzung §6.3,
/// Korrelations-Pfad §5.7 b) ist **Phase 3**.
///
/// **Aufbau.** Das Marker-Atom [`Datum::unresolved_marker`] ist ein gewöhnliches
/// Blatt-Daten (§2.1) mit fester, eingefrorener atomarer Nutzlast; seine
/// `ContentId` ist das eingefrorene Relations-/Typ-Daten „unaufgelöst/erwartet"
/// (§3.3/§4.1). Ein Platzhalter [`Datum::placeholder`] ist der **Knoten**, der
/// dieses Marker-Atom **und** die erwarteten Ziel-Kontexte besitzt.
impl Datum {
    /// Das eingefrorene **Marker-Atom** „unaufgelöst/erwartet" (§3.6) — ein
    /// gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast.
    ///
    /// Die Nutzlast ist exakt der ASCII-String `lakearch/unresolved/v1`; sie ist
    /// **eingefroren** (eine Änderung verschöbe die Marker-`ContentId` und damit
    /// die Erkennbarkeit aller Platzhalter). lakearch interpretiert die Bytes
    /// **nicht** (§1.4); der Wert ist allein eine wohlbekannte, föderationsweit
    /// gleiche Konvention (gleiche Bytes ⇒ gleiche `ContentId`, §5.3/§12.3).
    pub fn unresolved_marker() -> Self {
        Datum::leaf(*UNRESOLVED_MARKER_PAYLOAD)
    }

    /// Erzeugt ein **Platzhalter-Daten** (§3.6): ein Knoten, der das
    /// [`unresolved`](Datum::unresolved_marker)-Marker-Atom **und** die
    /// erwarteten Ziel-Kontexte besitzt.
    ///
    /// `expected_contexts` sind die `ContentId`s der Kontexte, auf die das
    /// erwartete Ziel zeigen soll (sie dürfen leer sein — dann ist der
    /// Platzhalter „nur als unaufgelöst markiert", ohne weitere Erwartung). Wie
    /// bei [`Datum::node`] ist die `owns`-Menge **sortiert + dedupliziert**; das
    /// Marker-Atom wird hinzugefügt, dann kanonisiert.
    ///
    /// Gibt **immer** `Some` zurück: das Marker-Atom ist stets in der Menge, ein
    /// Platzhalter ist also nie der leere (nicht wohlgeformte) Knoten (§K2.1).
    ///
    /// Der Kernel **wertet nicht** (§1.4): er prüft **nicht**, ob die erwarteten
    /// Ziele existieren — das ist Sache der schreibenden Schicht (§7.2).
    pub fn placeholder(expected_contexts: impl IntoIterator<Item = ContentId>) -> Self {
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        let owns = core::iter::once(marker).chain(expected_contexts);
        // `node` gibt nur `None` für die leere Menge zurück; das Marker-Atom ist
        // immer dabei, daher ist der Platzhalter stets wohlgeformt (§K2.1).
        Datum::node(owns).expect("Platzhalter besitzt stets das Marker-Atom (§3.6)")
    }

    /// `true`, wenn dieser Knoten das eingefrorene „unaufgelöst/erwartet"-Marker-
    /// Atom besitzt — also ein **Platzhalter-Daten** ist (§3.6).
    ///
    /// Reines **strukturelles Matching** (§1.3): „besitzt der Knoten den Marker-
    /// Kontext?". Keine Wertung (§1.4). Ein Blatt ist nie ein Platzhalter.
    pub fn is_placeholder(&self) -> bool {
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        match self.owns() {
            // `owns` ist aufsteigend sortiert ⇒ Binärsuche ist zulässig und
            // ändert die Semantik nicht (reines Mengen-Matching, §1.3).
            Some(owns) => owns.binary_search(&marker).is_ok(),
            None => false,
        }
    }
}

/// Eingefrorene atomare Nutzlast des Marker-Atoms „unaufgelöst/erwartet" (§3.6).
/// Exakt 22 Bytes ASCII; **niemals** ändern (verschöbe alle Platzhalter-IDs).
const UNRESOLVED_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/unresolved/v1";

/// Eingefrorene atomare Nutzlast des Marker-Atoms „Bereichs-Zugehörigkeit" (§11.1).
/// Exakt 27 Bytes ASCII; **niemals** ändern (verschöbe alle Zugehörigkeits-IDs).
const AREA_MEMBERSHIP_MARKER_PAYLOAD: &[u8; 27] = b"lakearch/area-membership/v1";

/// Eingefrorene atomare Nutzlast des „Subjekt-Rolle"-Marker-Atoms einer
/// Berechtigung (§11.1). Exakt 24 Bytes ASCII; **niemals** ändern.
const PERMISSION_SUBJECT_MARKER_PAYLOAD: &[u8; 24] = b"lakearch/perm-subject/v1";

/// Eingefrorene atomare Nutzlast des „Bereichs-Rolle"-Marker-Atoms einer
/// Berechtigung (§11.1). Exakt 21 Bytes ASCII; **niemals** ändern.
const PERMISSION_AREA_MARKER_PAYLOAD: &[u8; 21] = b"lakearch/perm-area/v1";

/// Eingefrorene atomare Nutzlast des Marker-Atoms „Berechtigung" (§11.1). Exakt
/// 22 Bytes ASCII; **niemals** ändern (verschöbe alle Berechtigungs-IDs).
const PERMISSION_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/permission/v1";

/// Eingefrorene atomare Nutzlast des „Entzugs"-Marker-Atoms (§11.4). Exakt
/// 22 Bytes ASCII; **niemals** ändern.
const REVOCATION_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/revocation/v1";

/// Eingefrorene atomare Nutzlast des **Aufzeichnungszeit**-Achsen-Marker-Atoms
/// (§6.2: „wann das System es erfuhr"). Exakt 26 Bytes ASCII; **niemals** ändern
/// (verschöbe alle Aufzeichnungszeit-Aussagen). Bewusst **verschieden** von der
/// Gültigkeitszeit-Achse, damit die beiden Achsen strukturell unterscheidbar sind.
const RECORDING_TIME_MARKER_PAYLOAD: &[u8; 26] = b"lakearch/recording-time/v1";

/// Eingefrorene atomare Nutzlast des **Gültigkeitszeit**-Achsen-Marker-Atoms
/// (§6.2: „wann der Sachverhalt in der Welt gilt"). Exakt 25 Bytes ASCII;
/// **niemals** ändern.
const VALIDITY_TIME_MARKER_PAYLOAD: &[u8; 25] = b"lakearch/validity-time/v1";

/// Eingefrorene atomare Nutzlast des **Ersetzungs**-Marker-Atoms (§6.3:
/// Ersetzungs-Kontext). Exakt 22 Bytes ASCII; **niemals** ändern.
const SUPERSESSION_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/supersedes/v1";

/// Eingefrorene atomare Nutzlast des **Anker-Rollen**-Marker-Atoms (§9.1: das
/// eigene Anker-Daten = die Klasse). Exakt 18 Bytes ASCII; **niemals** ändern
/// (verschöbe die Erkennbarkeit aller Anker).
const ANCHOR_MARKER_PAYLOAD: &[u8; 18] = b"lakearch/anchor/v1";

/// Eingefrorene atomare Nutzlast des **Mitgliedschafts**-Marker-Atoms (§9.3:
/// Repräsentant → Anker, ein **revidierbarer** Kontext, kein destruktiver
/// Zusammenschluss). Exakt 22 Bytes ASCII; **niemals** ändern.
const MEMBERSHIP_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/membership/v1";

/// Eingefrorene atomare Nutzlast des **Grad**-Rollen-Marker-Atoms einer
/// Mitgliedschaft (§9.3: Mitgliedschaft ist **gradiert**). Exakt 17 Bytes ASCII;
/// **niemals** ändern. Der Grad-**Wert** selbst ist ein opakes Daten — der
/// Kernel **wertet/vergleicht ihn nie** (§1.4/§9-Präambel).
const MEMBERSHIP_GRADE_MARKER_PAYLOAD: &[u8; 17] = b"lakearch/grade/v1";

/// Eingefrorene atomare Nutzlast des **deckungsgleich**-Stärke-Marker-Atoms der
/// gradierten referenziellen Identität (§5.5). Exakt 32 Bytes ASCII; **niemals**
/// ändern.
const IDENT_DECKUNGSGLEICH_PAYLOAD: &[u8; 32] = b"lakearch/ident-deckungsgleich/v1";

/// Eingefrorene atomare Nutzlast des **ergaenzt**-Stärke-Marker-Atoms (§5.5).
/// Exakt 26 Bytes ASCII; **niemals** ändern.
const IDENT_ERGAENZT_PAYLOAD: &[u8; 26] = b"lakearch/ident-ergaenzt/v1";

/// Eingefrorene atomare Nutzlast des **widerspricht-in**-Stärke-Marker-Atoms
/// (§5.5). Exakt 33 Bytes ASCII; **niemals** ändern.
const IDENT_WIDERSPRICHT_IN_PAYLOAD: &[u8; 33] = b"lakearch/ident-widerspricht-in/v1";

/// Eingefrorene atomare Nutzlast des **verwandt-mit**-Stärke-Marker-Atoms
/// (§5.5). Exakt 30 Bytes ASCII; **niemals** ändern.
const IDENT_VERWANDT_MIT_PAYLOAD: &[u8; 30] = b"lakearch/ident-verwandt-mit/v1";

/// Eingefrorene atomare Nutzlast des **bekannt-verschieden**-Stärke-Marker-Atoms
/// (§5.5). Exakt 37 Bytes ASCII; **niemals** ändern.
const IDENT_BEKANNT_VERSCHIEDEN_PAYLOAD: &[u8; 37] = b"lakearch/ident-bekannt-verschieden/v1";

/// Eingefrorene atomare Nutzlast des **Verbergen**-Kuratierungs-Marker-Atoms
/// (§9.5: ein **reversibler** Lese-Seiten-Filter, nichts wird gelöscht). Exakt
/// 25 Bytes ASCII; **niemals** ändern.
const CURATION_HIDE_MARKER_PAYLOAD: &[u8; 25] = b"lakearch/curation/hide/v1";

/// Eingefrorene atomare Nutzlast des **Aufheben-des-Verbergens**-Kuratierungs-
/// Marker-Atoms (§9.5: das **reversierende** Gegenstück zu *hide* — append-only,
/// nichts wird gelöscht). Exakt 27 Bytes ASCII; **niemals** ändern.
const CURATION_UNHIDE_MARKER_PAYLOAD: &[u8; 27] = b"lakearch/curation/unhide/v1";

/// Eingefrorene atomare Nutzlast des **Ersetzen**-Kuratierungs-Marker-Atoms
/// (§9.5). Exakt 28 Bytes ASCII; **niemals** ändern.
const CURATION_REPLACE_MARKER_PAYLOAD: &[u8; 28] = b"lakearch/curation/replace/v1";

/// Eingefrorene atomare Nutzlast des **Aktiv-Marker**-Atoms (§13): das
/// abschließende „Aktiv-Schreiben", das einen Mehr-Daten-Umbau gemeinsam sichtbar
/// macht (§13.1). Exakt 25 Bytes ASCII; **niemals** ändern. lakearch interpretiert
/// die Bytes **nicht** (§1.4) — der Wert ist nur eine wohlbekannte Konvention,
/// damit ein Marker-Daten als solches **erkennbar** ist (rein strukturell, §1.3).
/// Die §13-**Sichtbarkeits-Autorität** ist allein der Offset-Vergleich der
/// Log-Schicht (`marker_offset < W`), **nicht** dieses Atom.
const ACTIVE_MARKER_PAYLOAD: &[u8; 25] = b"lakearch/active-marker/v1";

/// Bereichs-Zugehörigkeit (§11.1) — „Zugehörigkeit ist ein Kontext".
///
/// **Konvention (§11.1/§1.3).** Ein **Bereich** ist ein gewöhnliches Daten; die
/// **Zugehörigkeit** eines Daten zu einem Bereich ist ein **Kontext**: ein
/// gewöhnlicher Knoten, der das eingefrorene
/// [`area_membership_marker`](Datum::area_membership_marker)-Atom **und** das
/// Bereichs-Daten besitzt — also exakt die zwei-elementige Menge
/// `{ Marker, Bereich }`. Besitzt ein Daten A einen solchen Zugehörigkeits-
/// Kontext, so gehört A dem Bereich an. Ein Daten darf **mehreren** Bereichen
/// angehören (§11.1), indem es mehrere solcher Kontexte besitzt.
///
/// **Reines strukturelles Matching (§1.3).** Das Tor (§11) liest diese Struktur
/// nur (es validiert/wertet **nicht**, §1.4): „besitzt der Kontext das
/// Marker-Atom und genau ein weiteres Daten (den Bereich)?". Die schreibende
/// Schicht (§7.2) baut die Zugehörigkeits-Kontexte; der Kernel materialisiert
/// sie nicht.
impl Datum {
    /// Das eingefrorene **Marker-Atom** „Bereichs-Zugehörigkeit" (§11.1) — ein
    /// gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast.
    ///
    /// Die Nutzlast ist exakt der ASCII-String `lakearch/area-membership/v1`; sie
    /// ist **eingefroren** (eine Änderung verschöbe die Marker-`ContentId` und
    /// damit die Erkennbarkeit aller Zugehörigkeiten). lakearch interpretiert die
    /// Bytes **nicht** (§1.4); der Wert ist allein eine wohlbekannte,
    /// föderationsweit gleiche Konvention (gleiche Bytes ⇒ gleiche `ContentId`,
    /// §5.3/§12.3).
    pub fn area_membership_marker() -> Self {
        Datum::leaf(*AREA_MEMBERSHIP_MARKER_PAYLOAD)
    }

    /// Erzeugt einen **Zugehörigkeits-Kontext** (§11.1): ein Knoten, der das
    /// [`area_membership_marker`](Datum::area_membership_marker)-Atom **und** das
    /// Bereichs-Daten `area` besitzt — die zwei-elementige Menge `{ Marker, area }`.
    ///
    /// Die schreibende Schicht hängt diesen Kontext als besessenen Kontext an das
    /// Daten, das dem Bereich angehören soll. Reine Struktur (§1.3); keine Wertung.
    pub fn area_membership(area: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::area_membership_marker());
        // `node` dedupliziert; Marker und Bereich sind nur dann gleich, wenn der
        // „Bereich" selbst das Marker-Atom wäre — eine entartete Eingabe, die der
        // Kernel **nicht** validiert (§1.4). `expect` ist sicher: der Marker ist
        // stets in der Menge, also nie leer (§K2.1).
        Datum::node([marker, area]).expect("Zugehörigkeit besitzt stets das Marker-Atom (§11.1)")
    }

    /// Liefert das **Bereichs-Daten**, falls dieser Knoten ein
    /// **Zugehörigkeits-Kontext** ist (§11.1) — also exakt `{ Marker, Bereich }`
    /// besitzt; sonst `None`. Reines strukturelles Matching (§1.3): „besitzt der
    /// Knoten das Marker-Atom und genau ein weiteres Daten?". Keine Wertung (§1.4).
    ///
    /// Ein Blatt, ein Knoten ohne den Marker oder ein Knoten mit ≠ 2 Kontexten ist
    /// **kein** Zugehörigkeits-Kontext (`None`).
    pub fn area_membership_target(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::area_membership_marker());
        let owns = self.owns()?;
        // Genau zwei Kontexte, einer davon der Marker; der andere ist der Bereich.
        if owns.len() != 2 {
            return None;
        }
        if owns[0] == marker {
            Some(owns[1])
        } else if owns[1] == marker {
            Some(owns[0])
        } else {
            None
        }
    }
}

/// Berechtigung & Entzug (§11.1/§11.4) — **rein strukturelle Konvention** (§1.3),
/// auditierbar als gewöhnliche Daten.
///
/// **Beschreibung (§11.1).** Eine **Berechtigung** ist ein Daten mit Kontexten
/// *Subjekt, Bereich, Recht, …*. Der Kernel muss aus einer Berechtigung **rein
/// strukturell** (ohne Ordnung/Wertung, §1.4) das Paar *(Subjekt, Bereich)*
/// ablesen können. Da die `owns`-Menge adress-sortiert ist (§K2.3), trägt die
/// **Position** keine Bedeutung; Rollen werden daher über eigene **rollen-getaggte
/// Kontexte** ausgedrückt — genau wie die Zugehörigkeit (§11.1) ein
/// `{ Marker, Bereich }`-Knoten ist:
///
/// - ein **Subjekt-Rollen-Kontext** = Knoten `{ subject_role_marker, subject }`,
/// - ein **Bereichs-Rollen-Kontext** = Knoten `{ area_role_marker, area }`,
/// - dazu das Top-Level-Marker-Atom [`Datum::permission_marker`], das den ganzen
///   Knoten als Berechtigung ausweist.
///
/// Eine Berechtigung ist also der Knoten, der **diese drei** Kontexte besitzt
/// (`{ permission_marker, subject_role_ctx, area_role_ctx }`). Weitere Kontexte
/// (Recht, Zeit, Urheber, §11.1) dürfen hinzukommen, ohne die strukturelle
/// Ablesbarkeit von *(Subjekt, Bereich)* zu stören; der Kernel **wertet sie nicht**
/// (§1.4) — er liest nur Subjekt und Bereich.
///
/// **Entzug (§11.4/§6.3).** Ein **Entzug** ist ein neuer Kontext, der eine
/// bestehende Berechtigung als überholt markiert (append-only, §6.3 — nie
/// gelöscht). Strukturell: ein Knoten `{ revocation_marker, permission_id }`, der
/// auf die `ContentId` der entzogenen Berechtigung zeigt. „Aktiv" ist damit eine
/// **strukturelle** Notion (§11.5): aktiv ist eine Berechtigung, die im Snapshot
/// vorliegt **und** von keinem Entzugs-Kontext im Snapshot benannt wird — **kein**
/// Wall-Clock-Vergleich (das wäre Ordnung → §1.4-Verstoß). Welche Berechtigung für
/// einen *Zeitpunkt* gilt, ist eine Lese-Projektion der Schicht darüber (§6.4/§8.2).
impl Datum {
    /// Das eingefrorene **Subjekt-Rollen-Marker-Atom** einer Berechtigung (§11.1).
    pub fn permission_subject_marker() -> Self {
        Datum::leaf(*PERMISSION_SUBJECT_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Bereichs-Rollen-Marker-Atom** einer Berechtigung (§11.1).
    pub fn permission_area_marker() -> Self {
        Datum::leaf(*PERMISSION_AREA_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Berechtigungs-Marker-Atom** (§11.1) — weist einen Knoten
    /// als Berechtigung aus.
    pub fn permission_marker() -> Self {
        Datum::leaf(*PERMISSION_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Entzugs-Marker-Atom** (§11.4).
    pub fn revocation_marker() -> Self {
        Datum::leaf(*REVOCATION_MARKER_PAYLOAD)
    }

    /// Erzeugt einen **Subjekt-Rollen-Kontext** `{ subject_role_marker, subject }`
    /// (§11.1) — der besessene Kontext einer Berechtigung, der ihr Subjekt trägt.
    pub fn permission_subject_role(subject: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::permission_subject_marker());
        Datum::node([marker, subject])
            .expect("Subjekt-Rollen-Kontext besitzt stets das Marker-Atom (§11.1)")
    }

    /// Erzeugt einen **Bereichs-Rollen-Kontext** `{ area_role_marker, area }`
    /// (§11.1) — der besessene Kontext einer Berechtigung, der ihren Bereich trägt.
    pub fn permission_area_role(area: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::permission_area_marker());
        Datum::node([marker, area])
            .expect("Bereichs-Rollen-Kontext besitzt stets das Marker-Atom (§11.1)")
    }

    /// Erzeugt eine **Berechtigung** (§11.1): der Knoten, der das
    /// [`permission_marker`](Datum::permission_marker)-Atom, den
    /// **Subjekt-Rollen-Kontext** (`subject`) und den **Bereichs-Rollen-Kontext**
    /// (`area`) besitzt. Die schreibende Schicht hängt — vor dem Bau dieser
    /// Berechtigung — die beiden Rollen-Kontexte selbst an (sie sind besessene
    /// Daten, §3.1); ihre `ContentId`s ergeben sich aus
    /// [`Datum::permission_subject_role`]/[`Datum::permission_area_role`].
    ///
    /// Reine Struktur (§1.3); keine Wertung (§1.4). Der Kernel materialisiert die
    /// Berechtigung nicht — er liest sie nur (§11.2).
    pub fn permission(subject: ContentId, area: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::permission_marker());
        let subject_role = ContentId::of_datum(&Datum::permission_subject_role(subject));
        let area_role = ContentId::of_datum(&Datum::permission_area_role(area));
        Datum::node([marker, subject_role, area_role])
            .expect("Berechtigung besitzt stets das Marker-Atom (§11.1)")
    }

    /// Erzeugt einen **Entzug** (§11.4): der Knoten `{ revocation_marker,
    /// permission }`, der die Berechtigung mit `ContentId` `permission` als überholt
    /// markiert (append-only, §6.3). Künftige Lesevorgänge filtern die entzogene
    /// Berechtigung (§11.4); bereits Gelesenes bleibt.
    pub fn revocation(permission: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::revocation_marker());
        Datum::node([marker, permission])
            .expect("Entzug besitzt stets das Marker-Atom (§11.4)")
    }

    /// Liest aus dem Rollen-Kontext `{ role_marker, target }` das **Ziel** `target`
    /// (Subjekt bzw. Bereich) — reines strukturelles Matching (§1.3): „besitzt der
    /// Knoten genau zwei Kontexte, einer davon `role_marker`?". Sonst `None`.
    fn role_target(&self, role_marker: ContentId) -> Option<ContentId> {
        let owns = self.owns()?;
        if owns.len() != 2 {
            return None;
        }
        if owns[0] == role_marker {
            Some(owns[1])
        } else if owns[1] == role_marker {
            Some(owns[0])
        } else {
            None
        }
    }

    /// Liest *(Subjekt, Bereich)* aus einer **Berechtigung** (§11.1), falls dieser
    /// Knoten eine ist — also das Berechtigungs-Marker-Atom **und** je einen
    /// Subjekt- und Bereichs-Rollen-Kontext besitzt; sonst `None`. Reines
    /// strukturelles Matching (§1.3): die `owns`-Kontexte werden über
    /// [`role_target`](Datum::role_target) aufgelöst — **aber** ein Rollen-Kontext
    /// ist selbst ein besessenes Daten, dessen Inhalt erst aufgelöst werden muss;
    /// daher nimmt diese Methode einen `resolve`-Closure entgegen, der eine
    /// `ContentId` zu ihrem [`Datum`] auflöst (der Store liefert ihn). Fehlt ein
    /// Rollen-Kontext im Store (Geschlossenheit ist Sache der schreibenden Schicht,
    /// §3.6), liefert die Methode `None` (keine Wertung, §1.4).
    pub fn permission_subject_area<F>(&self, mut resolve: F) -> Option<(ContentId, ContentId)>
    where
        F: FnMut(ContentId) -> Option<Datum>,
    {
        let owns = self.owns()?;
        let perm_marker = ContentId::of_datum(&Datum::permission_marker());
        if owns.binary_search(&perm_marker).is_err() {
            return None;
        }
        let subj_marker = ContentId::of_datum(&Datum::permission_subject_marker());
        let area_marker = ContentId::of_datum(&Datum::permission_area_marker());
        let mut subject = None;
        let mut area = None;
        for ctx_id in owns {
            if *ctx_id == perm_marker {
                continue;
            }
            let ctx = match resolve(*ctx_id) {
                Some(c) => c,
                None => continue, // fehlender Rollen-Kontext: überspringen (§3.6/§1.4).
            };
            if let Some(s) = ctx.role_target(subj_marker) {
                subject = Some(s);
            } else if let Some(a) = ctx.role_target(area_marker) {
                area = Some(a);
            }
        }
        match (subject, area) {
            (Some(s), Some(a)) => Some((s, a)),
            _ => None,
        }
    }

    /// Liest aus einem **Entzug** (§11.4) die `ContentId` der entzogenen
    /// Berechtigung, falls dieser Knoten ein Entzug ist — also exakt
    /// `{ revocation_marker, permission }` besitzt; sonst `None`. Reines
    /// strukturelles Matching (§1.3).
    pub fn revocation_target(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::revocation_marker());
        self.role_target(marker)
    }
}

/// Zeit als Daten (§6) — **rein strukturelle Konvention** (§1.3), die der Kernel
/// **niemals** interpretiert, ordnet, vergleicht oder bereichs-testet.
///
/// **TIME IS DATA (§6.1).** Zeitpunkte und Zeiträume sind **gewöhnliche** Daten;
/// eine **Zeit-Aussage** ist ein **besonderer Kontext**. Der **Zeit-Wert** selbst
/// (z. B. ein Blatt mit den Zeit-Bytes) ist ein **opakes** Daten: lakearch sieht
/// ihn als Bytes (§1.4) und **parst/ordnet/vergleicht ihn nie**.
///
/// **Zwei Achsen (§6.2).** Es gibt **zwei** Zeitachsen, ausgedrückt über zwei
/// eingefrorene, **verschiedene** Achsen-Marker-Atome:
///
/// - **Aufzeichnungszeit** ([`Datum::recording_time_marker`]) — wann das System
///   den Sachverhalt **erfuhr**.
/// - **Gültigkeitszeit** ([`Datum::validity_time_marker`]) — wann der Sachverhalt
///   **in der Welt gilt**.
///
/// Ein Daten **darf beide** tragen; die Achsen **dürfen auseinanderfallen** (§6.2)
/// — sie sind strukturell **distinkt und unabhängig** (verschiedene Marker ⇒
/// verschiedene Kontext-`ContentId`s). Eine **Zeit-Aussage** ist — analog zur
/// Zugehörigkeit (§11.1) und zum Ersetzungs-Kontext (§6.3) — der Knoten
/// `{ Achsen-Marker, Zeit-Wert }`. Die schreibende Schicht hängt einen solchen
/// Kontext als besessenen Kontext an das Daten, dessen Zeit auf der jeweiligen
/// Achse er aussagt.
///
/// **HARTE GRENZE (§1.4/§6.4/§8.2).** Der Kernel stellt **ausschließlich** bereit:
/// Zeit **als Daten speichern**, Zeit-Aussage-Kontexte für den **strukturellen
/// LOOKUP** indizieren (Exakt-Match/Mitgliedschaft, §1.3 — **keine** geordneten
/// Bereichs-Abfragen) und **strukturell traversieren**. Der Kernel
/// **interpretiert, ordnet, vergleicht** den Zeit-Wert **nicht** und entscheidet
/// **nicht** „welche Version gilt zum Zeitpunkt T" oder „neueste gewinnt" — eine
/// „Version" ist eine **Leseregel** (§6.4) der Schicht **darüber** (§8). **Kein**
/// Verb dieses Moduls nimmt eine Zeit entgegen und liefert „die aktive" zurück;
/// **keine** Funktion vergleicht zwei Zeit-Werte.
impl Datum {
    /// Das eingefrorene **Aufzeichnungszeit**-Achsen-Marker-Atom (§6.2) — ein
    /// gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast. lakearch
    /// interpretiert die Bytes **nicht** (§1.4); der Wert ist allein eine
    /// wohlbekannte, föderationsweit gleiche Konvention (gleiche Bytes ⇒ gleiche
    /// `ContentId`, §5.3/§12.3).
    pub fn recording_time_marker() -> Self {
        Datum::leaf(*RECORDING_TIME_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Gültigkeitszeit**-Achsen-Marker-Atom (§6.2) — ein
    /// gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast. Bewusst
    /// **verschieden** vom Aufzeichnungszeit-Marker, sodass die beiden Achsen
    /// strukturell **distinkt** sind (§6.2: sie dürfen auseinanderfallen).
    pub fn validity_time_marker() -> Self {
        Datum::leaf(*VALIDITY_TIME_MARKER_PAYLOAD)
    }

    /// Erzeugt eine **Aufzeichnungszeit-Aussage** (§6.1/§6.2): der Kontext-Knoten
    /// `{ recording_time_marker, time_value }`, der den **opaken** Zeit-Wert
    /// `time_value` als Aufzeichnungszeit ausweist.
    ///
    /// `time_value` ist die `ContentId` eines **gewöhnlichen** Zeit-Wert-Daten
    /// (z. B. ein Blatt mit den Zeit-Bytes, [`Datum::leaf`]); der Kernel
    /// **interpretiert/ordnet/vergleicht** ihn **nicht** (§1.4/§6.4). Die
    /// schreibende Schicht hängt den zurückgegebenen Kontext an das Daten, dessen
    /// Aufzeichnungszeit er aussagt.
    pub fn recording_time(time_value: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::recording_time_marker());
        Datum::node([marker, time_value])
            .expect("Zeit-Aussage besitzt stets das Achsen-Marker-Atom (§6.2)")
    }

    /// Erzeugt eine **Gültigkeitszeit-Aussage** (§6.1/§6.2): der Kontext-Knoten
    /// `{ validity_time_marker, time_value }`, der den **opaken** Zeit-Wert
    /// `time_value` als Gültigkeitszeit ausweist. Wie [`Datum::recording_time`]
    /// ist `time_value` opak (§1.4/§6.4).
    pub fn validity_time(time_value: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::validity_time_marker());
        Datum::node([marker, time_value])
            .expect("Zeit-Aussage besitzt stets das Achsen-Marker-Atom (§6.2)")
    }

    /// Liest aus einer **Aufzeichnungszeit-Aussage** (§6.2) die `ContentId` des
    /// **opaken** Zeit-Werts, falls dieser Knoten eine ist — also exakt
    /// `{ recording_time_marker, time_value }` besitzt; sonst `None`. Reines
    /// strukturelles Matching (§1.3): „besitzt der Knoten das Achsen-Marker-Atom
    /// und genau ein weiteres Daten (den Zeit-Wert)?".
    ///
    /// Der zurückgegebene Wert ist **nur eine Adresse** (§5.2); der Kernel **parst
    /// und vergleicht** den Zeit-Wert **nicht** (§1.4/§6.4) — das Ordnen/Vergleichen
    /// liegt in der Schicht darüber (§8).
    pub fn recording_time_value(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::recording_time_marker());
        self.role_target(marker)
    }

    /// Liest aus einer **Gültigkeitszeit-Aussage** (§6.2) die `ContentId` des
    /// **opaken** Zeit-Werts, falls dieser Knoten eine ist; sonst `None`. Wie
    /// [`Datum::recording_time_value`] reines strukturelles Matching (§1.3); der
    /// Kernel **parst/vergleicht** den Wert **nicht** (§1.4/§6.4).
    pub fn validity_time_value(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::validity_time_marker());
        self.role_target(marker)
    }
}

/// Ersetzung (§6.3) — **append-only**, **rein strukturelle Konvention** (§1.3).
///
/// **Ersetzungs-Kontext (§6.3).** Neues Wissen kommt als **neues** Daten hinzu;
/// ein **Ersetzungs-Kontext** verknüpft ein **NEUERES** Daten mit dem **ÄLTEREN**,
/// das es überholt — **ohne** das Ältere je zu ändern oder zu löschen (§7.1). Der
/// Ersetzungs-Kontext ist — analog zur Zugehörigkeit (§11.1) — der Knoten
/// `{ supersession_marker, older }`, der auf die `ContentId` des überholten
/// (älteren) Daten zeigt. Das **neuere** Daten **besitzt** diesen Kontext.
///
/// **Beide Richtungen traversierbar.** Weil das neuere Daten den Ersetzungs-
/// Kontext besitzt und dieser auf das ältere zeigt, entstehen über die bestehenden
/// Indizes (`owner→contexts` / `target→referrers`, §1.2/§10.3) automatisch
/// **beide** Richtungen: *supersedes* (neuer → älter, vorwärts über den Kontext)
/// und *superseded-by* (älter → neuer, rückwärts). Der Kernel **verknüpft** und
/// **traversiert** nur (§1.2/§1.3).
///
/// **GRENZE (§6.4/§8).** Welches Daten „aktuell" ist, entscheidet der Kernel
/// **nicht** — „eine Version ist eine **Leseregel**" (§6.4) der Schicht darüber
/// (§8). „Neuester Offset gewinnt" gibt es **nicht** (§Append-Order-Semantik); die
/// Leseseite wählt aus den expliziten Ersetzungs-/Zeit-Kontexten.
impl Datum {
    /// Das eingefrorene **Ersetzungs**-Marker-Atom (§6.3) — ein gewöhnliches
    /// Blatt-Daten (§2.1) mit fester atomarer Nutzlast.
    pub fn supersession_marker() -> Self {
        Datum::leaf(*SUPERSESSION_MARKER_PAYLOAD)
    }

    /// Erzeugt einen **Ersetzungs-Kontext** (§6.3): der Knoten
    /// `{ supersession_marker, older }`, der das überholte (ältere) Daten mit
    /// `ContentId` `older` benennt. Das **neuere** Daten **besitzt** diesen Kontext
    /// (die schreibende Schicht hängt ihn an, §7.2) — so wird das Ältere als
    /// überholt markiert, **ohne** es je zu ändern oder zu löschen (§7.1).
    ///
    /// Reine Struktur (§1.3); keine Wertung (§1.4). Der Kernel entscheidet **nicht**,
    /// welches Daten „aktuell" ist (§6.4/§8).
    pub fn supersedes(older: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::supersession_marker());
        Datum::node([marker, older])
            .expect("Ersetzungs-Kontext besitzt stets das Marker-Atom (§6.3)")
    }

    /// Liest aus einem **Ersetzungs-Kontext** (§6.3) die `ContentId` des überholten
    /// (älteren) Daten, falls dieser Knoten ein Ersetzungs-Kontext ist — also exakt
    /// `{ supersession_marker, older }` besitzt; sonst `None`. Reines strukturelles
    /// Matching (§1.3): „besitzt der Knoten das Marker-Atom und genau ein weiteres
    /// Daten?". Keine Wertung (§1.4); **kein** Vergleich/keine Ordnung der Daten.
    pub fn supersedes_target(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::supersession_marker());
        self.role_target(marker)
    }
}

/// Die **Stärke** einer gradierten referenziellen Identität (§5.5) — eine
/// **Familie** von Identitäts-Kontexten *unterschiedlicher Stärke*. Jede Variante
/// entspricht genau **einem** eingefrorenen Stärke-Marker-Atom.
///
/// **HARTE GRENZE (§5.5/§9-Präambel/§1.4).** Diese Aufzählung ist eine reine
/// **strukturelle Etikette** — sie trägt **keine** Ordnung, kein Gewicht, keine
/// Schwelle. Der Kernel **vergleicht, ordnet, schwellt** Stärken **niemals** und
/// entscheidet **nie**, welche Repräsentanten „wirklich" zusammengehören. Welche
/// Stärke wie zu werten ist, liegt **ausschließlich** in der Schicht darüber
/// (§1.4/§1.5). `lakearch` **speichert und traversiert** sie nur. Bewusst wird
/// **kein** `PartialOrd`/`Ord` abgeleitet (eine Ordnung wäre ein §1.4-Verstoß).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdentityStrength {
    /// *deckungsgleich* (§5.5) — die Daten beschreiben dasselbe Ding deckungsgleich.
    Deckungsgleich,
    /// *ergänzt* (§5.5) — das eine Daten ergänzt das andere.
    Ergaenzt,
    /// *widerspricht-in* (§5.5) — die Daten widersprechen sich (in Attributen).
    WidersprichtIn,
    /// *verwandt-mit* (§5.5) — die Daten sind verwandt.
    VerwandtMit,
    /// *bekannt-verschieden* (§5.5) — die Daten sind bekannt **verschieden**.
    BekanntVerschieden,
}

impl IdentityStrength {
    /// Die eingefrorene atomare Nutzlast des zur Stärke gehörenden Marker-Atoms
    /// (§5.5). Reine Konvention (gleiche Bytes ⇒ gleiche `ContentId`, §5.3/§12.3);
    /// lakearch interpretiert die Bytes **nicht** (§1.4).
    fn marker_payload(self) -> &'static [u8] {
        match self {
            IdentityStrength::Deckungsgleich => IDENT_DECKUNGSGLEICH_PAYLOAD,
            IdentityStrength::Ergaenzt => IDENT_ERGAENZT_PAYLOAD,
            IdentityStrength::WidersprichtIn => IDENT_WIDERSPRICHT_IN_PAYLOAD,
            IdentityStrength::VerwandtMit => IDENT_VERWANDT_MIT_PAYLOAD,
            IdentityStrength::BekanntVerschieden => IDENT_BEKANNT_VERSCHIEDEN_PAYLOAD,
        }
    }

    /// Liste **aller** Stärke-Varianten (§5.5) — für strukturelles Rück-Matching
    /// (welche Stärke trägt ein Identitäts-Kontext?). **Keine** Ordnung impliziert
    /// (§1.4); die Reihenfolge ist allein Aufzählungs-Bequemlichkeit.
    fn all() -> [IdentityStrength; 5] {
        [
            IdentityStrength::Deckungsgleich,
            IdentityStrength::Ergaenzt,
            IdentityStrength::WidersprichtIn,
            IdentityStrength::VerwandtMit,
            IdentityStrength::BekanntVerschieden,
        ]
    }
}

/// Anker & Mitgliedschaft (§9.1/§9.3) — **append-only**, **rein strukturelle
/// Konvention** (§1.3), die der Kernel **niemals** auflöst, rankt oder entscheidet.
///
/// **Repräsentantensystem (§9.1).** Tragen mehrere Daten dieselbe referenzielle
/// Identität, existiert ein **eigenes Anker-Daten** (die Klasse). Der Anker ist ein
/// **gewöhnliches** inhaltsadressiertes Daten (§2.1: er hat eine `ContentId` wie
/// alles andere); sein bestand-**lokaler** Auflösungs-Handle für §12.4 ist die
/// [`crate::id::AnchorId`] — sie ist **nie** die alleinige Identität des Ankers.
/// Strukturell ist der Anker ein Knoten, der das eingefrorene
/// [`anchor_marker`](Datum::anchor_marker)-Atom besitzt (er weist sich damit als
/// Klasse aus).
///
/// **Mitgliedschaft (§9.1/§9.3).** Die Repräsentanten verweisen per
/// **Mitgliedschafts-Kontext** auf den **Anker** (§9.2: anderes verweist auf den
/// Anker, nie auf einen einzelnen Repräsentanten). Mitgliedschaft ist **gradiert
/// und revidierbar** — ein **Kontext**, **kein** destruktiver Zusammenschluss
/// (§9.3). Strukturell ist sie der Knoten `{ membership_marker, anchor,
/// grade_ctx }`: er benennt den Anker und trägt einen **Grad-Sub-Kontext**
/// (`{ grade_marker, grade_value }`), dessen Grad-**Wert** ein **opakes** Daten ist.
///
/// **HARTE GRENZE (§9-Präambel/§1.4).** Der Kernel **hält** diese Strukturen; das
/// **Auflösen** (Schwellen, Entscheidungen, „welcher Repräsentant gewinnt") liegt
/// **ausschließlich** in der Schicht darüber (§1.5). Der Kernel **berechnet,
/// vergleicht, schwellt** den Grad **niemals** und **entscheidet keine
/// Mitgliedschaft** — er **speichert und traversiert** nur (§1.3). Eine **Revision**
/// der Mitgliedschaft ist ein **ersetzender** Kontext (§9.3/§6.3: Phase-3-Ersetzung),
/// **nie** eine Löschung; ein **Split** (§9.4) entsteht durch neue Kontexte, die alte
/// ersetzen — betroffene Repräsentanten werden zu einem neuen Anker **re-verwiesen**
/// (append-only, §7.1). Ein Repräsentant wird **niemals** in den Anker umgewandelt
/// (§9.2).
impl Datum {
    /// Das eingefrorene **Anker-Rollen**-Marker-Atom (§9.1) — ein gewöhnliches
    /// Blatt-Daten (§2.1) mit fester atomarer Nutzlast.
    pub fn anchor_marker() -> Self {
        Datum::leaf(*ANCHOR_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Mitgliedschafts**-Marker-Atom (§9.3).
    pub fn membership_marker() -> Self {
        Datum::leaf(*MEMBERSHIP_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Grad-Rollen**-Marker-Atom einer Mitgliedschaft (§9.3).
    pub fn membership_grade_marker() -> Self {
        Datum::leaf(*MEMBERSHIP_GRADE_MARKER_PAYLOAD)
    }

    /// Erzeugt ein **Anker-Daten** (§9.1): ein Knoten, der das
    /// [`anchor_marker`](Datum::anchor_marker)-Atom **und** beliebige weitere
    /// `payload`-Kontexte besitzt (etwa ein die Klasse benennendes Daten). Der Anker
    /// ist ein **gewöhnliches** inhaltsadressiertes Daten (§2.1) mit eigener
    /// `ContentId`; `payload` darf leer sein (dann ist der Anker „nur als Klasse
    /// markiert").
    ///
    /// Gibt **immer** `Some` zurück: das Marker-Atom ist stets in der Menge, ein
    /// Anker ist also nie der leere (nicht wohlgeformte) Knoten (§K2.1).
    ///
    /// Reine Struktur (§1.3); keine Wertung (§1.4). Der Kernel **entscheidet keine
    /// Identität** (§9-Präambel) — er hält nur die Klasse.
    pub fn anchor(payload: impl IntoIterator<Item = ContentId>) -> Self {
        let marker = ContentId::of_datum(&Datum::anchor_marker());
        let owns = core::iter::once(marker).chain(payload);
        Datum::node(owns).expect("Anker besitzt stets das Marker-Atom (§9.1)")
    }

    /// `true`, wenn dieser Knoten das eingefrorene Anker-Rollen-Marker-Atom besitzt
    /// — also ein **Anker-Daten** ist (§9.1). Reines strukturelles Matching (§1.3):
    /// „besitzt der Knoten den Anker-Marker-Kontext?". Ein Blatt ist nie ein Anker.
    pub fn is_anchor(&self) -> bool {
        let marker = ContentId::of_datum(&Datum::anchor_marker());
        match self.owns() {
            Some(owns) => owns.binary_search(&marker).is_ok(),
            None => false,
        }
    }

    /// Erzeugt einen **Grad-Sub-Kontext** `{ grade_marker, grade_value }` (§9.3) —
    /// der Kontext, der den (opaken) Grad einer Mitgliedschaft trägt. `grade_value`
    /// ist die `ContentId` eines **gewöhnlichen** Grad-Wert-Daten (z. B. ein Blatt
    /// mit opaken Konfidenz-Bytes); der Kernel **interpretiert/vergleicht/schwellt**
    /// ihn **nie** (§1.4/§9-Präambel).
    pub fn membership_grade(grade_value: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::membership_grade_marker());
        Datum::node([marker, grade_value])
            .expect("Grad-Sub-Kontext besitzt stets das Marker-Atom (§9.3)")
    }

    /// Liest aus einem **Grad-Sub-Kontext** (§9.3) die `ContentId` des **opaken**
    /// Grad-Werts, falls dieser Knoten einer ist — also exakt
    /// `{ grade_marker, grade_value }` besitzt; sonst `None`. Reines strukturelles
    /// Matching (§1.3). Der zurückgegebene Wert ist **nur eine Adresse** (§5.2); der
    /// Kernel **vergleicht/schwellt** den Grad **nie** (§1.4/§9-Präambel).
    pub fn membership_grade_value(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::membership_grade_marker());
        self.role_target(marker)
    }

    /// Erzeugt einen **Mitgliedschafts-Kontext** (§9.1/§9.3): der Knoten
    /// `{ membership_marker, anchor, grade_ctx }`, der einen Repräsentanten per
    /// Kontext auf den **Anker** verweist (§9.2) und einen **Grad-Sub-Kontext**
    /// trägt (§9.3). Das **Repräsentanten-Daten besitzt** diesen Kontext (die
    /// schreibende Schicht hängt ihn an, §7.2) — so verweist der Repräsentant auf
    /// den Anker.
    ///
    /// - `anchor` — die `ContentId` des Anker-Daten (§9.1), auf das verwiesen wird.
    /// - `grade_value` — die `ContentId` des **opaken** Grad-Werts (§9.3); der
    ///   Grad-Sub-Kontext [`membership_grade`](Datum::membership_grade) ist ein
    ///   **besessenes** Daten der Mitgliedschaft (die schreibende Schicht hängt auch
    ///   ihn an).
    ///
    /// Mitgliedschaft ist **gradiert und revidierbar** — ein **Kontext**, **kein**
    /// destruktiver Zusammenschluss (§9.3). Reine Struktur (§1.3); keine Wertung
    /// (§1.4). Der Kernel **entscheidet keine Mitgliedschaft** und **wertet den Grad
    /// nicht** (§9-Präambel).
    pub fn membership(anchor: ContentId, grade_value: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::membership_marker());
        let grade_ctx = ContentId::of_datum(&Datum::membership_grade(grade_value));
        Datum::node([marker, anchor, grade_ctx])
            .expect("Mitgliedschaft besitzt stets das Marker-Atom (§9.3)")
    }

    /// Liest aus einem **Mitgliedschafts-Kontext** (§9.1/§9.3) die `ContentId` des
    /// **Ankers**, falls dieser Knoten eine Mitgliedschaft ist — also das
    /// Mitgliedschafts-Marker-Atom **und** genau zwei weitere Kontexte (Anker +
    /// Grad-Sub-Kontext) besitzt; sonst `None`. Reines strukturelles Matching
    /// (§1.3): die `owns`-Kontexte werden über den `resolve`-Closure aufgelöst, um
    /// den **Grad-Sub-Kontext** vom **Anker** zu unterscheiden (der Grad-Sub-Kontext
    /// ist ein Knoten `{ grade_marker, … }`, der Anker das übrige Daten).
    ///
    /// Fehlt der Grad-Sub-Kontext im Store (Geschlossenheit ist Sache der
    /// schreibenden Schicht, §3.6), liefert die Methode `None` (keine Wertung, §1.4).
    /// Der Kernel **verweist** nur strukturell auf den Anker; er **entscheidet keine
    /// Mitgliedschaft** (§9-Präambel).
    pub fn membership_anchor<F>(&self, mut resolve: F) -> Option<ContentId>
    where
        F: FnMut(ContentId) -> Option<Datum>,
    {
        let owns = self.owns()?;
        let membership_marker = ContentId::of_datum(&Datum::membership_marker());
        if owns.binary_search(&membership_marker).is_err() {
            return None;
        }
        // Genau drei Kontexte: Marker, Anker, Grad-Sub-Kontext (§9.3).
        if owns.len() != 3 {
            return None;
        }
        let mut anchor = None;
        for ctx_id in owns {
            if *ctx_id == membership_marker {
                continue;
            }
            // Der Grad-Sub-Kontext ist ein Knoten `{ grade_marker, … }`; alles andere
            // ist der Anker. Fehlt das besessene Daten, überspringen (§3.6/§1.4).
            match resolve(*ctx_id) {
                Some(ctx) if ctx.membership_grade_value().is_some() => continue,
                _ => {
                    if anchor.is_some() {
                        // Mehr als ein Nicht-Grad-Kontext ⇒ keine eindeutige
                        // Mitgliedschaft (reines Matching, keine Wertung §1.4).
                        return None;
                    }
                    anchor = Some(*ctx_id);
                }
            }
        }
        anchor
    }

    /// Liest aus einem **Mitgliedschafts-Kontext** (§9.3) die `ContentId` des
    /// **Grad-Sub-Kontextes**, falls dieser Knoten eine Mitgliedschaft ist — also
    /// das Mitgliedschafts-Marker-Atom besitzt und genau einen der besessenen
    /// Kontexte ein Grad-Sub-Kontext (`{ grade_marker, … }`) ist; sonst `None`.
    /// Reines strukturelles Matching (§1.3); der Grad-**Wert** wird **nicht**
    /// verglichen/geschwellt (§1.4/§9-Präambel).
    pub fn membership_grade_context<F>(&self, mut resolve: F) -> Option<ContentId>
    where
        F: FnMut(ContentId) -> Option<Datum>,
    {
        let owns = self.owns()?;
        let membership_marker = ContentId::of_datum(&Datum::membership_marker());
        if owns.binary_search(&membership_marker).is_err() {
            return None;
        }
        for ctx_id in owns {
            if *ctx_id == membership_marker {
                continue;
            }
            if let Some(ctx) = resolve(*ctx_id) {
                if ctx.membership_grade_value().is_some() {
                    return Some(*ctx_id);
                }
            }
        }
        None
    }
}

/// Gradierte referenzielle Identität (§5.5) — eine **Familie** von Identitäts-
/// Kontexten unterschiedlicher **Stärke**, **rein strukturelle Konvention** (§1.3).
///
/// **§5.5.** Referenzielle Identität ist **gradiert**: *deckungsgleich, ergänzt,
/// widerspricht-in, verwandt-mit, bekannt-verschieden* (siehe [`IdentityStrength`]).
/// Jeder solche Identitäts-Kontext **trägt eigene Kontexte**: betroffene Attribute,
/// **Konfidenz**, Urheber, Zeit (§3.4 native Reifikation — Aussagen über Aussagen).
/// Strukturell ist ein Identitäts-Kontext der Knoten
/// `{ strength_marker, a, b, sub_ctx_1, …, sub_ctx_n }`: er nennt das Stärke-Marker-
/// Atom, die **zwei** Daten, zwischen denen die Identität gilt, und beliebige
/// **reifizierte Sub-Kontexte**.
///
/// **HARTE GRENZE (§5.5/§9-Präambel/§1.4).** Der Kernel **speichert und traversiert**
/// diese Kontexte; er **berechnet, vergleicht, schwellt** Konfidenz **niemals** und
/// **entscheidet nicht**, welche Daten „wirklich" dasselbe sind — das ist die Schicht
/// **darüber** (§1.4/§1.5). Eine reifizierte **Konfidenz** ist ein gewöhnlicher
/// Sub-Kontext mit einem **opaken** Konfidenz-Wert-Daten: er wird **gehalten**, **nie**
/// geordnet/verglichen.
impl Datum {
    /// Das eingefrorene **Stärke-Marker-Atom** einer gradierten Identität (§5.5) —
    /// ein gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast je
    /// [`IdentityStrength`].
    pub fn identity_strength_marker(strength: IdentityStrength) -> Self {
        Datum::leaf(strength.marker_payload().to_vec())
    }

    /// Erzeugt einen **gradierten Identitäts-Kontext** (§5.5) zwischen den Daten `a`
    /// und `b` mit der Stärke `strength` und beliebigen **reifizierten**
    /// `sub_contexts` (§3.4: betroffene Attribute, Konfidenz, Urheber, Zeit). Der
    /// Knoten besitzt das Stärke-Marker-Atom, `a`, `b` und alle `sub_contexts`.
    ///
    /// `sub_contexts` sind die `ContentId`s besessener Sub-Kontext-Daten (die
    /// schreibende Schicht hängt sie als besessene Daten an, §3.1); etwa ein
    /// **Konfidenz**-Sub-Kontext mit einem **opaken** Konfidenz-Wert. Der Kernel
    /// **vergleicht/schwellt** sie **nie** (§1.4/§5.5).
    ///
    /// Reine Struktur (§1.3); keine Wertung (§1.4). Der Kernel **entscheidet keine
    /// Identität** (§9-Präambel) — er hält den gradierten Kontext und traversiert ihn.
    pub fn graded_identity(
        a: ContentId,
        b: ContentId,
        strength: IdentityStrength,
        sub_contexts: impl IntoIterator<Item = ContentId>,
    ) -> Self {
        let marker = ContentId::of_datum(&Datum::identity_strength_marker(strength));
        let owns = [marker, a, b].into_iter().chain(sub_contexts);
        Datum::node(owns).expect("gradierter Identitäts-Kontext besitzt stets das Marker-Atom (§5.5)")
    }

    /// Liest die **Stärke** eines gradierten Identitäts-Kontextes (§5.5), falls
    /// dieser Knoten einen Stärke-Marker besitzt; sonst `None`. Reines strukturelles
    /// Matching (§1.3): „welches der eingefrorenen Stärke-Marker-Atome besitzt der
    /// Knoten?". **Keine** Ordnung/Wertung der Stärke (§1.4); ein Blatt trägt nie eine
    /// Stärke.
    pub fn identity_strength(&self) -> Option<IdentityStrength> {
        let owns = self.owns()?;
        for s in IdentityStrength::all() {
            let marker = ContentId::of_datum(&Datum::identity_strength_marker(s));
            if owns.binary_search(&marker).is_ok() {
                return Some(s);
            }
        }
        None
    }

    /// `true`, wenn dieser Knoten ein **gradierter Identitäts-Kontext** ist (§5.5) —
    /// also (genau) einen Stärke-Marker trägt. Reines strukturelles Matching (§1.3);
    /// **keine** Wertung der Stärke (§1.4).
    pub fn is_graded_identity(&self) -> bool {
        self.identity_strength().is_some()
    }

    /// Die **reifizierten Sub-Kontexte** eines gradierten Identitäts-Kontextes
    /// (§5.5/§3.4) — die besessenen Kontexte **abzüglich** des Stärke-Marker-Atoms.
    /// Owned, in kanonischer (aufsteigender) Adress-Order (§5.2/§1.4). `None`, wenn
    /// der Knoten kein gradierter Identitäts-Kontext ist.
    ///
    /// Darin liegen (per Konvention der schreibenden Schicht) `a`, `b` **und** die
    /// reifizierten Sub-Kontexte (betroffene Attribute, **Konfidenz**, Urheber, Zeit).
    /// Der Kernel **liest sie nur** strukturell (§1.3) — er **vergleicht/schwellt
    /// Konfidenz nie** (§1.4/§5.5). Das Aussondern von `a`/`b` vs. Sub-Kontexten ist
    /// Sache der Schicht darüber (sie kennt das Vokabular, §14).
    pub fn graded_identity_contexts(&self) -> Option<Vec<ContentId>> {
        let strength = self.identity_strength()?;
        let marker = ContentId::of_datum(&Datum::identity_strength_marker(strength));
        let owns = self.owns()?;
        Some(owns.iter().copied().filter(|c| *c != marker).collect())
    }
}

/// Kuratierung (§9.5) — **ausschließlich reversible** Kontexte (*verbergen,
/// ersetzen, Mitgliedschaft*); die **Leseseite filtert** sie. Es wird **nie**
/// gelöscht (physisches Entfernen ist Compaction, §15/Phase 8). **Rein strukturelle
/// Konvention** (§1.3).
///
/// **§9.5.** Kuratierung fügt nur **reversible** Kontexte hinzu. Hier sind das die
/// beiden curation-spezifischen:
///
/// - **Verbergen** ([`curation_hide`](Datum::curation_hide)) — ein **reversibler
///   Lese-Seiten-Filter** (analog zum Bereichs-Filter, §11.3): ein verborgenes Daten
///   **VANISHt** aus der gegateten Projektion. Es wird **nichts** gelöscht; der
///   Kontext ist append-only (§7.1) und durch ein **Aufheben** umkehrbar.
/// - **Aufheben des Verbergens** ([`curation_unhide`](Datum::curation_unhide)) — das
///   **reversierende** Gegenstück (§9.5): ein neuer, append-only Kontext, der ein
///   früheres Verbergen aufhebt. Nichts wird gelöscht (§7.1).
/// - **Ersetzen** ([`curation_replace`](Datum::curation_replace)) — ein reversibler
///   Ersetzungs-Hinweis der Kuratierung (§9.5), der ein Daten zugunsten eines anderen
///   zurückstellt; die **Leseseite** entscheidet, **ob** sie ihm folgt (§8).
///
/// **HARTE GRENZE (§9.5/§1.4).** Der Kernel **hält** diese Kontexte und stellt das
/// **Verbergen** als reversiblen **strukturellen Lese-Filter** bereit; die
/// **Read-Seite** (das Tor/die gegateten Helfer) wendet ihn an. Der Kernel **löscht
/// nie** (§7.1), **wertet nicht** (§1.4) und **entscheidet keine Identität**
/// (§9-Präambel).
impl Datum {
    /// Das eingefrorene **Verbergen**-Kuratierungs-Marker-Atom (§9.5).
    pub fn curation_hide_marker() -> Self {
        Datum::leaf(*CURATION_HIDE_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Aufheben-des-Verbergens**-Kuratierungs-Marker-Atom (§9.5).
    pub fn curation_unhide_marker() -> Self {
        Datum::leaf(*CURATION_UNHIDE_MARKER_PAYLOAD)
    }

    /// Das eingefrorene **Ersetzen**-Kuratierungs-Marker-Atom (§9.5).
    pub fn curation_replace_marker() -> Self {
        Datum::leaf(*CURATION_REPLACE_MARKER_PAYLOAD)
    }

    /// Erzeugt einen **Verbergen-Kontext** (§9.5): der Knoten
    /// `{ curation_hide_marker, target }`, der das Daten mit `ContentId` `target`
    /// für die **Leseseite** verbirgt — ein **reversibler** Filter (analog zum
    /// Bereichs-Filter, §11.3), der **nichts** löscht (§7.1). Ein späteres
    /// [`curation_unhide`](Datum::curation_unhide) hebt ihn auf.
    pub fn curation_hide(target: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::curation_hide_marker());
        Datum::node([marker, target])
            .expect("Verbergen-Kontext besitzt stets das Marker-Atom (§9.5)")
    }

    /// Erzeugt einen **Aufheben-Kontext** (§9.5): der Knoten
    /// `{ curation_unhide_marker, target }`, der ein früheres Verbergen des Daten
    /// `target` **reversiert** — ein neuer, append-only Kontext (§7.1), **keine**
    /// Löschung. Die **Leseseite** sieht `target` damit wieder.
    pub fn curation_unhide(target: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::curation_unhide_marker());
        Datum::node([marker, target])
            .expect("Aufheben-Kontext besitzt stets das Marker-Atom (§9.5)")
    }

    /// Erzeugt einen **Ersetzen-Kontext** der Kuratierung (§9.5): der Knoten
    /// `{ curation_replace_marker, replaced, replacement }`, der das Daten
    /// `replaced` zugunsten von `replacement` zurückstellt. **Reversibel** und
    /// append-only (§7.1); die **Leseseite** entscheidet, ob sie ihm folgt (§8).
    pub fn curation_replace(replaced: ContentId, replacement: ContentId) -> Self {
        let marker = ContentId::of_datum(&Datum::curation_replace_marker());
        Datum::node([marker, replaced, replacement])
            .expect("Ersetzen-Kontext besitzt stets das Marker-Atom (§9.5)")
    }

    /// Liest aus einem **Verbergen-Kontext** (§9.5) die `ContentId` des verborgenen
    /// Daten, falls dieser Knoten ein Verbergen-Kontext ist — also exakt
    /// `{ curation_hide_marker, target }` besitzt; sonst `None`. Reines strukturelles
    /// Matching (§1.3); keine Wertung (§1.4).
    pub fn curation_hide_target(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::curation_hide_marker());
        self.role_target(marker)
    }

    /// Liest aus einem **Aufheben-Kontext** (§9.5) die `ContentId` des Daten, dessen
    /// Verbergen aufgehoben wird, falls dieser Knoten ein Aufheben-Kontext ist —
    /// also exakt `{ curation_unhide_marker, target }` besitzt; sonst `None`. Reines
    /// strukturelles Matching (§1.3).
    pub fn curation_unhide_target(&self) -> Option<ContentId> {
        let marker = ContentId::of_datum(&Datum::curation_unhide_marker());
        self.role_target(marker)
    }

    /// Liest aus einem **Ersetzen-Kontext** der Kuratierung (§9.5) das Paar
    /// *(ersetztes, ersetzendes)* Daten, falls dieser Knoten ein Ersetzen-Kontext
    /// ist — also das `curation_replace_marker`-Atom **und** genau zwei weitere
    /// Kontexte besitzt; sonst `None`. Reines strukturelles Matching (§1.3): die
    /// Position trägt **keine** Bedeutung (`owns` ist adress-sortiert, §K2.3), daher
    /// kann der Kernel **nicht** strukturell entscheiden, welches der beiden das
    /// ersetzte bzw. ersetzende ist — er gibt sie **adress-sortiert** als Paar
    /// heraus; die **Schicht darüber** kennt das Vokabular und ordnet zu (§14).
    /// **Keine** Wertung (§1.4).
    pub fn curation_replace_targets(&self) -> Option<(ContentId, ContentId)> {
        let marker = ContentId::of_datum(&Datum::curation_replace_marker());
        let owns = self.owns()?;
        if owns.len() != 3 {
            return None;
        }
        if owns.binary_search(&marker).is_err() {
            return None;
        }
        let rest: Vec<ContentId> = owns.iter().copied().filter(|c| *c != marker).collect();
        match rest.as_slice() {
            [x, y] => Some((*x, *y)),
            _ => None,
        }
    }
}

/// Aktiv-Marker (§13) — das abschließende „Aktiv-Schreiben" eines Mehr-Daten-Umbaus.
///
/// **Konvention (§13.1/§1.3).** Ein Umbau, der **mehrere Daten** betrifft, wird durch
/// **ein einziges abschließendes Aktiv-Schreiben** gemeinsam sichtbar. Das
/// Marker-Daten ist ein gewöhnliches Daten (§2.1), das das eingefrorene
/// [`active_marker`](Datum::active_marker)-Atom besitzt (so ist es **strukturell
/// erkennbar**, §1.3) und optional weitere Kontexte trägt (z. B. die `ContentId`s der
/// Konstituenten als Audit/Herkunft — der Kernel **wertet sie nicht**, §1.4).
///
/// **Wichtig (§13).** Die Sichtbarkeits-**Autorität** ist allein der Offset-Vergleich
/// der Log-Schicht (jeder Konstituent trägt im Record-Header den `marker_offset`
/// seines regierenden Markers; sichtbar ⇔ `marker_offset < W`). Dieses Marker-**Atom**
/// ist **nur** die strukturelle Erkennbarkeit des Marker-Daten — **keine** zweite
/// Epoche, **kein** Wall-Clock (§1.4/§13).
impl Datum {
    /// Das eingefrorene **Aktiv-Marker-Atom** (§13) — ein gewöhnliches Blatt-Daten
    /// (§2.1) mit fester atomarer Nutzlast `lakearch/active-marker/v1` (eingefroren —
    /// eine Änderung verschöbe die Marker-`ContentId`). lakearch interpretiert die
    /// Bytes **nicht** (§1.4); der Wert ist eine wohlbekannte, föderationsweit gleiche
    /// Konvention (gleiche Bytes ⇒ gleiche `ContentId`, §5.3/§12.3).
    pub fn active_marker() -> Self {
        Datum::leaf(*ACTIVE_MARKER_PAYLOAD)
    }

    /// Erzeugt ein **Marker-Daten** (§13): ein Knoten, der das
    /// [`active_marker`](Datum::active_marker)-Atom **und** die übergebenen
    /// `constituents` als besessene Kontexte trägt (Audit/Herkunft des Umbaus, §13).
    ///
    /// Das Marker-Daten ist der **eine** abschließende Aktiv-Schreibvorgang, dessen
    /// durabler Commit den Umbau **gemeinsam sichtbar** flippt (§13.1) — übergeben an
    /// [`crate::store::ContentStore::append_restructuring`] /
    /// [`crate::kernel::LakearchKernel::append_restructuring`]. Die Konstituenten als
    /// Kontexte aufzunehmen ist rein **Audit** (§13: der Marker trägt im Log ohnehin
    /// den `constituent_range`); die §13-Sichtbarkeit hängt **allein** am
    /// Offset-Vergleich, nicht an diesen Kontexten (§1.4). Ist `constituents` leer,
    /// ist das Marker-Daten das bloße Atom-Blatt.
    pub fn active_marker_for(constituents: impl IntoIterator<Item = ContentId>) -> Self {
        let marker = ContentId::of_datum(&Datum::active_marker());
        let mut owned: Vec<ContentId> = vec![marker];
        owned.extend(constituents);
        // `node` sortiert/dedupliziert (§K2.3); das Atom ist stets enthalten ⇒ nie leer.
        Datum::node(owned).expect("Aktiv-Marker besitzt stets das Marker-Atom (§13)")
    }

    /// `true`, wenn dieses Daten ein **Aktiv-Marker** (§13) ist — also das
    /// [`active_marker`](Datum::active_marker)-Atom besitzt **oder** das Atom selbst
    /// ist. Reines strukturelles Matching (§1.3); keine Wertung (§1.4).
    pub fn is_active_marker(&self) -> bool {
        if self.payload() == Some(&ACTIVE_MARKER_PAYLOAD[..]) {
            return true;
        }
        let marker = ContentId::of_datum(&Datum::active_marker());
        matches!(self.owns(), Some(owns) if owns.binary_search(&marker).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> ContentId {
        ContentId::from_bytes([byte; 32])
    }

    #[test]
    fn leaf_keeps_opaque_payload() {
        let d = Datum::leaf([1u8, 2, 3]);
        assert!(d.is_leaf());
        assert_eq!(d.payload(), Some(&[1u8, 2, 3][..]));
        assert_eq!(d.owns(), None);
    }

    #[test]
    fn empty_leaf_is_well_formed_and_distinct_from_node() {
        // Leeres Blatt: payload = [] ist wohlgeformt (§K3.5).
        let d = Datum::leaf([]);
        assert!(d.is_leaf());
        assert_eq!(d.payload(), Some(&[][..]));
    }

    #[test]
    fn node_sorts_and_dedups_owned_contexts() {
        // Einfüge-Reihenfolge + Duplikat dürfen das Resultat nicht ändern (§K2.3).
        let a = cid(0x01);
        let b = cid(0x02);
        let n1 = Datum::node([b, a, b]).expect("nicht-leerer Knoten");
        let n2 = Datum::node([a, b]).expect("nicht-leerer Knoten");
        let n3 = Datum::node([b, a]).expect("nicht-leerer Knoten");
        assert_eq!(n1, n2);
        assert_eq!(n2, n3);
        assert_eq!(n1.owns(), Some(&[a, b][..]), "aufsteigend sortiert");
    }

    #[test]
    fn node_without_contexts_is_rejected() {
        // Ein Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1).
        assert!(Datum::node([]).is_none());
    }

    #[test]
    fn node_is_not_a_leaf() {
        let n = Datum::node([cid(0x07)]).expect("nicht-leerer Knoten");
        assert!(n.is_node());
        assert!(!n.is_leaf());
        assert_eq!(n.payload(), None);
    }

    #[test]
    fn unresolved_marker_is_a_frozen_leaf() {
        // §3.6: das Marker-Atom ist ein gewöhnliches Blatt (§2.1) mit fester
        // Nutzlast.
        let m = Datum::unresolved_marker();
        assert!(m.is_leaf());
        assert_eq!(m.payload(), Some(&b"lakearch/unresolved/v1"[..]));
    }

    #[test]
    fn placeholder_owns_the_marker_and_is_a_node() {
        // §3.6: ein Platzhalter ist ein Knoten, der das Marker-Atom besitzt.
        let p = Datum::placeholder([]);
        assert!(p.is_node());
        assert!(p.is_placeholder());
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        assert_eq!(p.owns(), Some(&[marker][..]));
    }

    #[test]
    fn placeholder_includes_expected_contexts_sorted_and_dedup() {
        // §3.6 + §K2.3: Marker + erwartete Ziele, kanonisch sortiert/dedupliziert.
        let target = cid(0xff); // > Marker-CID in 32-Byte-Order
        let p = Datum::placeholder([target, target]);
        assert!(p.is_placeholder());
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        let owns = p.owns().expect("Knoten");
        assert_eq!(owns.len(), 2, "Marker + ein dedupliziertes Ziel");
        assert!(owns.contains(&marker));
        assert!(owns.contains(&target));
        // Aufsteigend sortiert (§K2.3).
        assert!(owns[0] < owns[1]);
    }

    #[test]
    fn ordinary_node_is_not_a_placeholder() {
        // Reines strukturelles Matching (§1.3): ohne Marker kein Platzhalter.
        let n = Datum::node([cid(0x07)]).unwrap();
        assert!(!n.is_placeholder());
        // Ein Blatt ist nie ein Platzhalter.
        assert!(!Datum::leaf([0x01]).is_placeholder());
    }

    // -- Bereichs-Zugehörigkeit (§11.1) --------------------------------------

    #[test]
    fn area_membership_marker_is_a_frozen_leaf() {
        let m = Datum::area_membership_marker();
        assert!(m.is_leaf());
        assert_eq!(m.payload(), Some(&b"lakearch/area-membership/v1"[..]));
    }

    #[test]
    fn area_membership_owns_marker_and_area() {
        let area = cid(0xAB);
        let ctx = Datum::area_membership(area);
        assert!(ctx.is_node());
        // Der Zugehörigkeits-Kontext zeigt strukturell auf den Bereich.
        assert_eq!(ctx.area_membership_target(), Some(area));
    }

    #[test]
    fn non_membership_nodes_have_no_area_target() {
        // Ein Blatt: kein Zugehörigkeits-Kontext.
        assert_eq!(Datum::leaf([0x01]).area_membership_target(), None);
        // Ein Knoten ohne den Marker: kein Zugehörigkeits-Kontext.
        assert_eq!(Datum::node([cid(0x01), cid(0x02)]).unwrap().area_membership_target(), None);
        // Ein Knoten mit dem Marker, aber drei Kontexten (≠ 2): kein eindeutiger
        // Bereich ⇒ None (reines Matching, keine Wertung, §1.4).
        let marker = ContentId::of_datum(&Datum::area_membership_marker());
        let three = Datum::node([marker, cid(0x01), cid(0x02)]).unwrap();
        assert_eq!(three.area_membership_target(), None);
        // Nur der Marker (ein Kontext): kein Bereich.
        let only = Datum::node([marker]).unwrap();
        assert_eq!(only.area_membership_target(), None);
    }

    // -- Berechtigung & Entzug (§11.1/§11.4) ---------------------------------

    /// Hilfs-Resolver: bildet eine kleine `ContentId → Datum`-Karte über die
    /// Rollen-Kontexte einer Berechtigung (so wie der Store sie auflöst).
    fn resolver(data: &[Datum]) -> impl FnMut(ContentId) -> Option<Datum> + '_ {
        move |id| {
            data.iter()
                .find(|d| ContentId::of_datum(d) == id)
                .cloned()
        }
    }

    #[test]
    fn permission_reads_back_subject_and_area_structurally() {
        let subject = cid(0x11);
        let area = cid(0x22);
        // Die Rollen-Kontexte sind besessene Daten; der Resolver muss sie kennen.
        let subj_role = Datum::permission_subject_role(subject);
        let area_role = Datum::permission_area_role(area);
        let perm = Datum::permission(subject, area);
        let resolve = resolver(std::slice::from_ref(&subj_role));
        // Mit beiden Rollen-Kontexten verfügbar ⇒ (Subjekt, Bereich) ablesbar.
        let known = [subj_role.clone(), area_role.clone()];
        assert_eq!(
            perm.permission_subject_area(resolver(&known)),
            Some((subject, area))
        );
        // Fehlt der Bereichs-Rollen-Kontext, ist die Berechtigung nicht vollständig
        // ablesbar (None, keine Wertung §1.4).
        let _ = resolve;
        assert_eq!(
            perm.permission_subject_area(resolver(std::slice::from_ref(&subj_role))),
            None
        );
    }

    #[test]
    fn non_permission_nodes_have_no_subject_area() {
        // Ein Blatt: keine Berechtigung.
        assert_eq!(
            Datum::leaf([0x01]).permission_subject_area(resolver(&[])),
            None
        );
        // Ein Knoten ohne das Berechtigungs-Marker-Atom: keine Berechtigung.
        let n = Datum::node([cid(0x01), cid(0x02)]).unwrap();
        assert_eq!(n.permission_subject_area(resolver(&[])), None);
    }

    #[test]
    fn revocation_points_at_a_permission() {
        let perm = Datum::permission(cid(0x11), cid(0x22));
        let perm_id = ContentId::of_datum(&perm);
        let rev = Datum::revocation(perm_id);
        assert!(rev.is_node());
        assert_eq!(rev.revocation_target(), Some(perm_id));
        // Ein gewöhnlicher Knoten ist kein Entzug.
        assert_eq!(Datum::node([cid(0x01)]).unwrap().revocation_target(), None);
        // Ein Blatt ist kein Entzug.
        assert_eq!(Datum::leaf([0x01]).revocation_target(), None);
    }

    #[test]
    fn permission_markers_are_frozen_leaves() {
        assert_eq!(
            Datum::permission_subject_marker().payload(),
            Some(&b"lakearch/perm-subject/v1"[..])
        );
        assert_eq!(
            Datum::permission_area_marker().payload(),
            Some(&b"lakearch/perm-area/v1"[..])
        );
        assert_eq!(
            Datum::permission_marker().payload(),
            Some(&b"lakearch/permission/v1"[..])
        );
        assert_eq!(
            Datum::revocation_marker().payload(),
            Some(&b"lakearch/revocation/v1"[..])
        );
    }

    // -- Zeit: zwei Achsen (§6.1/§6.2) ---------------------------------------

    #[test]
    fn time_axis_markers_are_frozen_distinct_leaves() {
        // §6.2: zwei eingefrorene, VERSCHIEDENE Achsen-Marker.
        let rec = Datum::recording_time_marker();
        let val = Datum::validity_time_marker();
        assert!(rec.is_leaf() && val.is_leaf());
        assert_eq!(rec.payload(), Some(&b"lakearch/recording-time/v1"[..]));
        assert_eq!(val.payload(), Some(&b"lakearch/validity-time/v1"[..]));
        // Die Achsen sind strukturell distinkt (verschiedene ContentIds).
        assert_ne!(
            ContentId::of_datum(&rec),
            ContentId::of_datum(&val),
            "die zwei Zeitachsen müssen unterscheidbar sein (§6.2)"
        );
    }

    #[test]
    fn recording_and_validity_time_read_back_their_opaque_value() {
        // §6.1: der Zeit-Wert ist ein opakes Daten; hier nur eine Adresse.
        let t_rec = cid(0xA1);
        let t_val = cid(0xB2);
        let rec_stmt = Datum::recording_time(t_rec);
        let val_stmt = Datum::validity_time(t_val);
        assert!(rec_stmt.is_node() && val_stmt.is_node());
        // Reines strukturelles Ablesen (§1.3) — KEIN Parsen/Vergleichen (§1.4/§6.4).
        assert_eq!(rec_stmt.recording_time_value(), Some(t_rec));
        assert_eq!(val_stmt.validity_time_value(), Some(t_val));
        // Achsen-Kreuz: eine Aufzeichnungszeit-Aussage ist KEINE Gültigkeits-Aussage.
        assert_eq!(rec_stmt.validity_time_value(), None);
        assert_eq!(val_stmt.recording_time_value(), None);
    }

    #[test]
    fn one_datum_carries_both_axes_distinct_and_independent() {
        // §6.2: ein Daten DARF beide Achsen tragen; sie dürfen auseinanderfallen.
        // Verschiedene Zeit-Werte je Achse ⇒ verschiedene Aussage-Kontexte.
        let t_rec = cid(0x10); // wann erfahren
        let t_val = cid(0x20); // wann gültig (divergiert)
        let rec_stmt = Datum::recording_time(t_rec);
        let val_stmt = Datum::validity_time(t_val);
        let rec_id = ContentId::of_datum(&rec_stmt);
        let val_id = ContentId::of_datum(&val_stmt);
        // Die zwei Aussage-Kontexte sind distinkt und unabhängig.
        assert_ne!(rec_id, val_id, "die zwei Achsen-Aussagen sind distinkt (§6.2)");
        // Ein Daten, das BEIDE Aussagen besitzt (plus ein Sachverhalts-Blatt).
        let fact = ContentId::of_datum(&Datum::leaf(b"sachverhalt".to_vec()));
        let bitemporal = Datum::node([rec_id, val_id, fact]).expect("Knoten");
        let owns = bitemporal.owns().expect("Knoten");
        assert!(owns.contains(&rec_id));
        assert!(owns.contains(&val_id));
        // Beide Achsen sind unabhängig wieder ablesbar (über die Aussage-Daten).
        assert_eq!(rec_stmt.recording_time_value(), Some(t_rec));
        assert_eq!(val_stmt.validity_time_value(), Some(t_val));
        // Die divergierten Werte bleiben verschieden — der Kernel ordnet sie NICHT.
        assert_ne!(t_rec, t_val);
    }

    // -- Ersetzung (§6.3) ----------------------------------------------------

    #[test]
    fn supersession_marker_is_a_frozen_leaf() {
        let m = Datum::supersession_marker();
        assert!(m.is_leaf());
        assert_eq!(m.payload(), Some(&b"lakearch/supersedes/v1"[..]));
    }

    #[test]
    fn supersession_links_newer_to_older_structurally() {
        // §6.3: der Ersetzungs-Kontext zeigt vom (besitzenden) NEUEREN auf das
        // ÄLTERE Daten — strukturell, ohne das Ältere zu ändern (§7.1).
        let older = ContentId::of_datum(&Datum::leaf(b"alt".to_vec()));
        let ctx = Datum::supersedes(older);
        assert!(ctx.is_node());
        assert_eq!(ctx.supersedes_target(), Some(older));

        // Das neuere Daten BESITZT den Ersetzungs-Kontext (so wird die Kante
        // beidseitig traversierbar — owner→contexts / target→referrers, §1.2).
        let ctx_id = ContentId::of_datum(&ctx);
        let fact = ContentId::of_datum(&Datum::leaf(b"neu".to_vec()));
        let newer = Datum::node([ctx_id, fact]).expect("Knoten");
        assert!(newer.owns().unwrap().contains(&ctx_id));

        // Ein gewöhnlicher Knoten / ein Blatt ist KEIN Ersetzungs-Kontext.
        assert_eq!(Datum::node([cid(0x07)]).unwrap().supersedes_target(), None);
        assert_eq!(Datum::leaf([0x01]).supersedes_target(), None);
        // Ein Knoten mit dem Marker, aber drei Kontexten (≠ 2): kein eindeutiges
        // Ziel ⇒ None (reines Matching, keine Wertung, §1.4).
        let marker = ContentId::of_datum(&Datum::supersession_marker());
        let three = Datum::node([marker, cid(0x01), cid(0x02)]).unwrap();
        assert_eq!(three.supersedes_target(), None);
    }

    // -- Anker / Mitgliedschaft / gradierte Identität / Kuratierung (§9, §5.5) --
    // (Der `resolver`-Helfer ist oben bei den Berechtigungs-Tests definiert.)

    #[test]
    fn phase4_markers_are_frozen_distinct_leaves_of_documented_length() {
        // §9.1/§9.3/§5.5/§9.5: jedes Marker-Atom ist ein gewöhnliches Blatt (§2.1)
        // mit fester, eingefrorener Nutzlast der dokumentierten Länge — und alle
        // sind paarweise verschieden (verschiedene ContentIds).
        let markers: [(Datum, &[u8]); 11] = [
            (Datum::anchor_marker(), b"lakearch/anchor/v1"),
            (Datum::membership_marker(), b"lakearch/membership/v1"),
            (Datum::membership_grade_marker(), b"lakearch/grade/v1"),
            (
                Datum::identity_strength_marker(IdentityStrength::Deckungsgleich),
                b"lakearch/ident-deckungsgleich/v1",
            ),
            (
                Datum::identity_strength_marker(IdentityStrength::Ergaenzt),
                b"lakearch/ident-ergaenzt/v1",
            ),
            (
                Datum::identity_strength_marker(IdentityStrength::WidersprichtIn),
                b"lakearch/ident-widerspricht-in/v1",
            ),
            (
                Datum::identity_strength_marker(IdentityStrength::VerwandtMit),
                b"lakearch/ident-verwandt-mit/v1",
            ),
            (
                Datum::identity_strength_marker(IdentityStrength::BekanntVerschieden),
                b"lakearch/ident-bekannt-verschieden/v1",
            ),
            (Datum::curation_hide_marker(), b"lakearch/curation/hide/v1"),
            (Datum::curation_unhide_marker(), b"lakearch/curation/unhide/v1"),
            (Datum::curation_replace_marker(), b"lakearch/curation/replace/v1"),
        ];
        let mut ids = Vec::new();
        for (d, payload) in &markers {
            assert!(d.is_leaf(), "Marker ist ein Blatt (§2.1)");
            assert_eq!(d.payload(), Some(&payload[..]), "eingefrorene Nutzlast");
            ids.push(ContentId::of_datum(d));
        }
        // Paarweise distinkt: 11 verschiedene ContentIds.
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "alle Marker sind distinkte Blätter (§9/§5.5)");
    }

    #[test]
    fn anchor_is_an_ordinary_content_addressed_node() {
        // §9.1/§2.1: der Anker ist ein gewöhnliches Daten (Knoten) mit eigener
        // ContentId; er trägt das Anker-Marker-Atom.
        let class = cid(0xC1);
        let anchor = Datum::anchor([class]);
        assert!(anchor.is_node());
        assert!(anchor.is_anchor());
        // Eine eigene, stabile ContentId (§2.1).
        assert_eq!(ContentId::of_datum(&anchor), ContentId::of_datum(&Datum::anchor([class])));
        // Ein gewöhnlicher Knoten / ein Blatt ist KEIN Anker.
        assert!(!Datum::node([class]).unwrap().is_anchor());
        assert!(!Datum::leaf([0x01]).is_anchor());
        // Auch ein „nur markierter" Anker (leere payload) ist wohlgeformt.
        assert!(Datum::anchor([]).is_anchor());
    }

    #[test]
    fn membership_links_representative_to_anchor_structurally() {
        // §9.1/§9.2/§9.3: der Mitgliedschafts-Kontext verweist (strukturell) auf den
        // ANKER und trägt einen Grad-Sub-Kontext; der Repräsentant BESITZT ihn.
        let anchor = ContentId::of_datum(&Datum::anchor([cid(0xC1)]));
        let grade_value = ContentId::of_datum(&Datum::leaf(b"0.92".to_vec()));
        let grade_ctx = Datum::membership_grade(grade_value);
        let membership = Datum::membership(anchor, grade_value);
        assert!(membership.is_node());

        // Resolver kennt den Grad-Sub-Kontext (besessenes Daten der Mitgliedschaft).
        let resolve = resolver(std::slice::from_ref(&grade_ctx));
        // Strukturell: die Mitgliedschaft verweist auf den Anker (§9.2), nicht auf
        // einen Repräsentanten.
        assert_eq!(membership.membership_anchor(resolve), Some(anchor));
        // Der Grad-Sub-Kontext ist ablesbar — sein opaker Wert wird NIE verglichen.
        assert_eq!(
            membership.membership_grade_context(resolver(std::slice::from_ref(&grade_ctx))),
            Some(ContentId::of_datum(&grade_ctx))
        );
        assert_eq!(grade_ctx.membership_grade_value(), Some(grade_value));

        // Der Repräsentant besitzt die Mitgliedschaft als Kontext (§9.1).
        let membership_id = ContentId::of_datum(&membership);
        let representative = Datum::node([membership_id]).unwrap();
        assert!(representative.owns().unwrap().contains(&membership_id));

        // Ein gewöhnlicher Knoten / ein Blatt ist KEINE Mitgliedschaft.
        assert_eq!(Datum::node([cid(0x07)]).unwrap().membership_anchor(resolver(&[])), None);
        assert_eq!(Datum::leaf([0x01]).membership_anchor(resolver(&[])), None);
    }

    #[test]
    fn graded_identity_carries_strength_and_a_stored_but_never_compared_confidence() {
        // §5.5/§3.4: ein gradierter Identitäts-Kontext trägt seine STÄRKE und einen
        // REIFIZIERTEN Konfidenz-Sub-Kontext, der GESPEICHERT, aber NIE verglichen
        // wird (der Kernel hat kein Verb dafür, §1.4/§9-Präambel).
        let a = cid(0xA1);
        let b = cid(0xB2);
        // Reifizierte Konfidenz: ein gewöhnlicher Kontext mit OPAKEM Wert (§3.4).
        let confidence_value = ContentId::of_datum(&Datum::leaf(b"konfidenz=0.8".to_vec()));
        let confidence_ctx = ContentId::of_datum(&Datum::node([confidence_value]).unwrap());

        let ident = Datum::graded_identity(a, b, IdentityStrength::Ergaenzt, [confidence_ctx]);
        assert!(ident.is_graded_identity());
        // Die Stärke ist strukturell ablesbar (KEINE Ordnung/Wertung, §1.4).
        assert_eq!(ident.identity_strength(), Some(IdentityStrength::Ergaenzt));

        // Die reifizierten Sub-Kontexte (a, b, Konfidenz) sind gehalten — der
        // Konfidenz-Sub-Kontext ist darunter, wird aber NIE verglichen/geschwellt.
        let ctxs = ident.graded_identity_contexts().expect("gradierter Identitäts-Kontext");
        assert!(ctxs.contains(&a));
        assert!(ctxs.contains(&b));
        assert!(ctxs.contains(&confidence_ctx), "Konfidenz reifiziert + gehalten (§3.4/§5.5)");
        // Der Stärke-Marker selbst ist NICHT in den Sub-Kontexten.
        let marker = ContentId::of_datum(&Datum::identity_strength_marker(IdentityStrength::Ergaenzt));
        assert!(!ctxs.contains(&marker));

        // Eine andere Stärke ergibt einen distinkten Kontext (Familie, §5.5).
        let other = Datum::graded_identity(a, b, IdentityStrength::BekanntVerschieden, []);
        assert_eq!(other.identity_strength(), Some(IdentityStrength::BekanntVerschieden));
        assert_ne!(ContentId::of_datum(&ident), ContentId::of_datum(&other));

        // Ein gewöhnlicher Knoten / ein Blatt trägt keine Stärke.
        assert!(!Datum::node([a, b]).unwrap().is_graded_identity());
        assert_eq!(Datum::leaf([0x01]).identity_strength(), None);
    }

    #[test]
    fn curation_hide_and_replace_are_reversible_contexts() {
        // §9.5: Verbergen ist reversibel (durch Aufheben); Ersetzen ist ein
        // reversibler Hinweis. NICHTS wird gelöscht — alles sind append-only Daten.
        let target = cid(0x44);
        let hide = Datum::curation_hide(target);
        assert!(hide.is_node());
        assert_eq!(hide.curation_hide_target(), Some(target));
        // Reversibel: das Aufheben benennt dasselbe Ziel — ein NEUER Kontext (§7.1).
        let unhide = Datum::curation_unhide(target);
        assert_eq!(unhide.curation_unhide_target(), Some(target));
        // Verbergen und Aufheben sind distinkte Kontexte (verschiedene Marker).
        assert_ne!(ContentId::of_datum(&hide), ContentId::of_datum(&unhide));
        // Achsen-Kreuz: ein Verbergen ist kein Aufheben und umgekehrt.
        assert_eq!(hide.curation_unhide_target(), None);
        assert_eq!(unhide.curation_hide_target(), None);

        // Ersetzen: reversibler Hinweis replaced↦replacement (§9.5).
        let replaced = cid(0x10);
        let replacement = cid(0x20);
        let replace = Datum::curation_replace(replaced, replacement);
        let (x, y) = replace.curation_replace_targets().expect("Ersetzen-Kontext");
        // Beide Ziele sind enthalten (adress-sortiert; die Zuordnung kennt die
        // Schicht darüber, §14) — der Kernel ordnet/wertet NICHT (§1.4).
        let mut got = [x, y];
        got.sort_unstable();
        let mut want = [replaced, replacement];
        want.sort_unstable();
        assert_eq!(got, want);

        // Ein gewöhnlicher Knoten / ein Blatt ist kein Kuratierungs-Kontext.
        assert_eq!(Datum::node([cid(0x07)]).unwrap().curation_hide_target(), None);
        assert_eq!(Datum::leaf([0x01]).curation_replace_targets(), None);
    }

    #[test]
    fn identity_strength_has_no_ordering_kernel_never_ranks() {
        // §5.5/§1.4 NEGATIV-GARANTIE: die Stärke ist eine reine Etikette OHNE
        // Ordnung. `IdentityStrength` leitet KEIN Ord/PartialOrd ab; es gibt KEIN
        // Verb, das Stärken oder Konfidenz vergleicht/rankt/schwellt. Dieser Test
        // friert das ein: er prüft nur strukturelle GLEICHHEIT (Eq), nie Ordnung.
        for s in IdentityStrength::all() {
            // Reflexive Gleichheit ist erlaubt (reines Matching, §1.3).
            assert_eq!(s, s);
        }
        // Distinkte Marker je Stärke (strukturell, kein Rang).
        let mut ids: Vec<ContentId> = IdentityStrength::all()
            .into_iter()
            .map(|s| ContentId::of_datum(&Datum::identity_strength_marker(s)))
            .collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "fünf distinkte Stärke-Marker (§5.5)");
        // Bewusst KEINE Assertion wie `Deckungsgleich > VerwandtMit` — eine solche
        // Ordnung existiert nicht und darf nie hinzukommen (§1.4).
    }

    // -- Aktiv-Marker (§13) --------------------------------------------------

    #[test]
    fn active_marker_atom_is_a_frozen_leaf_distinct_from_others() {
        // §13: das Aktiv-Marker-Atom ist ein gewöhnliches Blatt (§2.1) mit fester
        // Nutzlast — und distinkt von allen anderen Marker-Atomen.
        let m = Datum::active_marker();
        assert!(m.is_leaf());
        assert_eq!(m.payload(), Some(&b"lakearch/active-marker/v1"[..]));
        // Distinkt von einer Auswahl bestehender Marker (verschiedene ContentIds).
        let active = ContentId::of_datum(&m);
        for other in [
            Datum::area_membership_marker(),
            Datum::permission_marker(),
            Datum::revocation_marker(),
            Datum::supersession_marker(),
            Datum::anchor_marker(),
            Datum::membership_marker(),
            Datum::curation_hide_marker(),
        ] {
            assert_ne!(active, ContentId::of_datum(&other), "Aktiv-Marker distinkt (§13)");
        }
    }

    #[test]
    fn active_marker_for_owns_atom_and_constituents_and_is_recognizable() {
        // §13: ein Marker-Daten besitzt das Aktiv-Marker-Atom (erkennbar, §1.3) und
        // optional die Konstituenten als Audit-Kontexte.
        let c1 = cid(0xA1);
        let c2 = cid(0xA2);
        let marker = Datum::active_marker_for([c1, c2]);
        assert!(marker.is_node());
        assert!(marker.is_active_marker(), "trägt das Aktiv-Marker-Atom (§13)");
        let atom = ContentId::of_datum(&Datum::active_marker());
        let owns = marker.owns().expect("Knoten");
        assert!(owns.contains(&atom), "Atom enthalten");
        assert!(owns.contains(&c1) && owns.contains(&c2), "Konstituenten als Audit");
        // Das bloße Atom-Blatt ist ebenfalls als Marker erkennbar.
        assert!(Datum::active_marker().is_active_marker());
        // Ein gewöhnlicher Knoten / ein Blatt ist KEIN Aktiv-Marker.
        assert!(!Datum::node([c1]).unwrap().is_active_marker());
        assert!(!Datum::leaf([0x01]).is_active_marker());
    }
}
