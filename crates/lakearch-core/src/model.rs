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
}
