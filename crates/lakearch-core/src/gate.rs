//! Das Zugriffs-Tor (§11) — als **Typ-Skelett**, das die Unumgehbarkeit
//! (§11.2/§11.5) **zur Compile-Zeit** erzwingt.
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md` §11 und der gehärtete Plan.
//! Dieses Modul ist `#![forbid(unsafe_code)]` (das Tor muss beweisbar sicheres
//! Rust sein).
//!
//! ## Die Compile-Zeit-Garantie
//!
//! Der Speicher/Index liefert ausschließlich ein **opakes** [`SealedRecord`].
//! `SealedRecord` hat **keine** öffentliche Methode, die Daten-Bytes herausgibt.
//! Die **einzige** Funktion, die `SealedRecord → `[`VisibleDatum`] wandelt, ist
//! [`open`] — sie lebt hier und **verlangt** eine [`Capability`]. Sowohl
//! `Capability`/[`GrantedScopes`] als auch das innere Feld von `VisibleDatum`
//! sind **außerhalb dieses Moduls nicht konstruierbar** (private Felder + ein
//! *sealed trait*). Folge: „Tor vergessen" / „ohne Tor lesen" ist im Typsystem
//! **nicht darstellbar** — ein Compile-Fehler, kein Test-Fund (§11.5
//! „manipulationssicher").
//!
//! ## Phasen-Disziplin
//!
//! In diesem Stand (Phase 0.5) ist nur die **Form** eingefroren. Die
//! **Tor-Logik** (Bereichs-Index, zweiphasiges Filter-vor-Auflösen §11.3,
//! fail-closed, VANISH) landet in **Phase 2**; [`open`] ist hier ein Stub, der
//! die Sichtbarkeit **noch nicht** auswertet und ausschließlich von der
//! Capability-gebundenen Aufruf-Form lebt. Die Berechtigungs-Logik trägt der
//! Daemon (§11, Read-Audit lebt dort, nicht im Kernel; §8.4).

#![forbid(unsafe_code)]

use crate::id::ContentId;

/// *Sealed trait* (§Rust-Pattern): nur in diesem Modul implementierbar, weil
/// das einzige Implementier-Subjekt im **privaten** Submodul `sealed` liegt.
/// Token-Typen führen ihn als `Sealed`-Schranke, sodass **keine** Fremd-Crate
/// einen eigenen „Capability"-artigen Typ in eine Tor-Signatur einsetzen kann.
mod sealed {
    /// Marker; außerhalb von `gate` nicht referenzierbar (`pub(super)` an einem
    /// privaten Modul ⇒ effektiv modul-privat). Ab Phase 2 trägt ihn jede
    /// Token-Schranke in der Tor-Logik; im Skelett belegt seine bloße Existenz
    /// (plus die `impl …`-Zeilen unten), dass kein Fremd-Token einsetzbar ist.
    #[allow(dead_code)] // Phase 2: Schranke der Tor-Logik; Form jetzt eingefroren.
    pub(super) trait Sealed {}
}

/// Ein **versiegelter Speicher-Record**: das einzige, was Speicher und Index
/// (ab Phase 1) für ein gelesenes Daten herausgeben.
///
/// `SealedRecord` ist **opak**: es gibt **keine** öffentliche Methode, die die
/// Daten-Bytes (atomare Nutzlast oder besessene Kontext-IDs) liefert. Sichtbar
/// ist allein die [`ContentId`] (die ist ein berechenbarer Hash und damit kein
/// Geheimnis — sie adressiert, sie urteilt nicht, §5.2; das **Existenz-Orakel**
/// über IDs wehrt erst die Tor-Logik via VANISH ab, Phase 2). Den Inhalt
/// erschließt **ausschließlich** [`open`] gegen eine [`Capability`].
///
/// Konstruierbar nur **crate-intern** (vom Speicher/Index); der innere Wert ist
/// privat. Außerhalb des Crates existiert **kein** Konstruktionsweg.
#[derive(Clone, Debug)]
pub struct SealedRecord {
    /// Die Adresse des Daten (§5.2) — nicht-geheim, aber allein noch kein Lese-
    /// recht (VANISH wehrt das Existenz-Orakel ab, Phase 2).
    content_id: ContentId,
    /// Roh-Sicht auf den gespeicherten Inhalt. **Privat**; kein öffentlicher
    /// Getter. Erst [`open`] darf ihn — gegen eine Capability — freilegen.
    /// In Phase 1 trägt dies die kanonischen Bytes / einen Segment-Handle; im
    /// Skelett genügt der `ContentId`-Doppelgriff (s. [`open`]).
    payload: SealedPayload,
}

/// Privater Inhaltsträger eines [`SealedRecord`]. Bewusst ein eigener Typ, damit
/// keine `pub`-Felder durchsickern und der Skelett-Inhalt später (Phase 1) gegen
/// echte kanonische Bytes / einen `Arc<SegmentHandle>+offset` getauscht werden
/// kann, **ohne** die öffentliche Tor-Signatur zu ändern.
#[derive(Clone, Debug)]
struct SealedPayload {
    /// Skelett-Platzhalter für die spätere Roh-Sicht. Im Skelett spiegeln wir
    /// die `ContentId`, damit [`VisibleDatum`] etwas Reales trägt; ab Phase 1
    /// stehen hier die kanonischen Bytes bzw. ein Segment-Handle.
    content_id: ContentId,
}

impl SealedRecord {
    /// **Crate-interner** Konstruktor: nur Speicher/Index (ab Phase 1) erzeugen
    /// versiegelte Records. Es gibt **keinen** öffentlichen Konstruktionsweg —
    /// damit ist „Record ohne Tor selbst bauen und auslesen" außerhalb des
    /// Crates unmöglich.
    #[allow(dead_code)] // Phase 1: ruft der Speicher/Index; jetzt nur Tests + Form.
    pub(crate) fn seal(content_id: ContentId) -> Self {
        SealedRecord {
            content_id,
            payload: SealedPayload { content_id },
        }
    }

    /// Die **nicht-geheime** Adresse (§5.2). Bewusst die einzige öffentliche
    /// Auskunft: sie reicht für Index-/Mengen-Operationen, gibt aber **keinen**
    /// Inhalt preis. Das Existenz-Orakel über IDs wehrt die Tor-Logik ab
    /// (VANISH, Phase 2).
    pub fn content_id(&self) -> ContentId {
        self.content_id
    }
}

/// Eine **Capability** — der unfälschbare Nachweis, dass ein Lesevorgang das Tor
/// passiert (passieren wird, Phase 2). Sie bündelt die [`GrantedScopes`] des
/// Subjekts.
///
/// `Capability` ist **außerhalb dieses Moduls nicht konstruierbar** (privates
/// Feld + `Sealed`-Schranke). Sie wird ab Phase 2 ausschließlich vom Tor selbst
/// (aus auditierten Berechtigungen, §11.1) ausgestellt. Eine Fremd-Schicht kann
/// also keine Capability „erfinden".
pub struct Capability {
    /// Die gewährten Bereiche (§11.1). Privat — kein öffentlicher Getter, der
    /// die Mengen-Bytes herausgibt; das Tor matcht sie intern (§1.3).
    scopes: GrantedScopes,
}

impl sealed::Sealed for Capability {}

impl Capability {
    /// **Crate-interner** Aussteller: ab Phase 2 ruft das Tor dies auf, nachdem
    /// es die Berechtigungen strukturell gematcht hat (§11.2). Kein
    /// öffentlicher Weg.
    #[allow(dead_code)] // Phase 2: stellt das Tor aus; jetzt nur Tests + Form.
    pub(crate) fn issue(scopes: GrantedScopes) -> Self {
        Capability { scopes }
    }

    /// Crate-interne Sicht auf die gewährten Bereiche, **nur** für die Tor-Logik
    /// (Phase 2). Bewusst nicht `pub`.
    pub(crate) fn scopes(&self) -> &GrantedScopes {
        &self.scopes
    }
}

/// Die **gewährten Bereiche** eines Subjekts (§11.1) — die Menge der Bereichs-
/// Daten, deren Zugehörigkeit das Tor matchen darf (*Bereich ∈ gewährte
/// Bereiche*, §11.2/§1.3).
///
/// **Außerhalb dieses Moduls nicht konstruierbar** (privates Feld). Ab Phase 2
/// baut sie das Tor aus den aktiven Berechtigungen im Snapshot.
pub struct GrantedScopes {
    /// Bereichs-Daten-IDs (§11.1). Privat; das Tor matcht sie strukturell, gibt
    /// sie aber nicht heraus (sonst Bereichs-Leak, §11.3). Gelesen ab Phase 2
    /// (Tor-Logik); im Skelett friert das Feld nur die Form.
    #[allow(dead_code)] // Phase 2: liest die Tor-Logik via `scope_ids()`.
    scope_ids: Vec<ContentId>,
}

impl sealed::Sealed for GrantedScopes {}

impl GrantedScopes {
    /// **Crate-interner** Konstruktor (ab Phase 2 aus dem Bereichs-Index).
    #[allow(dead_code)] // Phase 2: baut das Tor; jetzt nur Tests + Form.
    pub(crate) fn from_scope_ids(scope_ids: impl IntoIterator<Item = ContentId>) -> Self {
        GrantedScopes {
            scope_ids: scope_ids.into_iter().collect(),
        }
    }

    /// Crate-interne Sicht für die Tor-Logik (Phase 2).
    #[allow(dead_code)] // Phase 2: nutzt die Tor-Logik (Bereich-∈-Matching, §1.3).
    pub(crate) fn scope_ids(&self) -> &[ContentId] {
        &self.scope_ids
    }
}

/// Ein **sichtbares Daten** — das einzige Ergebnis, das Daten-Inhalt einem Leser
/// zugänglich macht. Es entsteht **ausschließlich** aus [`open`], also **nur**
/// nach Vorlage einer [`Capability`].
///
/// Das innere Feld ist **privat** und außerhalb dieses Moduls nicht setzbar; es
/// gibt **keinen** öffentlichen Konstruktor. Damit ist der einzige Weg zu einem
/// `VisibleDatum` die Tor-Funktion [`open`].
#[derive(Clone, Debug)]
pub struct VisibleDatum {
    content_id: ContentId,
    /// Freigelegte Inhalts-Sicht. Privat; ab Phase 1 die kanonischen Bytes bzw.
    /// ein Lese-Handle. Hier spiegeln wir die `ContentId` (Skelett).
    revealed: SealedPayload,
}

impl VisibleDatum {
    /// Die Adresse des sichtbaren Daten (§5.2).
    pub fn content_id(&self) -> ContentId {
        self.content_id
    }

    /// Skelett-Auskunft, dass der Inhalt freigelegt ist. Ab Phase 1 ersetzt dies
    /// ein echter Inhalts-Zugriff (`payload()`/`owns()`-Sicht); im Skelett
    /// genügt der konsistente `ContentId`-Spiegel als Beweis, dass `open`
    /// tatsächlich aus dem versiegelten Inhalt schöpfte.
    pub fn revealed_content_id(&self) -> ContentId {
        self.revealed.content_id
    }
}

/// Die **einzige** Funktion, die ein [`SealedRecord`] in ein [`VisibleDatum`]
/// überführt — das Tor (§11.2). Sie **verlangt** eine [`Capability`]; ohne sie
/// gibt es **keinen** Weg zum Inhalt (§11.5 „immer aufgerufen").
///
/// ## Stand (Phase 0.5 — Form, nicht Logik)
///
/// Hier ist **nur die Form** eingefroren: Capability-gebundene Signatur, das
/// `SealedRecord → VisibleDatum`-Monopol. Die **Logik** (Phase 2) wird:
/// 1. **vor jeder Auflösung filtern** (§11.3): *Bereich des Daten ∈
///    `capability.scopes()`?* — reines strukturelles Matching (§1.3), mechanisch
///    (§1.7 a);
/// 2. bei Sichtbarkeit ein `VisibleDatum` liefern, sonst **VANISH** (`None`,
///    ununterscheidbar von „existiert nicht");
/// 3. bei Index-/Log-Inkonsistenz **fail-closed** ([`KernelError::Inconsistent`]
///    bzw. leeres Ergebnis).
///
/// Bis Phase 2 wird die Sichtbarkeit **noch nicht** ausgewertet; die Funktion
/// belegt allein, dass der **einzige** Inhalts-Pfad Capability-gebunden ist.
///
/// [`KernelError::Inconsistent`]: crate::error::KernelError::Inconsistent
pub fn open(record: &SealedRecord, capability: &Capability) -> Option<VisibleDatum> {
    // Phase 2: hier matcht das Tor `record`-Bereich ∈ `capability.scopes()`
    // (§11.2/§1.3) **vor** jeder Auflösung. Bis dahin nutzen wir die Capability
    // formal (kein toter Parameter) und legen den Inhalt frei.
    let _ = capability.scopes();
    Some(VisibleDatum {
        content_id: record.content_id,
        revealed: record.payload.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8) -> ContentId {
        ContentId::from_bytes([b; 32])
    }

    #[test]
    fn the_only_construction_path_compiles() {
        // Der **einzige** legale Weg zum Inhalt: Speicher versiegelt (crate-
        // intern) → Tor stellt Capability aus (crate-intern) → `open`.
        let record = SealedRecord::seal(cid(0x42));
        let cap = Capability::issue(GrantedScopes::from_scope_ids([cid(0x01)]));

        let visible = open(&record, &cap).expect("Skelett legt Inhalt frei");
        assert_eq!(visible.content_id(), cid(0x42));
        // `open` schöpft tatsächlich aus dem versiegelten Inhalt (Skelett-Spiegel).
        assert_eq!(visible.revealed_content_id(), cid(0x42));
    }

    #[test]
    fn sealed_record_exposes_only_its_address() {
        // §5.2: die Adresse ist nicht-geheim und die **einzige** öffentliche
        // Auskunft eines versiegelten Records. (Dass es keinen Inhalts-Getter
        // gibt, ist eine Compile-Zeit-Eigenschaft — siehe Modul-Doc.)
        let record = SealedRecord::seal(cid(0x07));
        assert_eq!(record.content_id(), cid(0x07));
    }

    // -------------------------------------------------------------------------
    // Compile-Zeit-Unumgehbarkeit (§11.5). Die folgenden Zeilen sind **bewusst
    // auskommentiert**: jede würde einen **Compile-Fehler** erzeugen und belegt
    // damit, dass „ohne Tor lesen" im Typsystem nicht darstellbar ist. Ein
    // `trybuild`-Test (Phase 2) friert das maschinell ein.
    //
    //   // (1) Capability außerhalb von `gate` konstruieren — privates Feld:
    //   let _ = Capability { scopes: ... };            // E0451: feld `scopes` privat
    //
    //   // (2) GrantedScopes von außen bauen — privates Feld:
    //   let _ = GrantedScopes { scope_ids: vec![] };   // E0451: feld privat
    //
    //   // (3) VisibleDatum direkt fälschen (Tor umgehen) — privates Feld:
    //   let _ = VisibleDatum { content_id: cid(0), revealed: ... }; // E0451
    //
    //   // (4) Inhalt aus SealedRecord ohne `open` ziehen — es gibt keine solche
    //   //     Methode (nur `content_id()`), also schon ein Name-Resolution-Fehler:
    //   let _ = SealedRecord::seal(cid(0)).payload;     // E0616: feld privat
    //
    //   // (5) Eigenen „Capability"-Typ in `open` einsetzen — `Sealed`-Schranke
    //   //     + konkreter Parametertyp verhindern jeden Fremd-Token.
    // -------------------------------------------------------------------------
    #[test]
    fn bypass_is_unrepresentable_documented() {
        // Dieser Test dokumentiert die Garantie und stellt sicher, dass die
        // legitimen Konstruktoren existieren; die Negativ-Fälle oben sind
        // Compile-Fehler (per Konstruktion).
        let _ = SealedRecord::seal(cid(0));
        let _ = Capability::issue(GrantedScopes::from_scope_ids([]));
    }
}
