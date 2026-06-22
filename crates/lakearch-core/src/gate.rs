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
//! ## Tor-Logik (Phase 2)
//!
//! Ab Phase 2 wertet [`open`] die **Sichtbarkeit** tatsächlich aus (§11.2/§11.3):
//!
//! - Ein **Bereich** ist ein Daten; **Zugehörigkeit** ist ein Kontext (ein Daten
//!   darf mehreren Bereichen angehören, §11.1). Ein [`SealedRecord`] trägt — vom
//!   Speicher server-seitig aus dem Zugehörigkeits-Index bestimmt — die Menge der
//!   Bereiche, denen sein Daten angehört.
//! - **Filter-vor-Auflösen (§11.3), reines Matching (§1.3):** sichtbar **gdw.**
//!   `Bereiche(Daten) ∩ gewährte Bereiche` nicht-leer ist. Ein Daten **ohne**
//!   Bereichs-Zugehörigkeit gilt als **unbeschränkt** (für alle sichtbar) —
//!   Bereiche sind *additive Restriktionen* (Policy-Default, in
//!   `DECISIONS-FOR-REVIEW.md` markiert).
//! - **VANISH (§11.3/§8.4):** ist das Daten nicht sichtbar, liefert [`open`]
//!   `None` — **ununterscheidbar** von „existiert nicht". Kein `<redacted>`, kein
//!   Existenz-Orakel über die berechenbaren Hash-IDs.
//! - **Match-only (§1.4/§11.5):** das Tor matcht ausschließlich Mengen-
//!   Zugehörigkeit; **keine** Zeitfenster-Auswertung (das wäre Ordnung →
//!   §1.4-Verstoß). „Aktiv" ist strukturell-im-Snapshot; die volle §13-Marker-
//!   Logik landet in Phase 5.
//!
//! Die Berechtigungs-*Ausstellung* (welche Bereiche ein Subjekt gewährt bekommt)
//! und das Read-Audit trägt der Daemon (§11, §8.4: Lesen erzeugt nichts).

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
    /// recht (VANISH wehrt das Existenz-Orakel ab).
    content_id: ContentId,
    /// Roh-Sicht auf den gespeicherten Inhalt. **Privat**; kein öffentlicher
    /// Getter. Erst [`open`] darf ihn — gegen eine Capability — freilegen.
    /// Trägt die durablen kanonischen Bytes (§K4); ab Phase 7 kann hier ein
    /// Zero-Copy-Segment-Handle stehen, ohne die Tor-Signatur zu ändern.
    payload: SealedPayload,
    /// Die **Bereiche**, denen das Daten angehört (§11.1), server-seitig aus dem
    /// Zugehörigkeits-Index bestimmt. **Privat**; das Tor matcht sie intern gegen
    /// die gewährten Bereiche (§11.2/§1.3) und gibt sie **nie** heraus
    /// (sichtbarkeits-blind, §11.3). Leer ⇒ unbeschränkt (Policy-Default).
    areas: Vec<ContentId>,
}

/// Privater Inhaltsträger eines [`SealedRecord`]. Bewusst ein eigener Typ, damit
/// keine `pub`-Felder durchsickern und die Roh-Sicht später (Phase 7) gegen einen
/// `Arc<SegmentHandle>+offset` (Zero-Copy) getauscht werden kann, **ohne** die
/// öffentliche Tor-Signatur zu ändern.
#[derive(Clone, Debug)]
struct SealedPayload {
    /// Die **kanonischen CBOR-Bytes** des Daten (§K4), wie sie durabel im Log
    /// liegen — die einzige Roh-Sicht auf den Inhalt. **Privat**; sie verlässt
    /// das Modul **ausschließlich** über [`open`] in einem [`VisibleDatum`].
    canonical_bytes: Vec<u8>,
}

impl SealedRecord {
    /// **Crate-interner** Konstruktor mit den durablen **kanonischen Bytes** des
    /// Daten (§K4) und den **Bereichen**, denen es angehört (§11.1, server-seitig
    /// bestimmt): nur Speicher/Kernel erzeugen versiegelte Records. Es gibt
    /// **keinen** öffentlichen Konstruktionsweg — damit ist „Record ohne Tor selbst
    /// bauen und auslesen" außerhalb des Crates unmöglich (§11.5).
    ///
    /// `areas` ist die — möglicherweise leere — Menge der Bereichs-`ContentId`s.
    /// Leer ⇒ **unbeschränkt** (Policy-Default, additive Restriktionen). Das Tor
    /// matcht sie in [`open`]; sie verlässt das Modul **nie** (sichtbarkeits-blind,
    /// §11.3).
    pub(crate) fn seal(
        content_id: ContentId,
        canonical_bytes: Vec<u8>,
        areas: Vec<ContentId>,
    ) -> Self {
        SealedRecord {
            content_id,
            payload: SealedPayload { canonical_bytes },
            areas,
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
/// `GrantedScopes` sind das **Eingabe-Subjekt** eines Lesevorgangs, das die
/// **Schicht darüber** dem Kernel vorlegt (§11.1) — sie sind daher öffentlich
/// **konstruierbar** ([`GrantedScopes::from_scope_ids`]). Das bricht die
/// Tor-Garantie **nicht**: das Tor (Phase 2) *validiert* sie gegen die
/// auditierten Berechtigungen im Snapshot, bevor es eine [`Capability`] ausstellt;
/// eine [`Capability`]/[`VisibleDatum`] bleibt unfälschbar (privat + `Sealed`).
/// Die Bereichs-Bytes selbst gibt das Feld **nicht** heraus (sonst Bereichs-Leak,
/// §11.3).
pub struct GrantedScopes {
    /// Bereichs-Daten-IDs (§11.1). Privat; das Tor matcht sie strukturell, gibt
    /// sie aber nicht heraus (sonst Bereichs-Leak, §11.3). Gelesen ab Phase 2
    /// (Tor-Logik) via `scope_ids()`.
    #[allow(dead_code)] // Phase 2: liest die Tor-Logik via `scope_ids()`.
    scope_ids: Vec<ContentId>,
}

impl sealed::Sealed for GrantedScopes {}

impl GrantedScopes {
    /// Konstruiert die **gewährten Bereiche**, die die Schicht darüber dem Kernel
    /// für einen Lesevorgang vorlegt (§11.1). Öffentlich, weil dies das
    /// **Eingabe-Subjekt** des Lesers ist — die Validierung gegen die auditierten
    /// Berechtigungen leistet das Tor (Phase 2), nicht der Aufrufer.
    pub fn from_scope_ids(scope_ids: impl IntoIterator<Item = ContentId>) -> Self {
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
    /// Freigelegte Inhalts-Sicht: die durablen **kanonischen Bytes** (§K4).
    /// Privat; ein Leser erschließt sie nur über die Methoden unten. (Ab Phase 7
    /// kann hier ein Zero-Copy-Lese-Handle stehen, ohne die Tor-Signatur zu
    /// ändern.)
    revealed: SealedPayload,
}

impl VisibleDatum {
    /// Die Adresse des sichtbaren Daten (§5.2).
    pub fn content_id(&self) -> ContentId {
        self.content_id
    }

    /// Die freigelegten **kanonischen CBOR-Bytes** (§K4) des Daten. Dies ist die
    /// einzige Stelle, an der die durable Roh-Sicht einen Leser erreicht — und
    /// **nur** nach Vorlage einer [`Capability`] an [`open`]. Die Bytes strikt zu
    /// dekodieren ist Sache der Schicht darüber ([`crate::serialize::strict_decode`]).
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.revealed.canonical_bytes
    }
}

/// Die **einzige** Funktion, die ein [`SealedRecord`] in ein [`VisibleDatum`]
/// überführt — das Tor (§11.2). Sie **verlangt** eine [`Capability`]; ohne sie
/// gibt es **keinen** Weg zum Inhalt (§11.5 „immer aufgerufen").
///
/// ## Sichtbarkeits-Logik (§11.2/§11.3, reines Matching §1.3)
///
/// 1. **Filter-vor-Auflösen (§11.3):** das Tor matcht *Bereiche des Daten ∩
///    gewährte Bereiche*. Ist die Schnittmenge nicht-leer, ist das Daten sichtbar;
///    ein Daten **ohne** Bereich gilt als **unbeschränkt** (Policy-Default —
///    additive Restriktionen, `DECISIONS-FOR-REVIEW.md`). Reines Mengen-Matching,
///    **kein** Wert/Ordnung (§1.4), mechanisch (§1.7 a).
/// 2. **Sichtbar:** liefert ein [`VisibleDatum`] mit den freigelegten kanonischen
///    Bytes.
/// 3. **VANISH (§11.3/§8.4):** nicht sichtbar ⇒ `None`, **ununterscheidbar** von
///    „existiert nicht" — kein `<redacted>`, kein Existenz-Orakel über die
///    berechenbaren Hash-IDs. Die Bereiche selbst verlassen das Tor **nie**
///    (sichtbarkeits-blind, §11.3).
///
/// **Fail-closed (§11):** das Tor entscheidet rein aus den im `SealedRecord`
/// versiegelten Bereichen und den gewährten Bereichen; eine Index-/Log-
/// Inkonsistenz fängt der **Speicher** vor dem Versiegeln ab
/// ([`KernelError::Inconsistent`]) und liefert dann gar kein `SealedRecord` —
/// das Tor sieht im Zweifel nichts und antwortet leer (DENY).
///
/// [`KernelError::Inconsistent`]: crate::error::KernelError::Inconsistent
pub fn open(record: &SealedRecord, capability: &Capability) -> Option<VisibleDatum> {
    // §11.3 Filter-vor-Auflösen: reines strukturelles Mengen-Matching (§1.3) der
    // Bereiche des Daten gegen die gewährten Bereiche. **Vor** jeder Freilegung.
    if !is_visible(&record.areas, capability.scopes().scope_ids()) {
        // VANISH (§11.3): nicht sichtbar ist ununterscheidbar von „existiert nicht".
        return None;
    }
    Some(VisibleDatum {
        content_id: record.content_id,
        revealed: record.payload.clone(),
    })
}

/// **Sichtbarkeits-Prädikat** (§11.2/§11.3) — reines Mengen-Matching (§1.3),
/// crate-intern auch von der Traversierung (Phase-A-Front, §11.3) genutzt.
///
/// `areas` = Bereiche des Daten; `granted` = gewährte Bereiche des Subjekts.
/// Sichtbar **gdw.**:
/// - `areas` ist **leer** (das Daten ist **unbeschränkt** — Policy-Default,
///   additive Restriktionen), **oder**
/// - `areas ∩ granted` ist nicht-leer (mindestens ein Bereich ist gewährt).
///
/// **Kein** Wert/Ordnung (§1.4): es wird nur Mengen-Zugehörigkeit gematcht. Die
/// Implementierung ist linear; beide Mengen sind klein (ein Daten gehört wenigen
/// Bereichen an).
pub(crate) fn is_visible(areas: &[ContentId], granted: &[ContentId]) -> bool {
    if areas.is_empty() {
        // Unbeschränkt (Policy-Default): keine Bereichs-Zugehörigkeit ⇒ für alle
        // sichtbar (Bereiche sind additive Restriktionen).
        return true;
    }
    areas.iter().any(|a| granted.contains(a))
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
        // Unbeschränktes Daten (keine Bereiche) ⇒ für alle sichtbar (Default).
        let record = SealedRecord::seal(cid(0x42), vec![0xA1, 0x00, 0x40], vec![]);
        let cap = Capability::issue(GrantedScopes::from_scope_ids([cid(0x01)]));

        let visible = open(&record, &cap).expect("Tor legt Inhalt frei");
        assert_eq!(visible.content_id(), cid(0x42));
        // `open` schöpft tatsächlich aus dem versiegelten Inhalt (die durablen
        // kanonischen Bytes).
        assert_eq!(visible.canonical_bytes(), &[0xA1, 0x00, 0x40]);
    }

    #[test]
    fn sealed_record_exposes_only_its_address() {
        // §5.2: die Adresse ist nicht-geheim und die **einzige** öffentliche
        // Auskunft eines versiegelten Records. (Dass es keinen Inhalts-Getter
        // gibt, ist eine Compile-Zeit-Eigenschaft — siehe Modul-Doc.)
        let record = SealedRecord::seal(cid(0x07), vec![0xA1, 0x00, 0x40], vec![]);
        assert_eq!(record.content_id(), cid(0x07));
    }

    // -- Sichtbarkeits-Logik (§11.2/§11.3) -----------------------------------

    #[test]
    fn visible_when_area_is_granted() {
        // Daten gehört Bereich 0x10 an; Subjekt hat 0x10 gewährt ⇒ sichtbar.
        let record = SealedRecord::seal(cid(0x42), vec![0xA1, 0x00, 0x40], vec![cid(0x10)]);
        let cap = Capability::issue(GrantedScopes::from_scope_ids([cid(0x10)]));
        let visible = open(&record, &cap).expect("Bereich gewährt ⇒ sichtbar");
        assert_eq!(visible.canonical_bytes(), &[0xA1, 0x00, 0x40]);
    }

    #[test]
    fn vanish_when_area_not_granted() {
        // Daten gehört Bereich 0x10 an; Subjekt hat nur 0x20 ⇒ VANISH (None,
        // ununterscheidbar von „existiert nicht", §11.3).
        let record = SealedRecord::seal(cid(0x42), vec![0xA1, 0x00, 0x40], vec![cid(0x10)]);
        let cap = Capability::issue(GrantedScopes::from_scope_ids([cid(0x20)]));
        assert!(open(&record, &cap).is_none(), "kein gewährter Bereich ⇒ VANISH");
    }

    #[test]
    fn unrestricted_datum_visible_to_all() {
        // Policy-Default: keine Bereichs-Zugehörigkeit ⇒ für alle sichtbar,
        // auch mit leeren gewährten Bereichen.
        let record = SealedRecord::seal(cid(0x42), vec![0xA1, 0x00, 0x40], vec![]);
        let cap = Capability::issue(GrantedScopes::from_scope_ids([]));
        assert!(open(&record, &cap).is_some(), "unbeschränkt ⇒ sichtbar");
    }

    #[test]
    fn multi_area_membership_visible_via_any_intersection(){
        // Ein Daten darf mehreren Bereichen angehören (§11.1); ein einziger
        // gewährter Bereich in der Schnittmenge genügt.
        let record = SealedRecord::seal(
            cid(0x42),
            vec![0xA1, 0x00, 0x40],
            vec![cid(0x10), cid(0x11), cid(0x12)],
        );
        let cap = Capability::issue(GrantedScopes::from_scope_ids([cid(0x99), cid(0x11)]));
        assert!(open(&record, &cap).is_some(), "ein gewährter Bereich genügt");
    }

    #[test]
    fn is_visible_predicate_is_pure_set_matching() {
        // Unbeschränkt ⇒ immer sichtbar.
        assert!(is_visible(&[], &[]));
        assert!(is_visible(&[], &[cid(1)]));
        // Schnittmenge nicht-leer ⇒ sichtbar.
        assert!(is_visible(&[cid(1), cid(2)], &[cid(2)]));
        // Disjunkt ⇒ nicht sichtbar.
        assert!(!is_visible(&[cid(1)], &[cid(2), cid(3)]));
        // Beschränkt, aber nichts gewährt ⇒ nicht sichtbar.
        assert!(!is_visible(&[cid(1)], &[]));
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
    //   let _ = SealedRecord::seal(cid(0), vec![], vec![]).payload;  // E0616: feld privat
    //
    //   // (5) Eigenen „Capability"-Typ in `open` einsetzen — `Sealed`-Schranke
    //   //     + konkreter Parametertyp verhindern jeden Fremd-Token.
    // -------------------------------------------------------------------------
    #[test]
    fn bypass_is_unrepresentable_documented() {
        // Dieser Test dokumentiert die Garantie und stellt sicher, dass die
        // legitimen Konstruktoren existieren; die Negativ-Fälle oben sind
        // Compile-Fehler (per Konstruktion).
        let _ = SealedRecord::seal(cid(0), vec![0xA1, 0x00, 0x40], vec![]);
        let _ = Capability::issue(GrantedScopes::from_scope_ids([]));
    }
}
