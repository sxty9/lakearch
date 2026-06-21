//! Der **eingefrorene Kernel-API-Vertrag** (§1) — Trait-Oberfläche, serialisierungs-
//! geformt.
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md` §1–§13 und der gehärtete Plan.
//! Dieses Modul friert in **Phase 0.5** nur die **Form** ein: die Verben, die
//! Newtypes, owned [`Step`]/Cursor, einen opaken [`SnapshotToken`] **an jeder
//! Read-Signatur**, die **drei** getrennten §1.3-Prädikate und die
//! **Umbenennungen** (Namen, die kein verbotenes Verhalten einladen). Die
//! *Semantik* der Verben landet phasenweise (siehe je Verb); die Stub-Bodies
//! geben [`KernelError::NotYetImplemented`] mit ihrer Phase zurück.
//!
//! ## Was der Kernel **ist** — und ausschließlich ist
//!
//! **append** als einzige Mutation (§7.1) · mechanische Vor-/Rückwärts-
//! Traversierung (§1.2, Visited-Set-beschränkt, zyklensicher §1.7 a) ·
//! **strukturelles Matching** (§1.3) · das **Zugriffs-Tor** (§11) ·
//! Inhaltsadressierung + Dedup (§5.2/§5.3) · Invalidierung = Rückwärts-
//! Traversierung (§10.3) · Atomarität über den Aktiv-Marker (§13).
//!
//! **Nicht** im Kernel (Schicht darüber, §1.4/§1.5): Rechnen, Werten, Sortieren,
//! Aggregieren, Konfidenz, Identitäts-*Entscheidung*, Eingabe-Validierung; „Platz
//! finden"/„Verbindung beurteilen"; Lese-Auflösung (Schwellen, Gewichtung,
//! Zeitpunkt, Zeitachse).

use crate::error::KernelError;
use crate::gate::{Capability, SealedRecord};
use crate::id::{AnchorId, ContentId};
use crate::model::Datum;

/// Opaker **Snapshot-Handle** (MVCC) — pinnt eine Lese-Epoche (§8.4/§13).
///
/// **Jeder** Read trägt einen `SnapshotToken`: Tor-Filter (§11) und Auflösung
/// (§9) laufen über **dasselbe** S, daher kein In-Kernel-TOCTOU. „Aktiv" heißt
/// **strukturell-aktiv-im-Snapshot S** (§13.2), **nie** ein Wall-Clock-Vergleich
/// (das wäre Ordnung → §1.4-Verstoß). Welche Berechtigung/Version für einen
/// *Zeitpunkt* gilt, ist eine Lese-Projektion der Schicht darüber (§6.4/§8.2).
///
/// Der innere Wert ist privat (opak): außerhalb des Crates **nicht**
/// konstruierbar; ein Token erhält man ab Phase 5 nur vom Kernel
/// ([`Kernel::pin_snapshot`]). Volle Epochen-Semantik (§13) folgt in Phase 5.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotToken {
    /// Die durable Commit-Watermark `W` = Offset des letzten durablen Records
    /// (eine Linearisierungsstelle; §13). Privat — der Wert ist ein Handle, kein
    /// öffentlich rechenbarer Index (§1.4).
    watermark: u64,
}

impl SnapshotToken {
    /// **Crate-interner** Konstruktor (ab Phase 5 aus der publizierten
    /// Watermark). Kein öffentlicher Weg — ein Token ist nicht fälschbar.
    #[allow(dead_code)] // Phase 5: pinnt der Kernel; jetzt nur Tests + Form.
    pub(crate) fn at_watermark(watermark: u64) -> Self {
        SnapshotToken { watermark }
    }

    /// Crate-interne Sicht auf die gepinnte Watermark (Sichtbarkeits-Filter,
    /// Phase 5). Bewusst nicht `pub`.
    #[allow(dead_code)] // Phase 5: liest der Sichtbarkeits-Filter (§13).
    pub(crate) fn watermark(&self) -> u64 {
        self.watermark
    }
}

/// Traversier-**Richtung** entlang der Besitz-/Kontext-Kanten (§1.2/§3.2).
///
/// Besitz ist **gerichtet** (§3.2): `Forward` folgt `Owner → besessene Kontexte`
/// (bzw. Verweis-Ziele, §3.3); `Backward` folgt `Ziel → Verweiser` (die
/// Rückwärts-Traversierung der Invalidierung, §10.3); `Both` beide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Vom Besitzer zu seinen besessenen Kontexten / Verweis-Zielen (§3.2/§3.3).
    Forward,
    /// Von einem Ziel zu seinen Verweisern (Rückwärts-Traversierung, §10.3).
    Backward,
    /// Beide Richtungen.
    Both,
}

/// Ein **Schritt** der Traversierung (§1.2) — owned, föderationsstabil
/// serialisierbar.
///
/// Ein Step ist eine durchschrittene **Kante**: von `from` über den Kontext
/// `edge_ctx` (das besessene Daten in seiner Kanten-Rolle, §3.1/§3.3) zu `to`,
/// in Tiefe `depth` ab dem Start. Die Kante existiert physisch **nur** als
/// abgeleiteter Index-Eintrag und hat **keine** eigene `ContentId` (§3.1/§2.2);
/// `edge_ctx` ist die ID des **besessenen Kontext-Daten**, nicht einer „Edge-
/// Entität".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Step {
    /// Quell-Daten der Kante.
    pub from: ContentId,
    /// Das besessene Kontext-Daten in seiner Kanten-Rolle (§3.1/§3.3) — **keine**
    /// eigene Entität (§2.2), nur die ID des besessenen Daten.
    pub edge_ctx: ContentId,
    /// Ziel-Daten der Kante.
    pub to: ContentId,
    /// Tiefe ab dem Start (Start = 0). Reines Mechanik-Maß der beschränkten
    /// Traversierung (§1.7 a), **kein** Wert/Ordnung über die Daten (§1.4).
    pub depth: u32,
}

/// Owned **Step-Strom** der Traversierung. Boxed Iterator (kein `async` im
/// Kernel — `async` lebt nur am Netz-Rand; der Kern ist sync-threaded).
///
/// Der Strom ist server-seitig **beschränkt** (Visited-Set, Tiefe/Knoten-Budget;
/// §1.7 a) und am Start **snapshot-gepinnt** (§13). Jedes Element ist ein
/// [`Step`] oder ein definierter [`KernelError`] (Budget/Abbruch/Inkonsistenz).
pub type StepStream<'a> = Box<dyn Iterator<Item = Result<Step, KernelError>> + Send + 'a>;

/// Die **gewährten Bereiche eines Subjekts**, wie die Schicht darüber sie dem
/// Kernel für einen Lesevorgang vorlegt (§11.1). Im Daemon stellt das Tor daraus
/// — gegen die auditierten Berechtigungen im Snapshot — eine [`Capability`] aus
/// (Phase 2). Hier nur als **Form** des Lese-Subjekts referenziert.
///
/// (Konkrete Konstruktion crate-intern in [`crate::gate`]; siehe dort.)
pub use crate::gate::GrantedScopes;

/// Der eingefrorene **Kernel-Vertrag** (§1). Jeder Read trägt einen
/// [`SnapshotToken`] und geht durchs Tor (§11); die einzigen Mutationen sind
/// [`append`](Kernel::append) und [`set_active_marker`](Kernel::set_active_marker)
/// (§7.1).
///
/// Alle Bodies sind in Phase 0.5 **Stubs** ([`KernelError::NotYetImplemented`]);
/// die Form ist eingefroren, die Semantik landet je Verb in ihrer Phase.
pub trait Kernel {
    // ------------------------------------------------------------------
    // Snapshots (§8.4/§13) — Phase 5 (volle Epochen-Semantik).
    // ------------------------------------------------------------------

    /// Pinnt einen MVCC-Snapshot und liefert seinen opaken [`SnapshotToken`]
    /// (§8.4/§13). **Phase 5.** Ein Token ist die **einzige** Quelle für jede
    /// Read-Signatur; so laufen Tor (§11) und Auflösung (§9) über dasselbe S.
    fn pin_snapshot(&self) -> Result<SnapshotToken, KernelError> {
        Err(KernelError::NotYetImplemented(5))
    }

    /// Stellt für ein Subjekt (dessen [`GrantedScopes`]) eine [`Capability`] aus
    /// — nach **strukturellem** Matching der aktiven Berechtigungen im Snapshot
    /// (§11.2/§1.3). **Phase 2 (Tor-Logik).** Die ausgestellte Capability ist
    /// der unfälschbare Tor-Nachweis für [`get_by_content_id`](Kernel::get_by_content_id).
    fn authorize(
        &self,
        scopes: GrantedScopes,
        snapshot: SnapshotToken,
    ) -> Result<Capability, KernelError> {
        let _ = (scopes, snapshot);
        Err(KernelError::NotYetImplemented(2))
    }

    // ------------------------------------------------------------------
    // Mutationen (§7.1) — die EINZIGEN. Phase 1 (append) / Phase 5 (Marker).
    // ------------------------------------------------------------------

    /// **append** — die **einzige** Mutation (§7.1): genau ein neues Daten samt
    /// seinen Kontexten kommt hinzu; nie geändert, nie gelöscht. Inhaltsgleiches
    /// dedupliziert automatisch (§5.3) und schreibt **nichts** Neues. Liefert die
    /// [`ContentId`] des (ggf. schon vorhandenen) Daten. **Phase 1.**
    ///
    /// `append` **rechnet und wertet nicht** (§7.3); es findet **nicht** den
    /// Platz und beurteilt **nicht** die Verbindung (§7.2) — es nimmt das fertige
    /// Ergebnis der schreibenden Schicht auf.
    fn append(&self, datum: &Datum) -> Result<ContentId, KernelError> {
        let _ = datum;
        Err(KernelError::NotYetImplemented(1))
    }

    /// **set_active_marker** — die einzige andere „Änderung" (§7.1/§13): selbst
    /// ein **Append** des Marker-Daten, das die Sichtbarkeits-Epoche umlegt
    /// (§13.1), **keine** In-Place-Mutation. Bis der Marker gesetzt ist, gelten
    /// die Konstituenten als inaktiv (§13.2); ein halb-vollzogener Umbau bleibt
    /// unsichtbar (§13.3). `constituents` = die `ContentId`s der gemeinsam
    /// sichtbar werdenden Daten. **Phase 5.**
    fn set_active_marker(
        &self,
        constituents: &[ContentId],
    ) -> Result<ContentId, KernelError> {
        let _ = constituents;
        Err(KernelError::NotYetImplemented(5))
    }

    // ------------------------------------------------------------------
    // Lesen einer Adresse (§5.2) — geht DURCHS TOR. Phase 1 (Form) / Phase 2 (Logik).
    // ------------------------------------------------------------------

    /// **get_by_content_id** (§5.2-Fetch) — geht **ebenfalls** durchs Tor (§11):
    /// liefert ein opakes [`SealedRecord`], dessen Inhalt **nur** [`crate::gate::open`]
    /// gegen die [`Capability`] freilegt. Verborgen und „nicht vorhanden" sind
    /// **ununterscheidbar** (VANISH; sonst Existenz-Orakel über berechenbare
    /// Hash-IDs, §11.3). `None` ⇒ nicht sichtbar **oder** nicht vorhanden — der
    /// Leser kann es nicht unterscheiden. **Phase 1** liefert `SealedRecord`,
    /// **Phase 2** die Tor-Sichtbarkeitslogik.
    fn get_by_content_id(
        &self,
        id: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Option<SealedRecord>, KernelError> {
        let _ = (id, capability, snapshot);
        Err(KernelError::NotYetImplemented(1))
    }

    // ------------------------------------------------------------------
    // Strukturelles Matching — die DREI §1.3-Prädikate, GETRENNT.
    // Kein generischer Wert-Prädikat-Schmuggel. Phase 2.
    // ------------------------------------------------------------------

    /// §1.3 (i) **Gleichheit auf Inhalts-/Adressebene**: tragen `a` und `b`
    /// dieselbe `ContentId`? Reines Adress-Matching (§5.2), **kein** Wert-
    /// Vergleich (§1.4). **Phase 2.**
    fn content_equal(
        &self,
        a: ContentId,
        b: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = (a, b, snapshot);
        Err(KernelError::NotYetImplemented(2))
    }

    /// §1.3 (ii) **„zeigt ein Kontext auf ein Daten?"**: besitzt — bzw. zielt —
    /// der Kontext `ctx` auf `target` (§3.3)? Reines strukturelles Matching, kein
    /// Wert (§1.4). **Phase 2.**
    fn context_points_to(
        &self,
        ctx: ContentId,
        target: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = (ctx, target, snapshot);
        Err(KernelError::NotYetImplemented(2))
    }

    /// §1.3 (iii) **Zugehörigkeit zu einer per Kontext gegebenen Menge**: ist
    /// `elem` Mitglied der Menge, die der Mengen-Kontext `set_ctx` aufspannt?
    /// Reines Mengen-Matching, **kein** Wert/Ordnung (§1.4). **Phase 2.**
    fn is_member_of_set(
        &self,
        elem: ContentId,
        set_ctx: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = (elem, set_ctx, snapshot);
        Err(KernelError::NotYetImplemented(2))
    }

    // ------------------------------------------------------------------
    // Mechanische Traversierung (§1.2/§1.7 a). Phase 2.
    // ------------------------------------------------------------------

    /// **traverse** — beschränkte, zyklensichere Vor-/Rückwärts-Traversierung
    /// (§1.2/§1.7 a). Liefert einen owned [`StepStream`]:
    ///
    /// - `start` — Start-Daten; `dir` — [`Direction`];
    /// - `max_depth`/`max_nodes` — **Budget** der beschränkten Traversierung
    ///   (§1.7 a); Überschreitung ⇒ [`KernelError::TraversalBudgetExceeded`];
    /// - `edge_type_filter` — `Some([…])` matcht **strukturell** auf das
    ///   Relations-Daten (§3.3), **nie** Wert (§1.4); `None` = kein Filter;
    /// - `snapshot` — am Start gepinnt (§13), server-seitiges Visited-Set
    ///   (zyklensicher, §1.6/§1.7 a).
    ///
    /// **Deterministischer Tiebreak:** aufsteigende `ContentId`-Byte-Order
    /// (föderationsstabil; §5.2 „adressiert, urteilt nicht") — dokumentiert als
    /// **kein** Wert-Sort (§1.4). **Phase 2** (Logik + Tor).
    fn traverse<'a>(
        &'a self,
        start: ContentId,
        dir: Direction,
        max_depth: u32,
        max_nodes: u64,
        edge_type_filter: Option<&'a [ContentId]>,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let _ = (start, dir, max_depth, max_nodes, edge_type_filter, snapshot);
        Err(KernelError::NotYetImplemented(2))
    }

    // ------------------------------------------------------------------
    // Anker / referenzielle Identität (§9). Umbenannt: liefert ROHE Kanten
    // inkl. Grad-Kontext-IDs — die Schicht darüber liest den Grad und
    // entscheidet (§5.5/§9.3). Phase 4.
    // ------------------------------------------------------------------

    /// **get_anchor_members** — liefert die **rohen** Mitgliedschafts-Kanten vom
    /// Anker `anchor` zu seinen Repräsentanten, **inklusive** der Grad-Kontext-
    /// IDs (§5.5/§9.3). Der Kernel **liest** nur (§1.3); den Grad **liest und
    /// entscheidet** die Schicht darüber (§1.4). Umbenannt von `resolve_anchor`,
    /// damit der Name kein Auflösen/Werten einlädt. **Phase 4.**
    fn get_anchor_members<'a>(
        &'a self,
        anchor: AnchorId,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let _ = (anchor, snapshot);
        Err(KernelError::NotYetImplemented(4))
    }

    /// **get_member_anchors** — die Gegenrichtung: liefert die **rohen**
    /// Mitgliedschafts-Kanten von einem Repräsentanten `member` zu den Ankern,
    /// denen er angehört (ein Daten darf mehreren angehören, §9.1), inkl. Grad-
    /// Kontext-IDs (§5.5/§9.3). **Phase 4.**
    fn get_member_anchors<'a>(
        &'a self,
        member: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let _ = (member, snapshot);
        Err(KernelError::NotYetImplemented(4))
    }

    // ------------------------------------------------------------------
    // Materialisierung & Invalidierung (§10). Umbenannt: der Kernel LÄUFT NUR
    // rückwärts (§10.3); „als stale markieren" ist ein Append der Schicht
    // darüber (§7.1/§6.3). Phase 6.
    // ------------------------------------------------------------------

    /// **find_dependents** — findet die von `input` abhängigen materialisierten
    /// Ergebnisse durch **Rückwärts-Traversierung** der Herkunfts-Kontexte
    /// (§10.2/§10.3). Der Kernel **läuft nur** rückwärts und matcht (§1.3); das
    /// **Als-stale-markieren** und Neu-Berechnen liegt außerhalb (§1.5/§7.1).
    /// Umbenannt von `invalidate`, damit der Name keine Mutation/Wertung
    /// einlädt. **Phase 6.**
    fn find_dependents<'a>(
        &'a self,
        input: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let _ = (input, snapshot);
        Err(KernelError::NotYetImplemented(6))
    }

    /// **traverse_provenance_backward** — die allgemeine Rückwärts-Traversierung
    /// der Herkunfts-Kontexte ab `result`, beschränkt durch `max_depth`/
    /// `max_nodes` (§10.3/§1.7 a). Mechanisch, zyklensicher; **kein** Neu-
    /// Berechnen (§1.5). **Phase 6.**
    fn traverse_provenance_backward<'a>(
        &'a self,
        result: ContentId,
        max_depth: u32,
        max_nodes: u64,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let _ = (result, max_depth, max_nodes, snapshot);
        Err(KernelError::NotYetImplemented(6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimaler **Form-Beweis**: ein Typ kann `Kernel` mit allen Default-Stubs
    /// implementieren (die Trait-Form ist konsistent), und die Stubs liefern
    /// ihre Phase. Dieser Stub wird **nicht** im Produktiv-Pfad benutzt.
    struct StubKernel;
    impl Kernel for StubKernel {}

    fn cid(b: u8) -> ContentId {
        ContentId::from_bytes([b; 32])
    }

    #[test]
    fn stub_verbs_report_their_phase_not_panic() {
        // Kein Verb panickt; jedes meldet NotYetImplemented mit seiner Phase.
        let k = StubKernel;
        assert!(matches!(
            k.pin_snapshot(),
            Err(KernelError::NotYetImplemented(5))
        ));
        assert!(matches!(
            k.append(&Datum::leaf([0x01])),
            Err(KernelError::NotYetImplemented(1))
        ));
        assert!(matches!(
            k.set_active_marker(&[cid(1), cid(2)]),
            Err(KernelError::NotYetImplemented(5))
        ));
    }

    #[test]
    fn read_verbs_carry_a_snapshot_token_and_compile() {
        // Form-Check: jede Read-Signatur akzeptiert einen SnapshotToken.
        let k = StubKernel;
        let snap = SnapshotToken::at_watermark(0);
        assert!(k.content_equal(cid(1), cid(1), snap).is_err());
        assert!(k.context_points_to(cid(1), cid(2), snap).is_err());
        assert!(k.is_member_of_set(cid(1), cid(2), snap).is_err());
        assert!(k.get_by_content_id_compiles(snap));
        assert!(k
            .traverse(cid(1), Direction::Both, 4, 100, None, snap)
            .is_err());
        assert!(k.get_anchor_members(AnchorId::new(1), snap).is_err());
        assert!(k.get_member_anchors(cid(1), snap).is_err());
        assert!(k.find_dependents(cid(1), snap).is_err());
        assert!(k
            .traverse_provenance_backward(cid(1), 4, 100, snap)
            .is_err());
    }

    impl StubKernel {
        /// `get_by_content_id` braucht eine `Capability`; die ist außerhalb von
        /// `gate` nicht konstruierbar. Wir prüfen daher nur, dass die Form über
        /// `authorize` (ebenfalls Stub) konsistent ist und nicht panickt.
        fn get_by_content_id_compiles(&self, snap: SnapshotToken) -> bool {
            matches!(
                self.authorize(GrantedScopes::from_scope_ids([]), snap),
                Err(KernelError::NotYetImplemented(2))
            )
        }
    }

    #[test]
    fn step_is_owned_and_copy() {
        // Step ist owned + Copy (föderationsstabil serialisierbar).
        let s = Step {
            from: cid(1),
            edge_ctx: cid(2),
            to: cid(3),
            depth: 0,
        };
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }
}
