//! Die konkrete **Kernel-Implementierung** ([`LakearchKernel`]) — die
//! Verdrahtung der Phase-1-Verben des eingefrorenen [`crate::api::Kernel`]-
//! Vertrags an den durablen Speicher.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2/§5.3 Identität &
//! Dedup; §7.1 append-only als einzige Mutation; §8.4 Log = alleinige Wahrheit;
//! §11 das Zugriffs-Tor) und der gehärtete Plan (Abschnitte „Kernel-API-Vertrag",
//! „Durability, Recovery & Atomarität", „Betrieb & Beobachtbarkeit").
//!
//! ## Was diese Phase verdrahtet
//!
//! - **[`Kernel::append`]** (§7.1) — die **einzige** Mutation: ein Daten samt
//!   seinen besessenen Kontexten kommt hinzu; Content-Dedup (§5.3) schreibt
//!   nichts und verbraucht keine seq; die abgeleiteten Kanten werden **erst nach**
//!   dem Log-`fsync` in den Index committet (Ordnung log-fsync → index-commit,
//!   §8.4).
//! - **[`Kernel::get_by_content_id`]** (§5.2-Fetch) — geht durchs Tor (§11):
//!   liefert ein opakes [`SealedRecord`], dessen Inhalt **nur** [`crate::gate::open`]
//!   gegen eine [`Capability`] freilegt. So kann **kein** Aufrufer die Bytes ohne
//!   das (Phase-2-)Tor lesen.
//!
//! Die Snapshot-/Capability-Verben sind in dieser Phase **minimal** verdrahtet,
//! damit ein Ende-zu-Ende-Lesepfad existiert; ihre **volle** Semantik landet in
//! ihren Phasen (siehe je Verb). Alle übrigen Verben (Matching, Traversierung,
//! Anker, Provenance, Aktiv-Marker) bleiben die phasenrichtigen
//! [`KernelError::NotYetImplemented`]-Stubs des Trait-Defaults.
//!
//! ## Nebenläufigkeit (Phase 1)
//!
//! Der [`crate::store::ContentStore`] ist der **eine** Append-Pfad (`&mut self`).
//! Da der `Kernel`-Vertrag jeden Verb über `&self` führt, kapselt
//! [`LakearchKernel`] den Store hinter einem [`std::sync::RwLock`]: `append`
//! nimmt den Schreib-Lock, Lesepfade den Lese-Lock. Ein **vergifteter Lock**
//! (ein Panic hielt ihn) ⇒ [`KernelError::Poisoned`] (fail-closed, §11). Die volle
//! lock-freie MPSC-/Group-Commit-Pipeline folgt in einer späteren Phase.
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: das `unsafe` lebt allein im
//! `mmap`-Leaf [`crate::log`].

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

use crate::api::{Direction, Kernel, SnapshotToken, StepStream};
use crate::compaction::{
    self, CompactedSegment, CompactionPlan, CompactionReport, Compactor, Generation, Keystore,
};
use crate::crypto::ErasureKey;
use crate::error::KernelError;
use crate::gate::{Capability, GrantedScopes, SealedRecord};
use crate::id::{AnchorId, ContentId};
use crate::index::EdgeIndex;
use crate::log::SegmentLog;
use crate::model::Datum;
use crate::store::{ContentStore, StagedHandle};
use crate::traverse::{run_traversal, CancelFlag, TraversalParams};

/// Aggregierte **Betriebs-Zähler** des Kernels (§Betrieb). Reine Mechanik-Signale
/// (§1.4): keine Wertung, **keine** sichtbaren Daten/IDs/Bereiche in Labels
/// (sichtbarkeits-blind, §11.3).
///
/// Sie fasst die Zähler des [`crate::store::ContentStore`] und des
/// [`crate::log::SegmentLog`] zu **einer** Lese-Sicht zusammen, wie sie der
/// Betrieb/Backup-Layer braucht (Append-Zahl, Dedup-Treffer, `fsync`-Zahl,
/// Log-Bytes, Segmentzahl).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KernelMetrics {
    /// Anzahl **physisch geschriebener** Daten (neue Records; ohne Dedup-Treffer).
    pub append_count: u64,
    /// Anzahl **Dedup-Treffer** (§5.3): inhaltsgleiches `append`, das **nichts**
    /// geschrieben hat.
    pub dedup_hit_count: u64,
    /// Anzahl in den Index committeter Kanten (über alle Appends/Rebuilds).
    pub edge_count: u64,
    /// Anzahl committeter Batches (Group-Commit-`fsync`s der Daten).
    pub batch_count: u64,
    /// Anzahl `fsync`-Aufrufe (Daten **und** Verzeichnis) im Log.
    pub fsync_count: u64,
    /// Anzahl Segmente im Log (in v1 stets 1).
    pub segment_count: u64,
    /// Committete Log-Bytes (= durable Watermark `W`, der committed offset).
    pub committed_bytes: u64,
    /// Anzahl **Fail-closed-Ereignisse** (§11): Lese-/Tor-/Traversier-Pfade, die
    /// wegen Index-/Log-Inkonsistenz **DENY** gewählt haben. Sichtbarkeits-blind
    /// (§11.3): zählt nur **dass** es geschah, nie **was**.
    pub fail_closed_count: u64,
}

/// Die konkrete **Kernel-Implementierung**: besitzt den
/// [`crate::store::ContentStore`] (und damit das Segment-Log + den Content-Store +
/// die Kanten-Indizes) und implementiert die Phase-1-Verben des
/// [`Kernel`]-Vertrags.
///
/// Generisch über die [`EdgeIndex`]-Engine (billig revidierbar, §Storage-Engine);
/// die Standard-Konstruktion ([`LakearchKernel::open`]) nutzt die pure-Rust-redb-
/// Engine.
pub struct LakearchKernel<I: EdgeIndex> {
    /// Der Content-Store hinter einem Lese-/Schreib-Lock. Der Store ist der eine
    /// Append-Pfad (`&mut self`); der Lock erlaubt den `&self`-Vertrag des Traits.
    store: RwLock<ContentStore<I>>,
    /// **Basis-Verzeichnis** des Bestands (für Compaction-Generationen §15). `None`,
    /// wenn der Kernel über [`from_store`](LakearchKernel::from_store) ohne Pfad
    /// gebaut wurde — dann ist [`compact`](LakearchKernel::compact) nicht verfügbar.
    base_dir: Option<PathBuf>,
    /// **Ausstehende Erasure** (§15): der Crypto-Shred-Plan, den eine gegatete,
    /// auditierte [`erase`](LakearchKernel::erase) füllt und die nächste
    /// [`compact`](LakearchKernel::compact) anwendet (sie versiegelt die erasten
    /// Nutzlasten). Hinter einem eigenen `Mutex` (orthogonal zum Store-Lock).
    pending: Mutex<CompactionPlan>,
}

impl<I: EdgeIndex> LakearchKernel<I> {
    /// Baut einen Kernel über einem bereits geöffneten [`ContentStore`]. Beim
    /// Öffnen hat der Store seine reinen Derivate (Dedup-Karte, Index) bereits aus
    /// dem Log rekonstruiert/versöhnt (§8.4).
    pub fn from_store(store: ContentStore<I>) -> Self {
        LakearchKernel {
            store: RwLock::new(store),
            base_dir: None,
            pending: Mutex::new(CompactionPlan::new()),
        }
    }

    /// Wie [`from_store`](LakearchKernel::from_store), aber mit dem **Basis-Verzeichnis**
    /// des Bestands — Voraussetzung für [`compact`](LakearchKernel::compact) (die
    /// compactierten Generationen leben unter `base_dir/compacted/`, §15).
    pub fn from_store_at(store: ContentStore<I>, base_dir: PathBuf) -> Self {
        LakearchKernel {
            store: RwLock::new(store),
            base_dir: Some(base_dir),
            pending: Mutex::new(CompactionPlan::new()),
        }
    }

    /// **Gegatete, beschränkte mechanische Traversierung** (§1.7 a) mit explizit
    /// vorgelegter [`Capability`] und kooperativem [`CancelFlag`] — der volle
    /// Phase-2-Einstieg.
    ///
    /// Diese konkrete Methode trägt — anders als die frozen-Form-`Kernel::traverse`
    /// — die [`Capability`] des Subjekts, sodass das Tor (§11.3) die Sichtbarkeit
    /// gegen die **gewährten Bereiche** matchen kann: nicht-sichtbare Nachbarn sind
    /// interne Front-Stopps (VANISH) und verändern die Ergebnisform nicht. Der
    /// Snapshot ist am `snapshot`-Token gepinnt (§1.7 a/§13): sein Watermark `W`
    /// fixiert die §13-Aktiv-Sicht für den **ganzen** Lauf (eine Linearisierungs-
    /// stelle, Snapshot-Isolation — kein Re-Lesen des Live-Watermarks).
    ///
    /// Liefert einen owned [`StepStream`]; jeder Schritt ist ein [`crate::api::Step`] oder ein
    /// definierter [`KernelError`] (Budget/Abbruch/Inkonsistenz — fail-closed §11).
    /// Der Strom ist durch `max_nodes` speicher-beschränkt (kein unbeschränkter
    /// Speicher, §1.7 a).
    pub fn traverse_with<'a>(
        &'a self,
        params: TraversalParams,
        capability: &Capability,
        snapshot: SnapshotToken,
        cancel: &CancelFlag,
    ) -> Result<StepStream<'a>, KernelError> {
        // §13: das am Token gepinnte Watermark `W` fixiert den Snapshot (ein Acquire-
        // Load; eine Linearisierungsstelle) — es wird in `run_traversal` für den ganzen
        // Lauf verwendet, nicht das (evtl. vorangerückte) Live-Watermark.
        let w = snapshot.watermark();
        // Den `edge_type_filter` an der **Verb-Grenze** normalisieren (aufsteigend
        // sortiert + dedupliziert, §1.3/§1.7 a): ein vom Aufrufer direkt befülltes
        // `TraversalParams` darf einen unsortierten Filter tragen — die
        // `binary_search`-Mitgliedschafts-Prüfung in `run_traversal` setzt aber
        // Sortierung voraus (sonst über-/unter-inklusive Treffer + Determinismus-
        // Bruch). `TraversalParams::new` stellt die Invariante her; `run_traversal`
        // prüft sie zusätzlich defensiv.
        let params = TraversalParams::new(
            params.start,
            params.dir,
            params.max_depth,
            params.max_nodes,
            params.edge_type_filter,
        );
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let steps = run_traversal(&store, capability, &params, cancel, w);
        Ok(Box::new(steps.into_iter()))
    }

    /// **Berechtigungs-basierte Autorisierung** (§11.1/§11.2) — der volle
    /// Tor-Einstieg: stellt für ein **Subjekt** eine [`Capability`] aus, deren
    /// gewährte Bereiche der Kernel aus den **aktiven** Berechtigungen im Snapshot
    /// **strukturell** ableitet (§11.2/§1.3) — alle Bereiche von Berechtigungen,
    /// deren Subjekt `subject` ist und die **nicht** entzogen sind (§11.4).
    ///
    /// „Aktiv" ist eine **strukturelle** Notion (§11.5): eine Berechtigung gilt,
    /// solange kein Entzugs-Kontext sie im Snapshot benennt — **kein** Wall-Clock-
    /// Vergleich (das wäre Ordnung → §1.4). Ein frisch angehängter Entzug verbirgt
    /// damit **künftige** Lesevorgänge des Daten-Bereichs (§11.4); bereits Gelesenes
    /// bleibt (§6.3).
    ///
    /// Diese konkrete Methode ergänzt die frozen-Form-[`Kernel::authorize`] (die das
    /// Subjekt-Konzept noch nicht trägt und die Scopes direkt entgegennimmt) — analog
    /// zu [`LakearchKernel::traverse_with`] gegenüber [`Kernel::traverse`]. Der
    /// `snapshot` pinnt die Lese-Epoche (Phase 1/2: die committete Watermark `W`;
    /// volle §13-Epoche: Phase 5).
    pub fn authorize_subject(
        &self,
        subject: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<Capability, KernelError> {
        let _ = snapshot;
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        // §11.2 strukturelles Matching: die aktiven (nicht entzogenen) Bereiche des
        // Subjekts. Reines Mengen-Matching (§1.3), kein Wall-Clock (§1.4).
        let areas = store.granted_areas_for_subject(subject);
        Ok(Capability::issue(GrantedScopes::from_scope_ids(areas)))
    }

    /// **resolve_placeholder** (§3.6 + §6.3) — die strukturelle **Auflösung** eines
    /// Platzhalters über die öffentliche Kernel-Oberfläche: das echte Ziel `real` ist
    /// eingetroffen und ersetzt den Platzhalter `placeholder` (append-only, §7.1).
    ///
    /// Delegiert an [`crate::store::ContentStore::resolve_placeholder`] (Schreib-Lock):
    /// hängt `real` an, baut den **Ersetzungs-Kontext** [`Datum::supersedes`]`(placeholder)`
    /// und einen Auflösungs-Knoten, der Platzhalter→real verknüpft (§6.3). Liefert
    /// `(real_id, resolution_id)`. Der auflösende Pfad ist anschließend über
    /// [`LakearchKernel::placeholder_resolvers_visible`] (gegatet) erreichbar.
    ///
    /// Der Kernel **validiert nicht** (§1.4/§7.2): er prüft **nicht**, ob `placeholder`
    /// ein Platzhalter ist — die Geschlossenheit erzwingt die schreibende Schicht (§3.6).
    pub fn resolve_placeholder(
        &self,
        placeholder: ContentId,
        real: &Datum,
    ) -> Result<(ContentId, ContentId), KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.resolve_placeholder(placeholder, real)
    }

    /// **append_restructuring** (§13) — die **atomare** Mehr-Daten-„Änderung": ein
    /// Umbau, der **mehrere Daten** betrifft (Zusammenführen/Spalten §9, Berechtigungs-
    /// Wechsel §11), wird durch **ein einziges abschließendes Aktiv-Schreiben** (den
    /// Marker) **gemeinsam sichtbar** (§13.1). Bis der Marker durabel ist, gelten alle
    /// `constituents` als **inaktiv** und werden von **jedem** Lesepfad ignoriert
    /// (`get_by_content_id`, Traversierung, alle gegateten Helfer — §13.2); der Marker-
    /// Commit flippt sie **gemeinsam** sichtbar (§13.3, Atomarität ohne Transaktions-
    /// Maschinerie).
    ///
    /// `constituents` = die gemeinsam sichtbar werdenden Daten (jedes wird als
    /// **bedingter Konstituent** angehängt, gestempelt mit dem Offset des regierenden
    /// Markers); `marker` = das abschließende **Marker-Daten**, dessen Commit den Umbau
    /// freigibt. Liefert `(constituent_ids, marker_id)`. Delegiert an
    /// [`crate::store::ContentStore::append_restructuring`] (Schreib-Lock; der Store ist
    /// der eine Append-Pfad).
    ///
    /// **Crash-Atomarität (§13.3):** crasht es **nach** den Konstituenten, aber **vor**
    /// dem Marker-`fsync`, bleiben die Konstituenten für immer **inaktiv** (ihr
    /// Marker-Offset liegt über dem durablen Watermark `W`, das die Recovery auf den
    /// letzten voll-durablen Record setzt) — ein halb-vollzogener Umbau ist nie
    /// sichtbar.
    ///
    /// **`set_active_marker`-Bezug.** Dies ist der **konkrete**, voll typisierte
    /// Restructuring-Einstieg — analog zu [`LakearchKernel::traverse_with`] gegenüber
    /// der frozen-Form-[`Kernel::traverse`]. Die eingefrorene Phase-0.5-Trait-Form
    /// [`Kernel::set_active_marker`]`(constituents: &[ContentId])` bleibt unangetastet
    /// (sie nimmt nur **schon vorhandene** IDs entgegen und kann daher die bedingten
    /// Konstituenten nicht **stagen**); das §13-Staging+Marker-Modell verlangt die
    /// **Daten** selbst, weil sie als bedingte Records geschrieben werden müssen.
    pub fn append_restructuring(
        &self,
        constituents: &[Datum],
        marker: &Datum,
    ) -> Result<(Vec<ContentId>, ContentId), KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.append_restructuring(constituents, marker)
    }

    /// **stage_restructuring** (§13, Phase 1) — der **erste** Halbschritt eines
    /// atomaren Umbaus: hängt die `constituents` als **bedingte, noch INAKTIVE**
    /// Konstituenten an (§13.2) und liefert einen [`StagedHandle`]. Bis der Marker
    /// committet ist, ignorieren **alle** Lesepfade die Konstituenten (sie VANISHen
    /// aus `get_by_content_id`, der Traversierung und jedem gegateten Helfer). Der
    /// abschließende [`commit_restructuring`](LakearchKernel::commit_restructuring)
    /// flippt sie **gemeinsam** sichtbar (§13.1).
    ///
    /// Dieser zweiphasige Pfad existiert, damit ein Aufrufer (und der Test) den
    /// **inaktiven Zwischenzustand** über die öffentlichen Lesepfade beobachten kann;
    /// [`append_restructuring`](LakearchKernel::append_restructuring) ist der
    /// Ein-Aufruf-Bequempfad (stage + commit unmittelbar).
    pub fn stage_restructuring(
        &self,
        constituents: &[Datum],
    ) -> Result<StagedHandle, KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.stage_restructuring(constituents)
    }

    /// **commit_restructuring** (§13, Phase 2) — der **abschließende** Aktiv-
    /// Schreibvorgang: committet das `marker`-Daten für den gestageten `handle` und
    /// flippt damit **alle** Konstituenten in **einem** Linearisierungspunkt
    /// **gemeinsam sichtbar** (§13.1, Atomarität ohne Transaktions-Maschinerie §13.3).
    /// Liefert die [`ContentId`] des Marker-Daten.
    pub fn commit_restructuring(
        &self,
        handle: StagedHandle,
        marker: &Datum,
    ) -> Result<ContentId, KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.commit_restructuring(handle, marker)
    }

    /// **Gegateter Zeit-Aussage-Lookup** (§6.1/§6.2/§11.3) — liefert die für die
    /// `capability` **sichtbaren** Daten, die die Zeit-Aussage `statement` tragen.
    ///
    /// `statement` ist die `ContentId` eines **Zeit-Aussage-Kontextes**
    /// (`{ Achsen-Marker, Zeit-Wert }`, [`Datum::recording_time`]/
    /// [`Datum::validity_time`]). Der Lookup ist **rein strukturell** (Exakt-Match/
    /// Mitgliedschaft, §1.3) — er **parst/ordnet/vergleicht** den opaken Zeit-Wert
    /// **nie** (§1.4/§6.4) und ist **keine** geordnete Bereichs-Abfrage. Welche
    /// Version zum Zeitpunkt T „gilt", ist eine Leseregel der Schicht darüber (§8).
    ///
    /// **Gated (§11.3):** nicht-sichtbare Träger VANISHen (sie erscheinen nicht im
    /// Ergebnis, ununterscheidbar von „existiert nicht"). Es werden **nur**
    /// `ContentId`s geliefert; den Inhalt legt erst das Tor frei (§11.5). Fail-closed
    /// (§11): ein korrupter Bereichs-Index ⇒ [`KernelError::Inconsistent`] (DENY).
    ///
    /// **§13-Snapshot:** der `snapshot`-Token pinnt das Watermark `W` (eine
    /// Linearisierungsstelle, §13); die §13-Aktiv-Sicht ist damit für diesen Token
    /// stabil — Tor (§11) und §13-Filter laufen über **dasselbe** S.
    pub fn time_carriers_visible(
        &self,
        statement: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.time_carriers_of(statement);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatetes context_points_to** (§1.3 ii / §11.3) — der **gegatete** Einstieg
    /// zum Prädikat „zeigt der Kontext `ctx` auf `target`?", der — anders als die
    /// frozen-Form-[`Kernel::context_points_to`] — eine [`Capability`] trägt und das
    /// Tor **vor** dem Roh-Index-Match anwendet.
    ///
    /// Das Prädikat verrät einen strukturellen **Besitz-Fakt** über (potentiell)
    /// bereichs-beschränkte oder noch **inaktive** Daten (§13.2) — es **muss** daher
    /// über dasselbe Tor wie [`get_by_content_id`](Kernel::get_by_content_id)/
    /// [`traverse_with`](LakearchKernel::traverse_with) laufen (§11.2). Beide
    /// Operanden (`ctx` **und** `target`) werden am gepinnten Watermark gegen die
    /// **Sichtbarkeit** geprüft ([`crate::store::ContentStore::visible_filter`], das
    /// is_active §13 + Kuratierung §9.5 + §11-Bereich + fail-closed §11 bündelt):
    ///
    /// - Ist **ein** Operand nicht sichtbar/inaktiv ⇒ `false` (**VANISH**,
    ///   ununterscheidbar von „der Fakt besteht nicht", §11.3) — der Roh-Index wird
    ///   für verborgene Operanden **nie** konsultiert (kein Existenz-/Struktur-Orakel
    ///   über einen halb-vollzogenen Umbau oder beschränkte Daten).
    /// - Sind **beide** sichtbar ⇒ reines Mengen-Matching (§1.3) über den Vorwärts-
    ///   Index (`target ∈ contexts_of(ctx)`), wie die frozen-Form.
    ///
    /// **Fail-closed (§11):** eine Index-/Log-Inkonsistenz im Sichtbarkeits-Filter ⇒
    /// [`KernelError`] (DENY), **nie** ein leckendes `true`. Der `snapshot`-Token
    /// pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn context_points_to_visible(
        &self,
        ctx: ContentId,
        target: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let granted = capability.scopes().scope_ids();
        let w = snapshot.watermark();
        // §11.3 Filter-vor-Auflösen: beide Operanden müssen sichtbar sein, sonst
        // VANISH (false). `visible_filter` wendet is_active (§13) + Kuratierung
        // (§9.5) + §11-Bereich + fail-closed (§11) am gepinnten `w` an.
        let visible = store.visible_filter(&[ctx, target], granted, w)?;
        if !(visible.contains(&ctx) && visible.contains(&target)) {
            return Ok(false);
        }
        // Beide sichtbar ⇒ reines Mengen-Matching (§1.3) über den Vorwärts-Index.
        let ctxs = store.index().contexts_of(ctx)?;
        Ok(ctxs.binary_search(&target).is_ok())
    }

    /// **Gegatetes is_member_of_set** (§1.3 iii / §11.3) — der **gegatete** Einstieg
    /// zum Prädikat „ist `elem` Mitglied der vom Mengen-Kontext `set_ctx`
    /// aufgespannten Menge?", der — anders als die frozen-Form-[`Kernel::is_member_of_set`]
    /// — eine [`Capability`] trägt und das Tor **vor** dem Roh-Index-Match anwendet.
    ///
    /// Wie [`context_points_to_visible`](LakearchKernel::context_points_to_visible)
    /// verrät das Prädikat einen strukturellen **Zugehörigkeits-Fakt** über
    /// (potentiell) beschränkte oder noch **inaktive** Daten (§13.2) und läuft daher
    /// über dasselbe Tor (§11.2): beide Operanden (`elem` **und** `set_ctx`) werden am
    /// gepinnten Watermark gegen die Sichtbarkeit geprüft. Ist **ein** Operand nicht
    /// sichtbar/inaktiv ⇒ `false` (**VANISH**, §11.3) — der Roh-Index wird für
    /// verborgene Operanden **nie** konsultiert. Sind **beide** sichtbar ⇒ reines
    /// Mengen-Matching (`elem ∈ contexts_of(set_ctx)`, §1.3).
    ///
    /// **Fail-closed (§11):** eine Inkonsistenz im Sichtbarkeits-Filter ⇒
    /// [`KernelError`] (DENY), **nie** ein leckendes `true`. Der `snapshot`-Token
    /// pinnt das Watermark `W` (§13).
    pub fn is_member_of_set_visible(
        &self,
        elem: ContentId,
        set_ctx: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let granted = capability.scopes().scope_ids();
        let w = snapshot.watermark();
        // §11.3 Filter-vor-Auflösen: beide Operanden müssen sichtbar sein, sonst
        // VANISH (false). Bündelt is_active (§13) + Kuratierung (§9.5) + §11-Bereich.
        let visible = store.visible_filter(&[elem, set_ctx], granted, w)?;
        if !(visible.contains(&elem) && visible.contains(&set_ctx)) {
            return Ok(false);
        }
        // Beide sichtbar ⇒ reines Mengen-Matching (§1.3) über den Vorwärts-Index.
        let members = store.index().contexts_of(set_ctx)?;
        Ok(members.binary_search(&elem).is_ok())
    }

    /// **Gegatete Ersetzungs-Traversierung — supersedes** (§6.3/§11.3): die für die
    /// `capability` **sichtbaren** **älteren** Daten, die `newer` überholt (neuer →
    /// älter). Reines strukturelles Folgen der Ersetzungs-Kontexte (§1.2/§1.3); der
    /// Kernel entscheidet **nicht**, welches „aktuell" ist (§6.4/§8).
    ///
    /// **Gated (§11.3):** ein nicht-sichtbares älteres Daten VANISHt. Nur
    /// `ContentId`s; Inhalt nur über das Tor (§11.5). Fail-closed (§11). Der
    /// `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn supersedes_visible(
        &self,
        newer: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.supersedes_of(newer);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete Ersetzungs-Traversierung — superseded-by** (§6.3/§11.3): die für
    /// die `capability` **sichtbaren** **neueren** Daten, die `older` überholen
    /// (älter → neuer) — die Gegenrichtung zu [`supersedes_visible`](LakearchKernel::supersedes_visible).
    /// So ist die Ersetzungs-Relation in **beide** Richtungen gegated traversierbar
    /// (§1.2).
    ///
    /// **Gated (§11.3):** ein nicht-sichtbares überholendes Daten VANISHt — ein
    /// nicht-sichtbares ersetzendes Daten ist damit ununterscheidbar von „es gibt
    /// keines". Nur `ContentId`s; Inhalt nur über das Tor (§11.5). Fail-closed (§11).
    /// Der `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn superseded_by_visible(
        &self,
        older: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.superseded_by_of(older);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete Platzhalter-Auflösung** (§3.6/§6.3/§11.3): die für die `capability`
    /// **sichtbaren** **echten** Daten, die `placeholder` aufgelöst haben.
    ///
    /// Die Auflösung ([`crate::store::ContentStore::resolve_placeholder`]) verknüpft
    /// Platzhalter→real über einen **Ersetzungs-Kontext** (§6.3): ein Auflösungs-
    /// Knoten `{ real, supersedes(placeholder) }` überholt den Platzhalter und
    /// besitzt das echte Daten. Dieser Helfer folgt daher *superseded-by* vom
    /// Platzhalter zu seinen Auflösungs-Knoten und von dort **vorwärts** zu den
    /// echten Daten (alles strukturell, §1.2/§1.3) — der auflösende Pfad ist vom
    /// Platzhalter aus erreichbar (geschlossener Verweis, §3.6).
    ///
    /// **Gated (§11.3):** sowohl der Auflösungs-Knoten als auch das echte Daten
    /// müssen sichtbar sein; nicht-sichtbare VANISHen. Nur `ContentId`s; Inhalt nur
    /// über das Tor (§11.5). Fail-closed (§11). Der Platzhalter selbst bleibt
    /// append-only unverändert (§7.1) — dieser Helfer mutiert **nichts**. Der
    /// `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn placeholder_resolvers_visible(
        &self,
        placeholder: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let granted = capability.scopes().scope_ids();
        let w = snapshot.watermark();
        // superseded-by(placeholder) = die (sichtbaren) Auflösungs-Knoten.
        let resolution_nodes =
            store.visible_filter(&store.superseded_by_of(placeholder), granted, w)?;
        // Die `ContentId` des Ersetzungs-Kontextes ist strukturell bestimmt
        // (`{ supersession_marker, placeholder }`, §6.3): das echte Daten ist der
        // **übrige** besessene Kontext eines Auflösungs-Knotens, der genau diesen
        // Ersetzungs-Kontext **und** das echte Daten besitzt. Reines strukturelles
        // Aussondern (§1.3); keine Wertung (§1.4).
        let supersedes_ctx_id = ContentId::of_datum(&Datum::supersedes(placeholder));
        let mut reals: Vec<ContentId> = Vec::new();
        for node in resolution_nodes {
            for ctx in store.index().contexts_of(node)? {
                if ctx == supersedes_ctx_id {
                    continue; // der Ersetzungs-Kontext selbst — kein echtes Ziel.
                }
                reals.push(ctx);
            }
        }
        store.visible_filter(&reals, granted, w)
    }

    /// **materialize** (§10.1) — ein **berechnetes Ergebnis** als gewöhnliches Daten
    /// speichern (die Schicht darüber reicht es ein, §1.5/§7.2) und, wenn es ein
    /// **älteres** Ergebnis ersetzt (`replaces = Some(older)`), es per Phase-3-
    /// Ersetzungs-Kontext (§6.3) damit verknüpfen — **append-only**, das ältere wird
    /// **nie** geändert/gelöscht (§7.1).
    ///
    /// **Der Kernel BERECHNET das Ergebnis NICHT** (§1.5/§10.1): `result` ist das
    /// fertige Daten der schreibenden Schicht; dieses Verb hängt nur an (§7.1) und
    /// verknüpft strukturell (§1.3). Delegiert an
    /// [`crate::store::ContentStore::materialize`] (Schreib-Lock; der Store ist der
    /// eine Append-Pfad). Liefert `(result_id, Option<link_id>)`.
    pub fn materialize(
        &self,
        result: &Datum,
        replaces: Option<ContentId>,
    ) -> Result<(ContentId, Option<ContentId>), KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.materialize(result, replaces)
    }

    /// **Gegatete Herkunft — Ergebnis→Eingaben** (§10.2/§11.3): die für die
    /// `capability` **sichtbaren** Eingaben, aus denen das berechnete Ergebnis
    /// `result` entstand. Reines strukturelles Folgen der Herkunfts-Kontexte
    /// (§1.2/§1.3); der Kernel **berechnet nichts** und entscheidet **nicht**, welches
    /// Ergebnis „aktuell" ist (§1.5/§10.1).
    ///
    /// **Gated (§11.3):** eine nicht-sichtbare Eingabe VANISHt. Nur `ContentId`s;
    /// Inhalt nur über das Tor (§11.5). Fail-closed (§11). Der `snapshot`-Token pinnt
    /// das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn origin_inputs_visible(
        &self,
        result: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.origin_inputs_of(result);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete Invalidierung — find_dependents (eine Stufe)** (§10.3/§11.3): die
    /// für die `capability` **sichtbaren** materialisierten Ergebnisse, die (direkt)
    /// von der Eingabe `input` abhängen — die Invalidierungs-Rückwärts-Kante (§10.3,
    /// *derived-from*). Der Kernel **findet** sie nur (mechanisch, §1.7 a); das
    /// **Als-stale-markieren/Neu-Berechnen** liegt **außerhalb** (§1.5/§7.1) — es gibt
    /// **kein** Verb, das hier neu berechnet oder auto-invalidiert.
    ///
    /// **Gated (§11.3):** ein nicht-sichtbares abhängiges Ergebnis VANISHt. Nur
    /// `ContentId`s; Inhalt nur über das Tor (§11.5). Fail-closed (§11). Der
    /// `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    ///
    /// Für die **mehrstufige** (transitive) Rückwärts-Traversierung der Herkunft —
    /// beschränkt, zyklensicher — siehe die Trait-Verben
    /// [`crate::api::Kernel::find_dependents`] /
    /// [`crate::api::Kernel::traverse_provenance_backward`].
    pub fn dependents_visible(
        &self,
        input: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.dependents_of(input);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete Anker-Mitgliedschaft — Anker→Repräsentanten** (§9.1/§9.3/§11.3):
    /// die für die `capability` **sichtbaren** Repräsentanten, die per Mitgliedschafts-
    /// Kontext auf den Anker `anchor` verweisen (§9.2). Reines strukturelles Folgen der
    /// Mitgliedschafts-Kanten (§1.2/§1.3); der Kernel **entscheidet keine
    /// Mitgliedschaft** und **wertet/schwellt den Grad nie** (§9-Präambel/§1.4).
    ///
    /// **Gated (§11.3):** ein nicht-sichtbarer (oder kuratorisch verborgener, §9.5)
    /// Repräsentant VANISHt. Nur `ContentId`s; Inhalt nur über das Tor (§11.5).
    /// Fail-closed (§11). Es wird **kein** Repräsentant „gewählt" oder gerankt — die
    /// Schicht darüber liest den Grad und entscheidet (§1.4/§1.5). Der `snapshot`-
    /// Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn anchor_members_visible(
        &self,
        anchor: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.anchor_members_of(anchor);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete Anker-Mitgliedschaft — Repräsentant→Anker** (§9.1/§11.3): die für
    /// die `capability` **sichtbaren** Anker, denen `member` per Mitgliedschafts-
    /// Kontext angehört (ein Daten darf mehreren angehören, §9.1) — die Gegenrichtung
    /// zu [`anchor_members_visible`](LakearchKernel::anchor_members_visible). So ist die
    /// Mitgliedschaft in **beide** Richtungen gegated traversierbar (§1.2).
    ///
    /// **Gated (§11.3):** ein nicht-sichtbarer/verborgener Anker VANISHt. Nur
    /// `ContentId`s; Inhalt nur über das Tor (§11.5). Fail-closed (§11). Der
    /// `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn member_anchors_visible(
        &self,
        member: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.member_anchors_of(member);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// **Gegatete gradierte Identitäts-Links** (§5.5/§11.3): die für die `capability`
    /// **sichtbaren** gradierten Identitäts-Kontexte ([`Datum::graded_identity`]), die
    /// `datum` erwähnen. Reines strukturelles Folgen der Identitäts-Links (§1.2/§1.3);
    /// der Kernel **vergleicht/schwellt Konfidenz nie** und **entscheidet keine
    /// Identität** (§5.5/§9-Präambel/§1.4) — er reicht nur die rohen Kontext-IDs
    /// heraus, deren Stärke/Konfidenz die Schicht darüber liest und wertet (§1.5).
    ///
    /// **Gated (§11.3):** ein nicht-sichtbarer/verborgener Identitäts-Kontext VANISHt.
    /// Nur `ContentId`s; Inhalt nur über das Tor (§11.5). Fail-closed (§11). Der
    /// `snapshot`-Token pinnt das Watermark `W` (§13 — stabile §13-Aktiv-Sicht).
    pub fn graded_identity_links_visible(
        &self,
        datum: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let candidates = store.graded_identity_links_of(datum);
        store.visible_filter(&candidates, capability.scopes().scope_ids(), snapshot.watermark())
    }

    /// Der bestand-**lokale** [`AnchorId`]-Handle eines Anker-Daten (§9.1/§12.4),
    /// falls vergeben; sonst `None`. **Kein** Inhalts-Read (nur eine Handle-Auflösung
    /// über die rebuildbare Karte) — der Anker bleibt ein gewöhnliches
    /// inhaltsadressiertes Daten (§2.1), die [`AnchorId`] ist **nie** seine alleinige
    /// Identität (§12.4).
    pub fn anchor_id_of(&self, anchor: ContentId) -> Result<Option<AnchorId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        Ok(store.anchor_id_of(anchor))
    }

    /// Die Anker-`ContentId` zu einem bestand-lokalen [`AnchorId`]-Handle (§12.4),
    /// falls vergeben; sonst `None`. Umkehrung von
    /// [`anchor_id_of`](LakearchKernel::anchor_id_of).
    pub fn anchor_cid_of(&self, anchor_id: AnchorId) -> Result<Option<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        Ok(store.anchor_cid_of(anchor_id))
    }

    /// Alle **Anker-`ContentId`s** dieses Bestands (§9.1/§12.4) — owned, aufsteigend
    /// in 32-Byte-Adress-Order (deterministisch, **kein** Wert-Sort §1.4). Die
    /// Schicht darüber findet damit Versöhnungs-Kandidaten für die Föderation und
    /// **entscheidet** die referenzielle Identität (§9-Präambel/§5.7 b); der Kernel
    /// **verlinkt** nur (§1.4). Reine Handle-Auflösung; **kein** Inhalts-Read.
    pub fn anchor_cids(&self) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        Ok(store.anchor_cids())
    }

    /// **content_set** (§12) — die `ContentId`s **aller** aktiven (§13) Daten dieses
    /// Bestands, owned und aufsteigend in 32-Byte-Adress-Order (deterministisch,
    /// **kein** Wert-Sort §1.4). Föderationsstabiler Vergleichs-Schlüssel: zwei
    /// Bestände sind **inhaltsgleich**, wenn ihre `content_set` gleich sind (§12.3).
    /// Reines Adress-Matching (§1.3); **kein** Inhalt verlässt das Crate (nur Hash-
    /// Adressen). Nützlich, um die **Idempotenz** eines Doppel-Ingest zu prüfen
    /// (gleiche Menge ⇒ byte-gleicher Bestand, §12.4).
    pub fn content_set(&self) -> Result<Vec<ContentId>, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let mut ids: Vec<ContentId> = store
            .iter_active_data()?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort_unstable();
        Ok(ids)
    }

    /// **federate** (§12.3/§12.5) — nimmt einen **fremden** Bestand `foreign` in
    /// diesen auf. **Kein Sonderfall** (§12.5): jedes aktive fremde Daten läuft über
    /// den **einen** lokalen Append-Pfad ([`Kernel::append`]); **inhaltsgleiche**
    /// Daten kollabieren **automatisch** über ihre `ContentId` (Dedup §5.3/§12.3).
    ///
    /// Liefert `(new_count, dedup_count)`: wie viele fremde Daten **neu** geschrieben
    /// wurden bzw. per Dedup **kollabierten**. Nimmt den **Lese**-Lock des fremden
    /// und den **Schreib**-Lock des lokalen Bestands (der lokale Store ist der eine
    /// Append-Pfad, §7.1). Ein vergifteter Lock ⇒ [`KernelError::Poisoned`] (§11).
    ///
    /// **Anker-Versöhnung (§12.4)** ist getrennt: Inhalts-IDs kollabieren hier
    /// automatisch, **Anker-IDs sind bestand-lokal** (§9.1) und werden über
    /// [`reconcile_anchor`](LakearchKernel::reconcile_anchor) als **deterministische**
    /// gradierte-Identitäts-Kontexte versöhnt. **Welche** Anker „dasselbe Ding" sind,
    /// bestimmt die Schicht darüber (Korrelations-Pfad §5.7 b); der Kernel
    /// **entscheidet keine Identität** (§9-Präambel/§1.4) — er verlinkt nur.
    pub fn federate<J: EdgeIndex>(
        &self,
        foreign: &LakearchKernel<J>,
    ) -> Result<(u64, u64), KernelError> {
        // Schreib-Lock zuerst (der lokale Store ist der eine Append-Pfad), dann der
        // Lese-Lock des fremden Bestands. Verschiedene Stores ⇒ kein Selbst-Deadlock;
        // der fremde Bestand wird nur gelesen.
        let mut local = self.store.write().map_err(|_| KernelError::Poisoned)?;
        let foreign_store = foreign.store.read().map_err(|_| KernelError::Poisoned)?;
        local.ingest_foreign(&foreign_store)
    }

    /// **reconcile_anchor** (§12.4) — versöhnt einen **fremden** Anker mit einem
    /// **lokalen** über einen **gradierten Identitäts-Kontext** (§5.5), dessen Bytes
    /// eine **reine, deterministische** Funktion von `(foreign_anchor, local_anchor,
    /// rule)` sind — **keine** Wall-Clock, **kein** Random. Ein erneuter Aufruf
    /// erzeugt einen **byte-gleichen** Kontext, der per Hash kollabiert (§5.3) ⇒
    /// Doppel-/Concurrent-Ingest sind **idempotent** (§12.4). Serialisiert durch den
    /// **einen** Append-Pfad (Schreib-Lock). Liefert die `ContentId` des
    /// Versöhnungs-Kontextes.
    ///
    /// `rule` ist das **opake** Regel-Daten (die Begründung der Versöhnung, von der
    /// Schicht darüber bestimmt); der Kernel **wertet sie nicht** (§1.4) und
    /// **entscheidet keine Identität** (§9-Präambel) — er verlinkt nur die von der
    /// Schicht darüber bestimmte Korrelation (§5.7 b).
    pub fn reconcile_anchor(
        &self,
        foreign_anchor: ContentId,
        local_anchor: ContentId,
        rule: &Datum,
    ) -> Result<ContentId, KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.reconcile_anchor(foreign_anchor, local_anchor, rule)
    }

    /// **erase** (§15/§9.5/§11, Plan „Compaction/DSGVO") — eine **gegatete,
    /// auditierte, nicht-transitive** physische Erasure (Crypto-Shred) des Daten
    /// `target` planen. Diese Op ist die **endgültige** Löschung („Recht auf
    /// Vergessen") — im Unterschied zum **reversiblen** logischen Verbergen (§9.5,
    /// [`Datum::curation_hide`], „Einschränkung der Verarbeitung").
    ///
    /// **Gegatet (§11):** das vorgelegte `right`-Daten **muss** das spezifische
    /// **Erasure-Recht** tragen ([`Datum::is_erasure_right`]); sonst geschieht
    /// **nichts** und es kommt [`KernelError::ErasureDenied`] zurück (fail-closed).
    ///
    /// **Auditiert (§7.1):** die Op **hängt ihr eigenes Audit-Daten an**
    /// ([`Datum::erasure_audit`]`(target)`) — der unveränderliche Beleg, **dass** und
    /// **was** erast wurde, bleibt im Log, auch nachdem die Nutzlast geschreddert ist
    /// (§3.6: der Verweis bleibt geschlossen, das Audit zeigt auf den Tombstone).
    /// Liefert die `ContentId` des Audit-Daten.
    ///
    /// **Wirkung:** `target` wird mit dem Lösch-Schlüssel `key` in den ausstehenden
    /// Crypto-Shred-Plan aufgenommen; die **nächste** [`compact`](LakearchKernel::compact)
    /// versiegelt seine Nutzlast in der neuen Generation. Das spätere **Zerstören**
    /// des Schlüssels im Keystore macht die Bytes unrückholbar (O(1)).
    ///
    /// **Nicht-transitiv über Föderation (§12.3):** die Erasure wirkt **nur lokal**
    /// (der Lösch-Schlüssel lebt nur im lokalen Keystore); sie propagiert **nicht** in
    /// andere Bestände. Ein anderer Bestand muss seine eigene, eigenständig gegatete +
    /// auditierte Erasure durchführen.
    pub fn erase(
        &self,
        target: ContentId,
        right: &Datum,
        key: ErasureKey,
    ) -> Result<ContentId, KernelError> {
        // §11 Tor-Gate: ohne das spezifische Erasure-Recht geschieht NICHTS.
        if !right.is_erasure_right() {
            return Err(KernelError::ErasureDenied);
        }
        // §7.1 Audit: das eigene, unveränderliche Audit-Daten anhängen (durch den
        // EINEN Append-Pfad serialisiert). Bleibt im Log, auch nach dem Shred (§3.6).
        let audit = Datum::erasure_audit(target);
        let audit_id = {
            let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
            store.append_datum(&audit)?
        };
        // Den Crypto-Shred-Plan vormerken (die nächste Compaction versiegelt `target`).
        let mut pending = self.pending.lock().map_err(|_| KernelError::Poisoned)?;
        pending.erase(target, key);
        Ok(audit_id)
    }

    /// **compact** (§15, Plan „Compaction/DSGVO") — schreibt die **nächste
    /// unveränderliche Generation** des Bestands: sie lässt **überholte** (§6.3) und
    /// **kuratorisch verborgene** (§9.5) Records physisch fallen (sofern kein retained
    /// Daten sie noch referenziert — Refcount-Schutz §5.3), **versiegelt** die geplanten
    /// **erasten** Records (Crypto-Shred) und schaltet die neue Generation **atomar**
    /// über den `CURRENT`-Marker live (§13-Epoche-Analogon). Sie **unmappt nie** das
    /// laufende Append-Log, das Leser halten — die compactierte Generation lebt in
    /// **ihrem eigenen** Verzeichnis (`base_dir/compacted/gen-N`), die alte bleibt auf
    /// Platte (drop-after-quiesce).
    ///
    /// Sie rekonstruiert einen **konsistenten** Index implizit: die neue Generation
    /// hält jedes Daten über seine **stabile logische ID** ([`ContentId`], nie ein roher
    /// Offset, §15) in deterministischer Adress-Order (§5.2/§1.4) — ein erneutes Lesen
    /// liefert dieselbe Sicht (Content-Adressierung intakt). Liefert die
    /// [`CompactedSegment`], den befüllten [`Keystore`] (die Lösch-Schlüssel) und einen
    /// [`CompactionReport`].
    ///
    /// **Refcount/Reachability (§5.3):** ein per Dedup mehrfach referenziertes Daten
    /// wird **nicht** fallengelassen, solange **eine** Referenz es behält — die
    /// Löschung einer Referenz zerstört **nicht** die Daten einer anderen.
    ///
    /// Erfordert ein **Basis-Verzeichnis** ([`LakearchKernel::open`]/
    /// [`from_store_at`](LakearchKernel::from_store_at)); sonst
    /// [`KernelError::Inconsistent`] (kein Ort für die Generation).
    ///
    /// **Konservativ (§1.4/§6.4).** `compact` **entscheidet keine Version** (welche
    /// von zwei Ersetzungs-verknüpften Daten „gilt", ist eine **Leseregel der Schicht
    /// darüber**, §6.4/§8). Es schlägt als Fallenlass-Kandidaten **mechanisch** die
    /// überholten (§6.3) und verborgenen (§9.5) Daten vor, lässt aber **nur** die
    /// **genuin verwaisten** (von keinem behaltenen Daten referenzierten) tatsächlich
    /// fallen (Closure-Fixpunkt §3.6). Will die Schicht darüber gezielt eine ganze
    /// (closure-konsistente) Version-Kette physisch entfernen, übergibt sie diese als
    /// `extra_drop` an [`compact_with_drop`](LakearchKernel::compact_with_drop).
    pub fn compact(&self) -> Result<(CompactedSegment, Keystore, CompactionReport), KernelError> {
        self.compact_with_drop(HashSet::new())
    }

    /// **compact_with_drop** (§15) — wie [`compact`](LakearchKernel::compact), aber mit
    /// einem **expliziten zusätzlichen Fallenlass-Satz** `extra_drop`, den die Schicht
    /// darüber (die §6.4/§8 die „gültige Version" bestimmt — **nicht** der Kernel,
    /// §1.4) als **closure-konsistente** Menge der physisch zu entfernenden Records
    /// vorlegt. Der Kernel **wertet nicht** (§1.4): er entfernt genau die übergebenen
    /// (plus die mechanisch verwaisten überholten/verborgenen) — geschützt durch den
    /// Closure-Fixpunkt (§3.6: nichts Behaltenes verweist je auf Entferntes) und den
    /// Refcount (§5.3: eine rechtmäßig gehaltene Referenz bewahrt ihr Daten).
    pub fn compact_with_drop(
        &self,
        extra_drop: HashSet<ContentId>,
    ) -> Result<(CompactedSegment, Keystore, CompactionReport), KernelError> {
        let base = self.base_dir.clone().ok_or(KernelError::Inconsistent)?;

        // Die aktiven Daten (§13) in Abhängigkeits-Reihenfolge (Kontexte vor Besitzern)
        // — die Eingabe des Rewrites. Plus die Fallenlass-Kandidaten (überholt §6.3 +
        // verborgen §9.5 + explizit übergebene) und der ausstehende Erasure-Plan (§15).
        let (data, drop_set) = {
            let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
            let data = store.iter_active_data()?;
            let mut drop: HashSet<ContentId> = extra_drop;
            for id in store.superseded_ids() {
                drop.insert(id);
            }
            for id in store.curation_hidden_ids() {
                drop.insert(id);
            }
            (data, drop)
        };

        let plan = {
            let pending = self.pending.lock().map_err(|_| KernelError::Poisoned)?;
            pending.clone()
        };

        // Die nächste Generation bestimmen (§15: monoton steigende Epoche).
        let next_gen: Generation =
            compaction::read_current_generation(&base)?.map(|g| g + 1).unwrap_or(0);

        // Compactor: physisch verdichten + crypto-shredden (closure-/refcount-geschützt).
        let compactor = Compactor::new(drop_set, plan);
        let (segment, keystore, _refs, report) = compactor.compact(next_gen, &data)?;

        // Die Generation UNVERÄNDERLICH schreiben (Segment + Keystore), DANN atomar
        // live schalten (CURRENT-Marker = der eine Linearisierungspunkt §13). Ein
        // Crash vor dem Publish lässt die alte Generation live (die neue nie sichtbar).
        let gdir = compaction::generation_dir(&base, next_gen);
        segment.write_to(&gdir)?;
        keystore.save(compaction::keystore_path(&gdir))?;
        compaction::publish_generation(&base, next_gen)?;

        Ok((segment, keystore, report))
    }

    /// Aggregierte **Betriebs-Zähler** (§Betrieb). Liest sowohl die Store- als auch
    /// die Log-Metriken unter dem Lese-Lock zusammen.
    pub fn stats(&self) -> Result<KernelMetrics, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let sm = store.metrics();
        let lm = store.log_metrics();
        Ok(KernelMetrics {
            append_count: sm.append_count,
            dedup_hit_count: sm.dedup_hit_count,
            edge_count: sm.edge_count,
            batch_count: lm.batch_count,
            fsync_count: lm.fsync_count,
            segment_count: lm.segment_count,
            committed_bytes: lm.committed_bytes,
            fail_closed_count: sm.fail_closed_count,
        })
    }
}

impl LakearchKernel<crate::index::RedbEdgeIndex> {
    /// Öffnet einen Kernel mit der Standard-Engine (redb) unter `dir`: ein
    /// Log-Verzeichnis `dir/log` und ein redb-Index `dir/index.redb`. Das
    /// Verzeichnis `dir` muss existieren.
    ///
    /// Beim Öffnen läuft die Log-Recovery (§Durability) und die Index-Versöhnung
    /// (§8.4); danach ist der Kernel betriebsbereit.
    pub fn open(dir: impl AsRef<std::path::Path>) -> Result<Self, KernelError> {
        let dir = dir.as_ref();
        let log_dir = dir.join("log");
        std::fs::create_dir_all(&log_dir).map_err(|_| KernelError::Io)?;
        let log = SegmentLog::open(&log_dir)?;
        let index = crate::index::RedbEdgeIndex::open(dir.join("index.redb"))?;
        let store = ContentStore::open(log, index)?;
        Ok(LakearchKernel::from_store_at(store, dir.to_path_buf()))
    }
}

impl<I: EdgeIndex> Kernel for LakearchKernel<I> {
    /// **Phase 1.** Pinnt einen MVCC-Snapshot am aktuellen durablen Watermark `W`
    /// (= committed Log-Offset). Der Token ist der Lese-Handle für jede
    /// Read-Signatur (§8.4/§13).
    ///
    /// **Stand (Phase 1).** Der Token trägt nur die Watermark; die **volle**
    /// Epochen-/Sichtbarkeits-Semantik (§13: „strukturell-aktiv-im-Snapshot")
    /// landet in Phase 5. Reine Mechanik (§1.4), **kein** Wall-Clock-Vergleich.
    fn pin_snapshot(&self) -> Result<SnapshotToken, KernelError> {
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        Ok(SnapshotToken::at_watermark(store.log_metrics().committed_bytes))
    }

    /// **Phase 1 (minimal).** Stellt für ein Subjekt (dessen [`GrantedScopes`])
    /// eine [`Capability`] aus — der unfälschbare Tor-Nachweis für
    /// [`Kernel::get_by_content_id`].
    ///
    /// **Stand (Phase 1).** Es wird **noch kein** strukturelles Berechtigungs-
    /// Matching gegen den Snapshot ausgeführt (das ist die Tor-Logik, Phase 2):
    /// die Capability bündelt allein die übergebenen Scopes, sodass der durchs
    /// Tor versiegelte Lesepfad schon Ende-zu-Ende existiert. `snapshot` wird
    /// formal entgegengenommen (jede Tor-Operation läuft über **dasselbe** S,
    /// §11.2), in Phase 2 dann ausgewertet.
    fn authorize(
        &self,
        scopes: GrantedScopes,
        snapshot: SnapshotToken,
    ) -> Result<Capability, KernelError> {
        // Phase 2: hier matcht das Tor die aktiven Berechtigungen im Snapshot
        // strukturell (§11.2/§1.3) und stellt erst dann eine Capability aus.
        let _ = snapshot;
        Ok(Capability::issue(scopes))
    }

    /// **append** (§7.1) — die **einzige** Mutation: genau ein neues Daten samt
    /// seinen besessenen Kontexten kommt hinzu (nie geändert, nie gelöscht).
    /// Inhaltsgleiches dedupliziert automatisch (§5.3) und schreibt **nichts**
    /// Neues. Liefert die [`ContentId`] des (ggf. schon vorhandenen) Daten.
    ///
    /// Die abgeleiteten Kanten (`owner→contexts` / `target→referrers`) werden
    /// **erst nach** dem Log-`fsync` in den Index committet (Ordnung log-fsync →
    /// index-commit, §8.4). `append` **rechnet und wertet nicht** (§7.3).
    fn append(&self, datum: &Datum) -> Result<ContentId, KernelError> {
        let mut store = self.store.write().map_err(|_| KernelError::Poisoned)?;
        store.append_datum(datum)
    }

    /// **get_by_content_id** (§5.2-Fetch) — geht **durchs Tor** (§11): liefert ein
    /// opakes [`SealedRecord`], dessen Inhalt **nur** [`crate::gate::open`] gegen
    /// die [`Capability`] freilegt. `None` ⇒ **nicht sichtbar ODER nicht vorhanden**
    /// — der Leser kann es **nicht** unterscheiden (VANISH, §11.3).
    ///
    /// ## VANISH schon an der Verb-Grenze (§11.3 — kein Existenz-Orakel)
    ///
    /// Die Sichtbarkeit wird **vor** der Rückgabe gematcht (Filter-vor-Auflösen,
    /// §11.3, reines Mengen-Matching §1.3): ist das Daten durabel vorhanden, aber
    /// für die `capability` **nicht** sichtbar, liefert dieses Verb `Ok(None)` —
    /// **ununterscheidbar** von „nicht vorhanden". Andernfalls könnte ein rechtloser
    /// Leser allein aus der Rückgabeform (`Some` vs. `None`) ein Existenz-Orakel
    /// über die berechenbaren Hash-Adressen ableiten (§11.3 verbietet genau das, und
    /// der API-Vertrag in [`crate::api::Kernel::get_by_content_id`] fordert `None`
    /// für Verborgenes). Damit verhält sich dieses Verb wie `is_visible_node` in der
    /// Traversierung: „abwesend" und „vorhanden-aber-verborgen" kollabieren beide zu
    /// `None`. Erst ein **sichtbares** Daten wird als `SealedRecord` versiegelt; das
    /// abschließende [`crate::gate::open`] gegen dieselbe `capability` setzt die
    /// Sichtbarkeit ein zweites Mal durch (Tor bleibt die einzige Inhalts-Quelle).
    ///
    /// **Fail-closed (§11):** eine Index-/Log-Inkonsistenz (`areas_of_checked` ⇒
    /// `Inconsistent`) ist ein **Fehler** (DENY + Fail-closed-Vermerk), **nie** ein
    /// stilles `Some`/`None`, das Unsichtbares durchsickern ließe.
    ///
    /// **§13-Snapshot (gepinntes W):** der `snapshot`-Token trägt das gepinnte
    /// Watermark `W` (eine Linearisierungsstelle, §13); die §13-Aktiv-Sicht
    /// (`get_sealed`) und der §11-Bereichs-Filter laufen über **dasselbe** S
    /// (§11.2) — ein nach dem Pinnen committeter Umbau bleibt für diesen Token
    /// unsichtbar (Snapshot-Isolation, kein Re-Lesen des Live-Watermarks).
    fn get_by_content_id(
        &self,
        id: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Option<SealedRecord>, KernelError> {
        // §13: das am Token gepinnte Watermark `W` fixiert die Aktiv-Sicht (§13.2).
        let w = snapshot.watermark();
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        // Server-seitig versiegeln: `None` ⇒ nicht vorhanden ODER §13-inaktiv unter `w`.
        let sealed = match store.get_sealed(id, w)? {
            Some(s) => s,
            None => return Ok(None),
        };
        // §11.3 Filter-vor-Auflösen / VANISH **an der Verb-Grenze**: ist das Daten
        // vorhanden, aber für diese Capability nicht sichtbar, kollabiert die
        // Rückgabe zu `Ok(None)` — ununterscheidbar von „nicht vorhanden", kein
        // Existenz-Orakel (§11.3). Reines Mengen-Matching (§1.3) über die durable
        // Wahrheit (`areas_of_checked`, fail-closed §11).
        let areas = store.areas_of_checked(id)?;
        if !crate::gate::is_visible(&areas, capability.scopes().scope_ids()) {
            // VANISH: verborgen ist ununterscheidbar von abwesend.
            return Ok(None);
        }
        Ok(Some(sealed))
    }

    /// **content_equal** (§1.3 i) — Gleichheit auf **Adressebene**: tragen `a` und
    /// `b` dieselbe [`ContentId`]? Reines Adress-Matching (§5.2), **kein** Wert-
    /// Vergleich (§1.4). Die `ContentId` ist ein berechenbarer, nicht-geheimer Hash;
    /// der Vergleich legt **keinen** Inhalt offen (kein Tor-Bypass) — er materialisiert
    /// nichts. Der `snapshot` wird formal entgegengenommen.
    fn content_equal(
        &self,
        a: ContentId,
        b: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = snapshot;
        Ok(a == b)
    }

    /// **context_points_to** (§1.3 ii) — „zeigt der Kontext `ctx` auf `target`?":
    /// besitzt der Knoten `ctx` das Daten `target` (§3.3)? Reines strukturelles
    /// Matching über den Vorwärts-Index (`owner → contexts`, §1.2/§3.2): `target`
    /// ist genau dann ein Ziel, wenn es in `contexts_of(ctx)` liegt. **Kein** Wert
    /// (§1.4); materialisiert keinen Inhalt.
    fn context_points_to(
        &self,
        ctx: ContentId,
        target: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = snapshot;
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        // `contexts_of` liefert aufsteigend sortierte owned IDs (§EdgeIndex) ⇒
        // Binärsuche ist zulässig (reines Mengen-Matching, §1.3).
        let ctxs = store.index().contexts_of(ctx)?;
        Ok(ctxs.binary_search(&target).is_ok())
    }

    /// **is_member_of_set** (§1.3 iii) — Zugehörigkeit zu der per Kontext gegebenen
    /// Menge: ist `elem` Mitglied der Menge, die der Mengen-Kontext `set_ctx`
    /// aufspannt? Reines Mengen-Matching über den Vorwärts-Index: `elem` ist genau
    /// dann Mitglied, wenn es in den von `set_ctx` besessenen Kontexten liegt.
    /// **Kein** Wert/Ordnung (§1.4); materialisiert keinen Inhalt.
    fn is_member_of_set(
        &self,
        elem: ContentId,
        set_ctx: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<bool, KernelError> {
        let _ = snapshot;
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let members = store.index().contexts_of(set_ctx)?;
        Ok(members.binary_search(&elem).is_ok())
    }

    /// **traverse** (§1.2/§1.7 a) — die beschränkte, zyklensichere mechanische
    /// Traversierung in der **frozen-Form**-Signatur (ohne explizite
    /// [`Capability`]).
    ///
    /// Da diese Trait-Form **keine** Capability trägt, läuft sie mit der **leersten
    /// möglichen** Sichtbarkeit (keine gewährten Bereiche): **unbeschränkte** Daten
    /// (ohne Bereichs-Zugehörigkeit) sind traversierbar, **bereichs-beschränkte**
    /// VANISHen (§11.3) — fail-safe, kein Leck ohne explizites Recht. Der volle
    /// gegatete Einstieg mit vorgelegter Capability ist
    /// [`LakearchKernel::traverse_with`].
    ///
    /// Deterministische Emission in aufsteigender `ContentId`-Adress-Order
    /// (§5.2/§1.4); `edge_type_filter` als strukturelles `ContentId`-Matching auf
    /// `edge_ctx` (§3.3). Budget-/Abbruch-/Inkonsistenz-Ende ist ein definierter
    /// [`KernelError`] (fail-closed §11).
    fn traverse<'a>(
        &'a self,
        start: ContentId,
        dir: Direction,
        max_depth: u32,
        max_nodes: u64,
        edge_type_filter: Option<&'a [ContentId]>,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        // §13: das am Token gepinnte Watermark `W` fixiert die Aktiv-Sicht für den
        // ganzen Lauf (eine Linearisierungsstelle) — kein Re-Lesen des Live-Watermarks.
        let w = snapshot.watermark();
        // Frozen-Form ohne Capability ⇒ fail-safe leere gewährte Bereiche: nur
        // unbeschränkte Daten sichtbar, beschränkte VANISHen (§11.3).
        let capability = Capability::issue(GrantedScopes::from_scope_ids([]));
        // Den Kanten-Typ-Filter in eine sortierte, owned Menge überführen (schnelle
        // Mitgliedschafts-Prüfung; aufsteigende Adress-Order, kein Wert-Sort §1.4).
        let edge_type_filter = edge_type_filter.map(|f| {
            let mut v = f.to_vec();
            v.sort_unstable();
            v.dedup();
            v
        });
        let params = TraversalParams {
            start,
            dir,
            max_depth,
            max_nodes,
            edge_type_filter,
        };
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        let steps = run_traversal(&store, &capability, &params, &CancelFlag::new(), w);
        Ok(Box::new(steps.into_iter()))
    }

    /// **find_dependents** (§10.2/§10.3) — findet die von `input` abhängigen
    /// materialisierten Ergebnisse durch **Rückwärts-Traversierung** der Herkunfts-
    /// Kontexte (*derived-from*: Eingabe → Ergebnisse), **transitiv** (ein Ergebnis
    /// kann selbst Eingabe eines weiteren sein) und **mechanisch** (§1.7 a):
    /// **deterministisch**, durch eine **Besuchsmenge beschränkt** und damit
    /// **zyklensicher** (§1.6/§1.7 a). Der Kernel **läuft nur rückwärts** und matcht
    /// (§1.3); das **Als-stale-markieren** und **Neu-Berechnen** liegt **außerhalb**
    /// (§1.5/§7.1) — dieses Verb fügt **kein** Verb hinzu, das neu berechnet oder
    /// auto-invalidiert.
    ///
    /// Jeder [`crate::api::Step`] ist eine durchschrittene Herkunfts-Kante: `from`
    /// (die geänderte Eingabe / ein abhängiges Zwischen-Ergebnis), `edge_ctx` (die
    /// `ContentId` des Herkunfts-Kontextes [`Datum::origin`]`(from)`, den das
    /// abhängige Ergebnis besitzt) und `to` (das abhängige Ergebnis). **Gegated**
    /// (§11.3, VANISH/fail-closed) und **§13-aktiv** über das am `snapshot` gepinnte
    /// Watermark `W`. **Frozen-Form ohne Capability** ⇒ fail-safe leere gewährte
    /// Bereiche (nur unbeschränkte Daten sichtbar, beschränkte VANISHen, §11.3); der
    /// volle gegatete Einstieg ist [`LakearchKernel::dependents_visible`] (eine Stufe).
    fn find_dependents<'a>(
        &'a self,
        input: ContentId,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let capability = Capability::issue(GrantedScopes::from_scope_ids([]));
        let steps = self.provenance_walk(input, ProvenanceDir::Dependents, u32::MAX, u64::MAX, &capability, snapshot)?;
        Ok(Box::new(steps.into_iter().map(Ok)))
    }

    /// **traverse_provenance_backward** (§10.2/§10.3) — die allgemeine **Rückwärts-
    /// Traversierung der Herkunfts-Kontexte** ab `result` (*origin*: Ergebnis →
    /// Eingaben → deren Eingaben …), beschränkt durch `max_depth`/`max_nodes` und
    /// **zyklensicher** über eine Besuchsmenge (§10.3/§1.7 a). Mechanisch (§1.4);
    /// **kein** Neu-Berechnen (§1.5).
    ///
    /// Jeder [`crate::api::Step`] ist eine durchschrittene Herkunfts-Kante: `from`
    /// (das Ergebnis / ein Zwischen-Ergebnis), `edge_ctx` (die `ContentId` des
    /// Herkunfts-Kontextes [`Datum::origin`]`(to)`, den `from` besitzt) und `to` (eine
    /// Eingabe). **Gegated** (§11.3, VANISH/fail-closed) und **§13-aktiv** über das am
    /// `snapshot` gepinnte Watermark `W`; **frozen-Form ohne Capability** ⇒ fail-safe
    /// leere gewährte Bereiche (§11.3).
    fn traverse_provenance_backward<'a>(
        &'a self,
        result: ContentId,
        max_depth: u32,
        max_nodes: u64,
        snapshot: SnapshotToken,
    ) -> Result<StepStream<'a>, KernelError> {
        let capability = Capability::issue(GrantedScopes::from_scope_ids([]));
        let steps = self.provenance_walk(result, ProvenanceDir::Origins, max_depth, max_nodes, &capability, snapshot)?;
        Ok(Box::new(steps.into_iter().map(Ok)))
    }
}

/// Richtung der **Herkunfts-Traversierung** (§10) — beide rein **mechanisch**
/// (§1.7 a), über die rebuildbaren Herkunfts-Indizes des Stores.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProvenanceDir {
    /// **Rückwärts** ab einem Ergebnis zu seinen **Eingaben** (*origin*; §10.2) —
    /// `traverse_provenance_backward`.
    Origins,
    /// Von einer **Eingabe** zu den **abhängigen Ergebnissen** (*derived-from*;
    /// die Invalidierungs-Rückwärts-Kante §10.3) — `find_dependents`.
    Dependents,
}

impl<I: EdgeIndex> LakearchKernel<I> {
    /// Gemeinsame **mechanische Herkunfts-Traversierung** (§10.2/§10.3/§1.7 a):
    /// **deterministisch** (aufsteigende `ContentId`-Adress-Order, §5.2/§1.4),
    /// durch eine **Besuchsmenge beschränkt** und damit **zyklensicher** (§1.6),
    /// **budget-beschränkt** (`max_depth`/`max_nodes` ⇒ definierter
    /// [`KernelError::TraversalBudgetExceeded`], nie unbeschränkter Speicher) und
    /// **gegated** (§11.3: VANISH/fail-closed; §13: aktiv unter dem gepinnten `W`).
    /// Der Kernel **matcht nur** (§1.3) und **berechnet nichts** (§1.5).
    ///
    /// Liefert die durchschrittenen [`crate::api::Step`]s als owned `Vec` (server-
    /// seitig vollständig materialisiert, aber durch `max_nodes` speicher-beschränkt).
    fn provenance_walk(
        &self,
        start: ContentId,
        dir: ProvenanceDir,
        max_depth: u32,
        max_nodes: u64,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Vec<crate::api::Step>, KernelError> {
        use crate::api::Step;
        use std::collections::HashSet;

        let w = snapshot.watermark();
        let granted = capability.scopes().scope_ids();
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;

        let mut steps: Vec<Step> = Vec::new();
        let mut visited: HashSet<ContentId> = HashSet::new();
        visited.insert(start);
        // BFS-Front: (Knoten, Tiefe). Die Front-Reihenfolge ist deterministisch, weil
        // die Nachbar-Listen aufsteigend adress-sortiert sind (§5.2/§1.4).
        let mut frontier: Vec<(ContentId, u32)> = vec![(start, 0)];

        while let Some((node, depth)) = frontier.pop() {
            if depth >= max_depth {
                continue;
            }
            // Nachbarn = die (sichtbaren, §13-aktiven) Daten, zu denen die Herkunfts-
            // Kante führt. Der `edge_ctx` ist strukturell der Herkunfts-Kontext, der
            // die beiden verbindet (§10.2) — je nach Richtung `origin(neighbor)` (ein
            // Ergebnis besitzt `origin(input)`) bzw. `origin(node)` (ein abhängiges
            // Ergebnis besitzt `origin(input=node)`).
            let raw = match dir {
                ProvenanceDir::Origins => store.origin_inputs_of(node),
                ProvenanceDir::Dependents => store.dependents_of(node),
            };
            let neighbors = store.visible_filter(&raw, granted, w)?;
            for neighbor in neighbors {
                let edge_ctx = match dir {
                    // node (Ergebnis) → neighbor (Eingabe): node besitzt origin(neighbor).
                    ProvenanceDir::Origins => ContentId::of_datum(&Datum::origin(neighbor)),
                    // node (Eingabe) → neighbor (abhängiges Ergebnis): neighbor besitzt origin(node).
                    ProvenanceDir::Dependents => ContentId::of_datum(&Datum::origin(node)),
                };
                if steps.len() as u64 >= max_nodes {
                    return Err(KernelError::TraversalBudgetExceeded);
                }
                steps.push(Step {
                    from: node,
                    edge_ctx,
                    to: neighbor,
                    depth: depth + 1,
                });
                // Zyklensicher (§1.6/§1.7 a): einen Knoten nie zweimal expandieren.
                if visited.insert(neighbor) {
                    frontier.push((neighbor, depth + 1));
                }
            }
        }
        // Deterministische Emission (§5.2/§1.4): aufsteigend nach (from, edge_ctx, to).
        steps.sort_unstable_by(|a, b| {
            (a.from, a.edge_ctx, a.to, a.depth).cmp(&(b.from, b.edge_ctx, b.to, b.depth))
        });
        Ok(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{open, GrantedScopes};
    use crate::index::RedbEdgeIndex;
    use crate::serialize::strict_decode;
    use tempfile::tempdir;

    /// Baut einen frischen Kernel (redb-Engine) in einem temporären Verzeichnis.
    fn open_kernel(dir: &std::path::Path) -> LakearchKernel<RedbEdgeIndex> {
        LakearchKernel::open(dir).expect("open kernel")
    }

    /// Mintet eine Capability + Snapshot über die Phase-1-Verben (so wie ein
    /// In-Process-Einbetter es täte).
    fn cap_and_snap(
        k: &LakearchKernel<RedbEdgeIndex>,
    ) -> (Capability, SnapshotToken) {
        let snap = k.pin_snapshot().expect("pin");
        let cap = k
            .authorize(GrantedScopes::from_scope_ids([]), snap)
            .expect("authorize");
        (cap, snap)
    }

    // ------------------------------------------------------------------------
    // Ende-zu-Ende: append → get_by_content_id → open → strikt dekodieren ⇒
    // dasselbe Daten (§5.2/§5.3 über das Tor, §11.5).
    // ------------------------------------------------------------------------

    #[test]
    fn append_then_get_round_trips_through_the_gate() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Ein kleiner Graph: zwei Blätter, ein Knoten, der beide besitzt.
        let x = k.append(&Datum::leaf(b"x".to_vec())).unwrap();
        let y = k.append(&Datum::leaf(b"y".to_vec())).unwrap();
        let node = Datum::node([x, y]).unwrap();
        let node_id = k.append(&node).unwrap();
        assert_eq!(node_id, ContentId::of_datum(&node));

        let (cap, snap) = cap_and_snap(&k);

        // Fetch durchs Tor: SealedRecord, dann open gegen die Capability.
        let sealed = k
            .get_by_content_id(node_id, &cap, snap)
            .unwrap()
            .expect("vorhanden");
        assert_eq!(sealed.content_id(), node_id);
        let visible = open(&sealed, &cap).expect("Tor legt Inhalt frei");
        assert_eq!(visible.content_id(), node_id);

        // Die freigelegten kanonischen Bytes dekodieren strikt zum Original (§K6).
        let decoded = strict_decode(visible.canonical_bytes()).unwrap();
        assert_eq!(decoded, node);
    }

    // ------------------------------------------------------------------------
    // VANISH-Vorform: unbekannte ID ⇒ None (Phase 2 macht „verborgen" hiervon
    // ununterscheidbar). Kein Panik, kein Orakel auf dieser Ebene.
    // ------------------------------------------------------------------------

    #[test]
    fn get_unknown_id_is_none() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let (cap, snap) = cap_and_snap(&k);
        let missing = ContentId::from_bytes([0xEE; 32]);
        assert!(k.get_by_content_id(missing, &cap, snap).unwrap().is_none());
    }

    // ------------------------------------------------------------------------
    // Dedup spiegelt sich in den Stats (§5.3): zweimal dasselbe Daten ⇒ ein
    // Append, ein Dedup-Treffer; Log-Bytes unverändert nach dem zweiten append.
    // ------------------------------------------------------------------------

    #[test]
    fn dedup_is_reflected_in_stats() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let d = Datum::leaf(b"once".to_vec());

        let id1 = k.append(&d).unwrap();
        let after_first = k.stats().unwrap();
        assert_eq!(after_first.append_count, 1);
        assert_eq!(after_first.dedup_hit_count, 0);
        let bytes_after_first = after_first.committed_bytes;

        // Zweites identisches append: Dedup-Treffer, kein neuer Record.
        let id2 = k.append(&d).unwrap();
        assert_eq!(id1, id2, "inhaltsgleich ⇒ dieselbe ContentId (§5.3)");

        let after_second = k.stats().unwrap();
        assert_eq!(after_second.append_count, 1, "kein zweiter physischer Record");
        assert_eq!(after_second.dedup_hit_count, 1, "ein Dedup-Treffer gezählt");
        assert_eq!(
            after_second.committed_bytes, bytes_after_first,
            "Dedup-Treffer schreibt nichts (Log-Bytes unverändert)"
        );
        // Plausible Log-Zähler: ein Batch (ein append_and_commit), fsyncs > 0.
        assert_eq!(after_second.batch_count, 1);
        assert!(after_second.fsync_count >= 1);
        assert_eq!(after_second.segment_count, 1);
    }

    // ------------------------------------------------------------------------
    // Reopen von Platte: nach Drop + Neu-Öffnen sind die Daten durabel lesbar,
    // die Kanten rekonstruiert (§8.4) und die committeten Bytes konsistent.
    // ------------------------------------------------------------------------

    #[test]
    fn reopen_from_disk_reads_back() {
        let dir = tempdir().unwrap();
        let (leaf_id, node_id, committed);
        {
            let k = open_kernel(dir.path());
            leaf_id = k.append(&Datum::leaf(b"persist".to_vec())).unwrap();
            let node = Datum::node([leaf_id]).unwrap();
            node_id = k.append(&node).unwrap();
            committed = k.stats().unwrap().committed_bytes;
        } // Kernel gedroppt → Log/Index geschlossen.

        // Neu öffnen: Recovery + Index-Versöhnung beim Öffnen.
        let k = open_kernel(dir.path());
        let stats = k.stats().unwrap();
        // Committete Bytes überstehen den Reopen (Watermark = durabler Tail).
        assert_eq!(stats.committed_bytes, committed);
        // append_count ist ein Mechanik-Zähler des laufenden Prozesses; nach einem
        // frischen Reopen ohne neue Appends ist er 0 (die Daten sind durabel, der
        // Zähler aber nicht persistiert — er zählt physische Schreibvorgänge).
        assert_eq!(stats.append_count, 0);

        let (cap, snap) = cap_and_snap(&k);

        // Beide Daten sind durabel über das Tor lesbar.
        let leaf_sealed = k
            .get_by_content_id(leaf_id, &cap, snap)
            .unwrap()
            .expect("Blatt durabel");
        let leaf_visible = open(&leaf_sealed, &cap).unwrap();
        assert_eq!(
            strict_decode(leaf_visible.canonical_bytes()).unwrap(),
            Datum::leaf(b"persist".to_vec())
        );

        let node_sealed = k
            .get_by_content_id(node_id, &cap, snap)
            .unwrap()
            .expect("Knoten durabel");
        let node_visible = open(&node_sealed, &cap).unwrap();
        assert_eq!(
            strict_decode(node_visible.canonical_bytes()).unwrap(),
            Datum::node([leaf_id]).unwrap()
        );

        // Erneutes append desselben Knotens nach Reopen ⇒ Dedup-Treffer (die
        // Dedup-Karte wurde aus dem Log rekonstruiert, §8.4).
        let again = k.append(&Datum::node([leaf_id]).unwrap()).unwrap();
        assert_eq!(again, node_id);
        assert_eq!(k.stats().unwrap().dedup_hit_count, 1);
    }

    // ------------------------------------------------------------------------
    // Phasen-Disziplin: die nicht verdrahteten Verben melden weiterhin ihre
    // Phase (NotYetImplemented), kein Verb panickt.
    // ------------------------------------------------------------------------

    #[test]
    fn unwired_verbs_still_report_their_phase() {
        // Nach Phase 6 sind Matching + Traversierung (Phase 2) und die Provenance-
        // Verben (Phase 6) verdrahtet; die noch unverdrahtete frozen-Form
        // `set_active_marker` (Phase 5 nutzt den konkreten `append_restructuring`)
        // meldet weiterhin ihre Phase, kein Verb panickt.
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();
        let a = ContentId::from_bytes([0x01; 32]);
        let b = ContentId::from_bytes([0x02; 32]);

        assert!(matches!(
            k.set_active_marker(&[a, b]),
            Err(KernelError::NotYetImplemented(5))
        ));
        // Phase 6 verdrahtet: die Provenance-Verben laufen (rückwärts, §10.3); für
        // ein unbekanntes Daten ist der Step-Strom leer (kein Fehler, kein Panic).
        let deps = k.find_dependents(a, snap).expect("find_dependents verdrahtet (Phase 6)");
        assert_eq!(deps.count(), 0, "unbekannte Eingabe ⇒ leerer Strom");
        let prov = k
            .traverse_provenance_backward(a, 4, 100, snap)
            .expect("traverse_provenance_backward verdrahtet (Phase 6)");
        assert_eq!(prov.count(), 0, "unbekanntes Ergebnis ⇒ leerer Strom");
    }

    // ------------------------------------------------------------------------
    // Phase 2: die drei §1.3-Prädikate sind verdrahtet (reines Matching).
    // ------------------------------------------------------------------------

    #[test]
    fn match_predicates_are_wired() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();

        let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
        let c = k.append(&Datum::leaf(b"c".to_vec())).unwrap();
        let a = k.append(&Datum::node([b, c]).unwrap()).unwrap();

        // content_equal: reine Adress-Gleichheit (§1.3 i).
        assert!(k.content_equal(a, a, snap).unwrap());
        assert!(!k.content_equal(a, b, snap).unwrap());

        // context_points_to: A besitzt B und C (§1.3 ii).
        assert!(k.context_points_to(a, b, snap).unwrap());
        assert!(k.context_points_to(a, c, snap).unwrap());
        // A besitzt sich nicht selbst.
        assert!(!k.context_points_to(a, a, snap).unwrap());

        // is_member_of_set: B und C sind Mitglieder der von A aufgespannten Menge
        // (§1.3 iii).
        assert!(k.is_member_of_set(b, a, snap).unwrap());
        assert!(k.is_member_of_set(c, a, snap).unwrap());
        let unknown = ContentId::from_bytes([0xEE; 32]);
        assert!(!k.is_member_of_set(unknown, a, snap).unwrap());
    }

    // ------------------------------------------------------------------------
    // Phase 2: die frozen-Form-`traverse` läuft (fail-safe leere Bereiche) und
    // emittiert in aufsteigender ContentId-Order.
    // ------------------------------------------------------------------------

    #[test]
    fn trait_traverse_runs_over_unrestricted_data() {
        use crate::api::Direction;
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
        let c = k.append(&Datum::leaf(b"c".to_vec())).unwrap();
        let a = k.append(&Datum::node([b, c]).unwrap()).unwrap();

        // Snapshot NACH den Appends pinnen (Snapshot-Isolation, §13: ein W fixiert
        // den Snapshot — nur bis dahin Durables ist sichtbar).
        let snap = k.pin_snapshot().unwrap();
        let stream = k
            .traverse(a, Direction::Forward, 2, 100, None, snap)
            .unwrap();
        let steps: Vec<_> = stream.map(|r| r.unwrap()).collect();
        let tos: Vec<ContentId> = steps.iter().map(|s| s.to).collect();
        let mut expected = vec![b, c];
        expected.sort_unstable();
        assert_eq!(tos, expected, "Forward-Nachbarn von A, aufsteigend");
    }

    // ------------------------------------------------------------------------
    // Phase 2: die gegatete `traverse_with` setzt die Sichtbarkeit (VANISH) durch.
    // ------------------------------------------------------------------------

    #[test]
    fn traverse_with_enforces_visibility() {
        use crate::api::Direction;
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _marker = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();
        let public_leaf = k.append(&Datum::leaf(b"public".to_vec())).unwrap();
        let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();
        let a = k.append(&Datum::node([public_leaf, secret]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        let p = TraversalParams {
            start: a,
            dir: Direction::Forward,
            max_depth: 2,
            max_nodes: 100,
            edge_type_filter: None,
        };

        // Ohne den Bereich: das geheime Daten VANISHt.
        let denied = k
            .authorize(GrantedScopes::from_scope_ids([]), snap)
            .unwrap();
        let steps: Vec<_> = k
            .traverse_with(p.clone(), &denied, snap, &CancelFlag::new())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(steps.iter().all(|s| s.to != secret), "geheim VANISHt");
        assert!(steps.iter().any(|s| s.to == public_leaf));

        // Mit dem Bereich: sichtbar.
        let granted = k
            .authorize(GrantedScopes::from_scope_ids([area]), snap)
            .unwrap();
        let steps2: Vec<_> = k
            .traverse_with(p, &granted, snap, &CancelFlag::new())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(steps2.iter().any(|s| s.to == secret), "mit Recht sichtbar");
    }

    // ------------------------------------------------------------------------
    // Phase 2: `authorize_subject` leitet die gewährten Bereiche aus aktiven
    // Berechtigungen ab; ein Entzug verbirgt künftige Reads (§11.1/§11.2/§11.4).
    // ------------------------------------------------------------------------

    /// Hängt eine vollständige Berechtigung an den Kernel und liefert ihre ID.
    fn append_permission(
        k: &LakearchKernel<RedbEdgeIndex>,
        subject: ContentId,
        area: ContentId,
    ) -> ContentId {
        k.append(&Datum::permission_subject_marker()).unwrap();
        k.append(&Datum::permission_area_marker()).unwrap();
        k.append(&Datum::permission_marker()).unwrap();
        k.append(&Datum::permission_subject_role(subject)).unwrap();
        k.append(&Datum::permission_area_role(area)).unwrap();
        k.append(&Datum::permission(subject, area)).unwrap()
    }

    #[test]
    fn authorize_subject_then_revoke_hides_future_reads() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let subject = k.append(&Datum::leaf(b"subject".to_vec())).unwrap();
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();
        let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();
        let perm = append_permission(&k, subject, area);

        // Aktiv: das Subjekt sieht das geheime Daten.
        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize_subject(subject, snap).unwrap();
        let sealed = k.get_by_content_id(secret, &cap, snap).unwrap().unwrap();
        assert!(open(&sealed, &cap).is_some(), "aktive Berechtigung ⇒ sichtbar");

        // Entzug ⇒ künftige Autorisierung gewährt den Bereich nicht mehr; das Verb
        // selbst liefert dann `None` (VANISH an der Verb-Grenze, §11.4/§11.3 — kein
        // Existenz-Orakel über die Rückgabeform).
        k.append(&Datum::revocation_marker()).unwrap();
        k.append(&Datum::revocation(perm)).unwrap();
        let snap2 = k.pin_snapshot().unwrap();
        let cap2 = k.authorize_subject(subject, snap2).unwrap();
        assert!(
            k.get_by_content_id(secret, &cap2, snap2).unwrap().is_none(),
            "nach Entzug ⇒ VANISH an der Verb-Grenze (§11.4)"
        );
    }

    // ------------------------------------------------------------------------
    // Filter-vor-Auflösen / VANISH über get_by_content_id (§11.3): ein
    // bereichs-beschränktes Daten ist ohne den Bereich schon an der VERB-GRENZE
    // None (ununterscheidbar von „existiert nicht") — kein Existenz-Orakel über
    // die Rückgabeform.
    // ------------------------------------------------------------------------

    #[test]
    fn get_by_content_id_filters_before_resolve() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();
        let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        // Ohne den Bereich: das Verb selbst liefert bereits `None` (VANISH) — die
        // Sichtbarkeit wird VOR der Rückgabe gematcht, sodass „vorhanden-aber-
        // verborgen" von „nicht vorhanden" ununterscheidbar ist (kein Existenz-
        // Orakel über die Rückgabeform, §11.3).
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(
            k.get_by_content_id(secret, &denied, snap).unwrap().is_none(),
            "verborgenes Daten ist an der Verb-Grenze None (VANISH, §11.3)"
        );

        // Eine unbekannte Adresse ist ebenfalls None — beide Fälle sind für den
        // rechtlosen Leser ununterscheidbar (kein Existenz-Orakel).
        let missing = ContentId::from_bytes([0xCD; 32]);
        assert!(k.get_by_content_id(missing, &denied, snap).unwrap().is_none());

        // Mit gewährtem Bereich wird dasselbe Daten sichtbar — erst dann gibt das
        // Verb ein `SealedRecord` heraus, das `open` freilegt.
        let granted = k
            .authorize(GrantedScopes::from_scope_ids([area]), snap)
            .unwrap();
        let sealed = k
            .get_by_content_id(secret, &granted, snap)
            .unwrap()
            .expect("mit Recht vorhanden");
        assert!(open(&sealed, &granted).is_some(), "mit Bereich sichtbar");
    }

    // ------------------------------------------------------------------------
    // KEIN EXISTENZ-ORAKEL an der Verb-Grenze (§11.3): die Rückgabeform von
    // `get_by_content_id` darf „vorhanden-aber-verborgen" NICHT von „nicht
    // vorhanden" unterscheidbar machen. Ein rechtloser Leser sieht für ein
    // verborgenes Daten und für eine zufällige unbekannte Adresse GENAU dieselbe
    // Form (`Ok(None)`).
    // ------------------------------------------------------------------------

    #[test]
    fn get_by_content_id_is_not_an_existence_oracle() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();
        let secret = k.append(&Datum::node([membership]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

        // Verborgenes (durabel vorhandenes) Daten ⇒ None.
        let hidden = k.get_by_content_id(secret, &denied, snap).unwrap();
        // Zufällige, nie geschriebene Adresse ⇒ None.
        let absent = k
            .get_by_content_id(ContentId::from_bytes([0x13; 32]), &denied, snap)
            .unwrap();
        // Die Rückgabeform ist in beiden Fällen IDENTISCH — kein Orakel (§11.3).
        assert!(hidden.is_none() && absent.is_none());
        assert_eq!(hidden.is_some(), absent.is_some());
    }

    // ------------------------------------------------------------------------
    // Phase 3: gegatete Ersetzungs-Traversierung in BEIDE Richtungen (§6.3) — eine
    // Kette überlebt Reopen + Wipe-&-Rebuild und ist von beiden Enden erreichbar.
    // ------------------------------------------------------------------------

    #[test]
    fn supersession_chain_is_gated_traversable_both_directions_and_survives_rebuild() {
        let dir = tempdir().unwrap();
        let (v1, v2, v3);
        {
            let k = open_kernel(dir.path());
            v1 = k.append(&Datum::leaf(b"v1".to_vec())).unwrap();
            k.append(&Datum::supersession_marker()).unwrap();
            let sup1 = k.append(&Datum::supersedes(v1)).unwrap();
            let p2 = k.append(&Datum::leaf(b"p2".to_vec())).unwrap();
            v2 = k.append(&Datum::node([sup1, p2]).unwrap()).unwrap();
            let sup2 = k.append(&Datum::supersedes(v2)).unwrap();
            let p3 = k.append(&Datum::leaf(b"p3".to_vec())).unwrap();
            v3 = k.append(&Datum::node([sup2, p3]).unwrap()).unwrap();

            // Capability für unbeschränkte Daten (keine Bereiche).
            let snap = k.pin_snapshot().unwrap();
            let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

            // supersedes (neuer → älter): v3→v2, v2→v1.
            assert_eq!(k.supersedes_visible(v3, &cap, snap).unwrap(), vec![v2]);
            assert_eq!(k.supersedes_visible(v2, &cap, snap).unwrap(), vec![v1]);
            // superseded-by (älter → neuer): v1→v2, v2→v3.
            assert_eq!(k.superseded_by_visible(v1, &cap, snap).unwrap(), vec![v2]);
            assert_eq!(k.superseded_by_visible(v2, &cap, snap).unwrap(), vec![v3]);
            // Das Älteste hat keine Vorgänger; das Neueste keine Nachfolger.
            assert!(k.supersedes_visible(v1, &cap, snap).unwrap().is_empty());
            assert!(k.superseded_by_visible(v3, &cap, snap).unwrap().is_empty());
        }
        // Reopen: die Ersetzungs-Indizes sind aus dem Log rekonstruiert (§8.4).
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert_eq!(k.supersedes_visible(v3, &cap, snap).unwrap(), vec![v2]);
        assert_eq!(k.superseded_by_visible(v1, &cap, snap).unwrap(), vec![v2]);
    }

    // ------------------------------------------------------------------------
    // Phase 3: ein NICHT-SICHTBARES überholendes Daten VANISHt (§11.3) — der
    // gegatete superseded-by-Helfer leakt es nicht.
    // ------------------------------------------------------------------------

    #[test]
    fn non_visible_superseding_datum_vanishes() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Bereich + Zugehörigkeits-Kontext für ein „geheimes" neueres Daten.
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();

        // older ist unbeschränkt; das überholende newer gehört dem Bereich an.
        let older = k.append(&Datum::leaf(b"old".to_vec())).unwrap();
        k.append(&Datum::supersession_marker()).unwrap();
        let sup = k.append(&Datum::supersedes(older)).unwrap();
        // newer besitzt den Ersetzungs-Kontext UND den Zugehörigkeits-Kontext ⇒
        // bereichs-beschränkt.
        let newer = k.append(&Datum::node([sup, membership]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        // Rechtloser Leser: das überholende (geheime) Daten VANISHt.
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(
            k.superseded_by_visible(older, &denied, snap).unwrap().is_empty(),
            "nicht-sichtbares überholendes Daten VANISHt (§11.3)"
        );
        // Mit dem Bereich wird es sichtbar.
        let granted = k.authorize(GrantedScopes::from_scope_ids([area]), snap).unwrap();
        assert_eq!(k.superseded_by_visible(older, &granted, snap).unwrap(), vec![newer]);
    }

    // ------------------------------------------------------------------------
    // Phase 3: gegateter Zeit-Aussage-Lookup (§6.1/§6.2) liefert die Träger;
    // nicht-sichtbare Träger VANISHen (§11.3).
    // ------------------------------------------------------------------------

    #[test]
    fn gated_time_lookup_returns_visible_carriers() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();

        let t = k.append(&Datum::leaf(b"T".to_vec())).unwrap();
        k.append(&Datum::recording_time_marker()).unwrap();
        let stmt = k.append(&Datum::recording_time(t)).unwrap();

        // Ein öffentlicher Träger und ein geheimer Träger derselben Zeit-Aussage.
        let public_carrier = k.append(&Datum::node([stmt]).unwrap()).unwrap();
        let secret_carrier = k.append(&Datum::node([stmt, membership]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        // Rechtloser Leser: nur der öffentliche Träger; der geheime VANISHt.
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert_eq!(
            k.time_carriers_visible(stmt, &denied, snap).unwrap(),
            vec![public_carrier],
            "geheimer Träger VANISHt (§11.3)"
        );
        // Mit dem Bereich: beide.
        let granted = k.authorize(GrantedScopes::from_scope_ids([area]), snap).unwrap();
        let mut both = k.time_carriers_visible(stmt, &granted, snap).unwrap();
        both.sort_unstable();
        let mut expected = vec![public_carrier, secret_carrier];
        expected.sort_unstable();
        assert_eq!(both, expected);
    }

    // ------------------------------------------------------------------------
    // Phase 3: vom Platzhalter ist das auflösende echte Daten über die gegatete
    // Traversierung erreichbar (§3.6/§6.3); der Platzhalter bleibt unverändert.
    // ------------------------------------------------------------------------

    #[test]
    fn placeholder_resolver_is_reachable_via_gated_traversal() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Einen Platzhalter anhängen (§3.6) und dann über die öffentliche Kernel-
        // Oberfläche auflösen (§6.3).
        let placeholder_id = k.append(&Datum::placeholder([])).unwrap();
        let real = Datum::leaf(b"echtes-ziel".to_vec());
        let (real_id, _res) = k.resolve_placeholder(placeholder_id, &real).unwrap();
        // Plausibilität: real_id ist die ContentId des echten Daten.
        assert_eq!(real_id, ContentId::of_datum(&Datum::leaf(b"echtes-ziel".to_vec())));

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        // Vom Platzhalter zum auflösenden echten Daten (gegatet).
        let resolvers = k.placeholder_resolvers_visible(placeholder_id, &cap, snap).unwrap();
        let real_id = ContentId::of_datum(&Datum::leaf(b"echtes-ziel".to_vec()));
        assert_eq!(resolvers, vec![real_id], "Platzhalter → Auflöser erreichbar (§3.6)");

        // Append-only: der Platzhalter ist über das Tor unverändert lesbar (§7.1).
        let sealed = k.get_by_content_id(placeholder_id, &cap, snap).unwrap().unwrap();
        let visible = open(&sealed, &cap).unwrap();
        let decoded = strict_decode(visible.canonical_bytes()).unwrap();
        assert!(decoded.is_placeholder(), "Platzhalter bleibt ein Platzhalter (§7.1)");
    }

    // ------------------------------------------------------------------------
    // Phase 3 / §1.4/§6.4: es gibt KEIN Kernel-Verb, das Zeit ordnet oder „die
    // aktive" Version nach Zeit auswählt. Dieser Test friert die Negativ-Garantie
    // ein: die Zeit-/Ersetzungs-Helfer liefern reine Mengen (Vec<ContentId>) ohne
    // Ordnungs-/Auswahl-Semantik, und sie ignorieren die opaken Zeit-Werte.
    // ------------------------------------------------------------------------

    #[test]
    fn no_kernel_verb_orders_or_selects_by_time() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Zwei verschiedene Zeit-Werte (opak); zwei Aussagen, je ein Träger.
        let t_early = k.append(&Datum::leaf(b"0001".to_vec())).unwrap();
        let t_late = k.append(&Datum::leaf(b"9999".to_vec())).unwrap();
        k.append(&Datum::recording_time_marker()).unwrap();
        let stmt_early = k.append(&Datum::recording_time(t_early)).unwrap();
        let stmt_late = k.append(&Datum::recording_time(t_late)).unwrap();
        let carrier_early = k.append(&Datum::node([stmt_early]).unwrap()).unwrap();
        let carrier_late = k.append(&Datum::node([stmt_late]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

        // Der Lookup liefert je AUSSAGE GENAU ihre Träger — er kombiniert/ordnet die
        // beiden Zeit-Werte NICHT (kein „neuester gewinnt", kein Bereich). Es gibt
        // keinen Verb-Aufruf der Gestalt `active_at(time) -> the_one`.
        assert_eq!(k.time_carriers_visible(stmt_early, &cap, snap).unwrap(), vec![carrier_early]);
        assert_eq!(k.time_carriers_visible(stmt_late, &cap, snap).unwrap(), vec![carrier_late]);

        // Das Ergebnis ist eine Adress-sortierte Menge (deterministisch, §5.2/§1.4) —
        // ihre Reihenfolge spiegelt die ContentId-Adressen, NICHT die Zeit-Werte:
        // selbst wenn t_early „kleiner" als t_late ist, hängt die Lookup-Ausgabe
        // allein an der jeweils abgefragten Aussage, nicht an einem Zeit-Vergleich.
        // (Der Kernel besitzt keinen Pfad, der die zwei opaken Werte vergleicht.)
        let early_addr_first = ContentId::of_datum(&Datum::leaf(b"0001".to_vec()))
            < ContentId::of_datum(&Datum::leaf(b"9999".to_vec()));
        // Adress-Ordnung ist von der „chronologischen" Ordnung der Bytes entkoppelt;
        // wir belegen nur, dass kein Zeit-Vergleich stattfindet (beide Lookups sind
        // unabhängig und je-Aussage exakt).
        let _ = early_addr_first;
    }

    // ------------------------------------------------------------------------
    // Phase 4: gegatete Anker-Mitgliedschaft in BEIDE Richtungen (§9.1/§9.3); ein
    // nicht-sichtbarer Repräsentant VANISHt (§11.3). Der lokale AnchorId-Handle
    // (§12.4) ist über die öffentliche Oberfläche erreichbar.
    // ------------------------------------------------------------------------

    #[test]
    fn gated_anchor_membership_both_directions_and_vanish() {
        use crate::id::AnchorId;
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Anker (§9.1) — ein gewöhnliches Daten mit lokalem Handle (§12.4).
        let class = k.append(&Datum::leaf(b"klasse".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor = k.append(&Datum::anchor([class])).unwrap();
        assert_eq!(k.anchor_id_of(anchor).unwrap(), Some(AnchorId::new(0)));
        assert_eq!(k.anchor_cid_of(AnchorId::new(0)).unwrap(), Some(anchor));

        // Bereich für einen „geheimen" Repräsentanten.
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        k.append(&Datum::area_membership_marker()).unwrap();
        let area_member = k.append(&Datum::area_membership(area)).unwrap();

        // Zwei Mitgliedschaften (gradiert) zum selben Anker (§9.3).
        let g1 = k.append(&Datum::leaf(b"g1".to_vec())).unwrap();
        let g2 = k.append(&Datum::leaf(b"g2".to_vec())).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        k.append(&Datum::membership_grade(g1)).unwrap();
        k.append(&Datum::membership_grade(g2)).unwrap();
        let m1 = k.append(&Datum::membership(anchor, g1)).unwrap();
        let m2 = k.append(&Datum::membership(anchor, g2)).unwrap();
        let public_rep = k.append(&Datum::node([m1]).unwrap()).unwrap();
        // Der geheime Repräsentant ist bereichs-beschränkt.
        let secret_rep = k.append(&Datum::node([m2, area_member]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        // Rechtloser Leser: nur der öffentliche Repräsentant; der geheime VANISHt.
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert_eq!(
            k.anchor_members_visible(anchor, &denied, snap).unwrap(),
            vec![public_rep],
            "geheimer Repräsentant VANISHt (§11.3)"
        );
        // Repräsentant→Anker (Gegenrichtung, §9.1).
        assert_eq!(k.member_anchors_visible(public_rep, &denied, snap).unwrap(), vec![anchor]);

        // Mit dem Bereich: beide Repräsentanten.
        let granted = k.authorize(GrantedScopes::from_scope_ids([area]), snap).unwrap();
        let mut both = k.anchor_members_visible(anchor, &granted, snap).unwrap();
        both.sort_unstable();
        let mut expected = vec![public_rep, secret_rep];
        expected.sort_unstable();
        assert_eq!(both, expected);
    }

    // ------------------------------------------------------------------------
    // Phase 4: gradierte Identitäts-Links (§5.5) sind von beiden erwähnten Daten
    // gegated erreichbar; die reifizierte Konfidenz wird GEHALTEN, aber NIE
    // verglichen (es existiert kein solches Verb).
    // ------------------------------------------------------------------------

    #[test]
    fn gated_graded_identity_links_hold_confidence_without_comparing() {
        use crate::model::IdentityStrength;
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let a = k.append(&Datum::leaf(b"a".to_vec())).unwrap();
        let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
        // Reifizierte, opake Konfidenz (§3.4/§5.5).
        let conf_val = k.append(&Datum::leaf(b"konf=0.8".to_vec())).unwrap();
        let conf_ctx = k.append(&Datum::node([conf_val]).unwrap()).unwrap();
        k.append(&Datum::identity_strength_marker(IdentityStrength::WidersprichtIn)).unwrap();
        let ident = k
            .append(&Datum::graded_identity(a, b, IdentityStrength::WidersprichtIn, [conf_ctx]))
            .unwrap();

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        // Von a UND b aus auffindbar (beide Richtungen, §1.2).
        assert_eq!(k.graded_identity_links_visible(a, &cap, snap).unwrap(), vec![ident]);
        assert_eq!(k.graded_identity_links_visible(b, &cap, snap).unwrap(), vec![ident]);

        // Der Identitäts-Kontext ist über das Tor lesbar; seine Stärke + Konfidenz
        // sind GEHALTEN. Der Kernel VERGLEICHT die Konfidenz NICHT (er reicht nur die
        // rohen Sub-Kontext-IDs heraus; die Schicht darüber wertet, §1.4/§5.5).
        let sealed = k.get_by_content_id(ident, &cap, snap).unwrap().unwrap();
        let visible = open(&sealed, &cap).unwrap();
        let decoded = strict_decode(visible.canonical_bytes()).unwrap();
        assert_eq!(decoded.identity_strength(), Some(IdentityStrength::WidersprichtIn));
        let ctxs = decoded.graded_identity_contexts().unwrap();
        assert!(ctxs.contains(&conf_ctx), "Konfidenz reifiziert + gehalten (§3.4/§5.5)");
    }

    // ------------------------------------------------------------------------
    // Phase 4: Kuratierung — Verbergen ist ein reversibler Lese-Filter (§9.5). Ein
    // verborgenes Daten VANISHt aus der gegateten Projektion; ein Aufheben
    // reversiert es. NICHTS wird gelöscht (§7.1) — das Daten bleibt durabel.
    // ------------------------------------------------------------------------

    #[test]
    fn curation_hide_is_a_reversible_readside_filter_over_public_api() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Ein Anker mit einem Repräsentanten, den wir kuratorisch verbergen.
        let class = k.append(&Datum::leaf(b"k".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor = k.append(&Datum::anchor([class])).unwrap();
        let g = k.append(&Datum::leaf(b"g".to_vec())).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        k.append(&Datum::membership_grade(g)).unwrap();
        let m = k.append(&Datum::membership(anchor, g)).unwrap();
        let rep = k.append(&Datum::node([m]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        // Anfangs sichtbar.
        assert_eq!(k.anchor_members_visible(anchor, &cap, snap).unwrap(), vec![rep]);

        // Verbergen (§9.5): der Repräsentant VANISHt aus der gegateten Projektion.
        k.append(&Datum::curation_hide_marker()).unwrap();
        k.append(&Datum::curation_hide(rep)).unwrap();
        assert!(
            k.anchor_members_visible(anchor, &cap, snap).unwrap().is_empty(),
            "verborgener Repräsentant VANISHt (§9.5/§11.3)"
        );
        // Append-only: das Daten bleibt durabel über das Tor lesbar (§7.1) — nur die
        // (kuratierte) Leseseite filtert es. Es ist NICHT gelöscht.
        // (get_by_content_id filtert NUR nach Bereich; Kuratierung greift in der
        // gegateten Mengen-Projektion. Der Inhalt selbst bleibt erhalten.)
        let sealed = k.get_by_content_id(rep, &cap, snap).unwrap();
        assert!(sealed.is_some(), "verborgenes Daten ist nicht gelöscht (§7.1)");

        // Aufheben (§9.5): reversiert — append-only, nichts gelöscht.
        k.append(&Datum::curation_unhide_marker()).unwrap();
        k.append(&Datum::curation_unhide(rep)).unwrap();
        assert_eq!(
            k.anchor_members_visible(anchor, &cap, snap).unwrap(),
            vec![rep],
            "Aufheben macht den Repräsentanten wieder sichtbar (§9.5)"
        );
    }

    // ------------------------------------------------------------------------
    // Phase 4 / HARTE GRENZE (§9-Präambel/§1.4/§5.5): es gibt KEIN Kernel-Verb, das
    // eine Identität AUFLÖST, einen „gewinnenden" Repräsentanten WÄHLT/RANKT, eine
    // Konfidenz VERGLEICHT/SCHWELLT oder destruktiv MERGT. Dieser Test friert die
    // Grenze ein: der Kernel liefert nur ROHE Mengen (Vec<ContentId>) — er hält die
    // Strukturen, er entscheidet nicht.
    // ------------------------------------------------------------------------

    #[test]
    fn kernel_never_resolves_ranks_or_thresholds_identity() {
        use crate::model::IdentityStrength;
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Ein Anker mit ZWEI Repräsentanten unterschiedlichen Grades — der Kernel
        // wählt KEINEN „besten" aus; er gibt beide roh heraus.
        let class = k.append(&Datum::leaf(b"k".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor = k.append(&Datum::anchor([class])).unwrap();
        let g_high = k.append(&Datum::leaf(b"0.99".to_vec())).unwrap();
        let g_low = k.append(&Datum::leaf(b"0.10".to_vec())).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        k.append(&Datum::membership_grade(g_high)).unwrap();
        k.append(&Datum::membership_grade(g_low)).unwrap();
        let m_high = k.append(&Datum::membership(anchor, g_high)).unwrap();
        let m_low = k.append(&Datum::membership(anchor, g_low)).unwrap();
        let rep_high = k.append(&Datum::node([m_high]).unwrap()).unwrap();
        let rep_low = k.append(&Datum::node([m_low]).unwrap()).unwrap();

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

        // Der Kernel liefert BEIDE Repräsentanten (Adress-sortierte Menge) — er rankt
        // NICHT nach Grad und wählt KEINEN „Gewinner" (§9-Präambel/§1.4). Hätte er ein
        // Auflösungs-Verb, läge hier eine Auswahl; es existiert keines.
        let mut members = k.anchor_members_visible(anchor, &cap, snap).unwrap();
        members.sort_unstable();
        let mut expected = vec![rep_high, rep_low];
        expected.sort_unstable();
        assert_eq!(members, expected, "beide Repräsentanten roh, kein Ranking (§1.4)");

        // Auch die gradierte Identität liefert nur rohe Kontext-IDs; die Stärke ist
        // eine Etikette OHNE Ordnung (IdentityStrength leitet kein Ord ab, §5.5/§1.4).
        let a = k.append(&Datum::leaf(b"a".to_vec())).unwrap();
        let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
        k.append(&Datum::identity_strength_marker(IdentityStrength::Deckungsgleich)).unwrap();
        let ident = k
            .append(&Datum::graded_identity(a, b, IdentityStrength::Deckungsgleich, []))
            .unwrap();
        // FRISCHER Snapshot nach den neuen Appends (Snapshot-Isolation, §13: ein W
        // fixiert den Snapshot — nach dem Pin Angehängtes ist für das alte Token
        // unsichtbar; wir pinnen daher neu).
        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        // Es gibt KEIN Verb `is_same(a, b) -> bool`/`confidence(a, b) -> f64`/
        // `winner(anchor) -> rep`; der einzige Pfad ist das rohe Link-Lesen.
        assert_eq!(k.graded_identity_links_visible(a, &cap, snap).unwrap(), vec![ident]);
        // Die Stärke ist nur strukturell ablesbar (kein Vergleich/Rang, §1.4).
        let sealed = k.get_by_content_id(ident, &cap, snap).unwrap().unwrap();
        let decoded = strict_decode(open(&sealed, &cap).unwrap().canonical_bytes()).unwrap();
        assert_eq!(decoded.identity_strength(), Some(IdentityStrength::Deckungsgleich));
    }

    // ========================================================================
    // Phase 5 — Atomarität (§13 Aktiv-Marker). Die §13-Sichtbarkeit ist in JEDEN
    // Lesepfad eingewoben: ein INAKTIVER (durch einen noch nicht committeten Marker
    // regierter) Konstituent wird über `get_by_content_id`, die Traversierung UND
    // jeden gegateten Helfer NIE beobachtet (§13.2); der Marker-Commit flippt den
    // ganzen Umbau ATOMAR gemeinsam sichtbar (§13.1). Orthogonal zum §11-Tor.
    // ========================================================================

    // ------------------------------------------------------------------------
    // §13: ein Mehr-Daten-Umbau ist über ALLE Lesepfade unsichtbar, bis sein
    // Marker committet — danach atomar vollständig sichtbar. Gegateter Helfer:
    // eine atomare Anker-Mitgliedschaft (Phase 4) wird gemeinsam freigegeben.
    // ------------------------------------------------------------------------

    #[test]
    fn restructuring_invisible_until_marker_then_atomically_visible() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // VORBEDINGUNG (aktiv, vor dem Umbau): ein Anker existiert bereits, ebenso die
        // Marker-Atome, die der Umbau referenziert (geschlossene Verweise, §3.6). Diese
        // sind UNBEDINGTE Einzel-Appends und damit sofort aktiv.
        let class = k.append(&Datum::leaf(b"klasse".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor = k.append(&Datum::anchor([class])).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        let grade = k.append(&Datum::leaf(b"g".to_vec())).unwrap();
        k.append(&Datum::membership_grade(grade)).unwrap();

        // Der UMBAU (§13): zwei gemeinsam sichtbar werdende Daten — der
        // Mitgliedschafts-Kontext und der ihn besitzende Repräsentant. Vorab ihre
        // ContentIds berechnen (kein Schreiben).
        let membership = Datum::membership(anchor, grade);
        let membership_id = ContentId::of_datum(&membership);
        let rep = Datum::node([membership_id]).unwrap();
        let rep_id = ContentId::of_datum(&rep);

        let cap_for = |snap| {
            k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap()
        };

        // --- Phase 1: stagen (INAKTIV) ---------------------------------------
        let handle = k.stage_restructuring(&[membership.clone(), rep.clone()]).unwrap();
        assert_eq!(handle.constituent_ids(), &[membership_id, rep_id]);

        let snap_staged = k.pin_snapshot().unwrap();
        let cap_staged = cap_for(snap_staged);

        // (a) get_by_content_id: beide Konstituenten VANISHen (ununterscheidbar von
        //     „nicht vorhanden", §13.2/§11.3).
        assert!(k.get_by_content_id(membership_id, &cap_staged, snap_staged).unwrap().is_none());
        assert!(k.get_by_content_id(rep_id, &cap_staged, snap_staged).unwrap().is_none());

        // (b) Traversierung: der Repräsentant erscheint NICHT als sichtbarer Knoten —
        //     der gegatete Helfer liefert KEINE Mitglieder für den Anker.
        assert!(
            k.anchor_members_visible(anchor, &cap_staged, snap_staged).unwrap().is_empty(),
            "inaktiver Repräsentant VANISHt aus dem gegateten Helfer (§13.2)"
        );
        // (c) Traversierung vom (aktiven) Anker rückwärts findet den inaktiven
        //     Repräsentanten NICHT (Front-Stopp).
        let p = TraversalParams {
            start: anchor,
            dir: Direction::Backward,
            max_depth: 3,
            max_nodes: 100,
            edge_type_filter: None,
        };
        let staged_steps: Vec<_> = k
            .traverse_with(p.clone(), &cap_staged, snap_staged, &CancelFlag::new())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            staged_steps.iter().all(|s| s.to != rep_id && s.to != membership_id),
            "inaktive Konstituenten VANISHen aus der Traversierung (§13.2)"
        );

        // --- Phase 2: Marker committen (ATOMAR sichtbar) ---------------------
        // Der Marker ist das bloße Aktiv-Marker-Atom (§13): die Konstituenten-Audit-
        // Information trägt der LOG-Header (`constituent_range`), nicht das Marker-
        // Daten — so erzeugt der Marker keine semantischen Kanten (er ist KEIN
        // Repräsentant des Ankers).
        let marker = Datum::active_marker();
        let marker_id = k.commit_restructuring(handle, &marker).unwrap();

        let snap_done = k.pin_snapshot().unwrap();
        let cap_done = cap_for(snap_done);

        // (a) get: BEIDE Konstituenten sind jetzt sichtbar (atomar gemeinsam, §13.1).
        let m_sealed = k.get_by_content_id(membership_id, &cap_done, snap_done).unwrap();
        let r_sealed = k.get_by_content_id(rep_id, &cap_done, snap_done).unwrap();
        assert!(m_sealed.is_some() && r_sealed.is_some(), "Umbau atomar sichtbar (§13.1)");
        assert!(open(&m_sealed.unwrap(), &cap_done).is_some());
        assert!(open(&r_sealed.unwrap(), &cap_done).is_some());

        // (b) der gegatete Anker-Helfer liefert nun den Repräsentanten.
        assert_eq!(
            k.anchor_members_visible(anchor, &cap_done, snap_done).unwrap(),
            vec![rep_id],
            "nach Marker: Mitgliedschaft gemeinsam sichtbar (§13.1)"
        );
        // (c) der Marker selbst ist ein unbedingtes, sichtbares Daten.
        assert!(k.get_by_content_id(marker_id, &cap_done, snap_done).unwrap().is_some());
    }

    // ------------------------------------------------------------------------
    // §13 SNAPSHOT-ISOLATION (ein W fixiert den Snapshot): ein VOR dem Marker-Commit
    // gepinnter Token sieht den Umbau NIE — auch nicht, nachdem der Marker committet
    // ist. Die §13-Aktiv-Sicht hängt am gepinnten Watermark des Tokens, NICHT am
    // (vorangerückten) Live-Watermark. Nur ein FRISCH gepinnter Snapshot sieht den
    // committeten Umbau. Das ist der Kern der Phase-5-Leser-Invariante.
    // ------------------------------------------------------------------------

    #[test]
    fn pinned_snapshot_does_not_see_restructuring_committed_after_pin() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Vorbedingung: ein Anker + Marker-Atome (unbedingt, sofort aktiv).
        let class = k.append(&Datum::leaf(b"klasse".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor = k.append(&Datum::anchor([class])).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        let grade = k.append(&Datum::leaf(b"g".to_vec())).unwrap();
        k.append(&Datum::membership_grade(grade)).unwrap();

        // Der Umbau: Mitgliedschaft + Repräsentant, gemeinsam sichtbar werdend.
        let membership = Datum::membership(anchor, grade);
        let membership_id = ContentId::of_datum(&membership);
        let rep = Datum::node([membership_id]).unwrap();
        let rep_id = ContentId::of_datum(&rep);

        // (1) Snapshot PINNEN, BEVOR der Umbau überhaupt gestaget/committet ist.
        let snap_old = k.pin_snapshot().unwrap();
        let cap_old = k.authorize(GrantedScopes::from_scope_ids([]), snap_old).unwrap();

        // (2) Umbau VOLLSTÄNDIG stagen UND committen (Marker durabel) — NACH dem Pin.
        let (_cids, _mid) = k
            .append_restructuring(&[membership.clone(), rep.clone()], &Datum::active_marker())
            .unwrap();

        // (3) Mit dem ALTEN Token: der Umbau bleibt UNSICHTBAR (sein Watermark `W`
        //     liegt vor dem Marker-Commit) — Snapshot-Isolation, ein W fixiert den
        //     Snapshot. KEIN Re-Lesen des Live-Watermarks.
        assert!(
            k.get_by_content_id(membership_id, &cap_old, snap_old).unwrap().is_none(),
            "alter Token sieht den nach dem Pin committeten Umbau NICHT (Snapshot-Isolation)"
        );
        assert!(
            k.get_by_content_id(rep_id, &cap_old, snap_old).unwrap().is_none(),
            "alter Token sieht den Repräsentanten NICHT"
        );
        assert!(
            k.anchor_members_visible(anchor, &cap_old, snap_old).unwrap().is_empty(),
            "gegateter Helfer am alten Snapshot sieht den Umbau NICHT"
        );
        // Auch die Traversierung am alten Token findet den Repräsentanten nicht.
        let p = TraversalParams {
            start: anchor,
            dir: Direction::Backward,
            max_depth: 3,
            max_nodes: 100,
            edge_type_filter: None,
        };
        let old_steps: Vec<_> = k
            .traverse_with(p.clone(), &cap_old, snap_old, &CancelFlag::new())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            old_steps.iter().all(|s| s.to != rep_id && s.to != membership_id),
            "alter Snapshot: Umbau VANISHt aus der Traversierung"
        );

        // (4) Ein FRISCH gepinnter Snapshot sieht den (jetzt durablen) Umbau.
        let snap_new = k.pin_snapshot().unwrap();
        let cap_new = k.authorize(GrantedScopes::from_scope_ids([]), snap_new).unwrap();
        assert!(
            k.get_by_content_id(membership_id, &cap_new, snap_new).unwrap().is_some(),
            "frischer Snapshot sieht den committeten Umbau (§13.1)"
        );
        assert_eq!(
            k.anchor_members_visible(anchor, &cap_new, snap_new).unwrap(),
            vec![rep_id],
            "frischer Snapshot: Mitgliedschaft gemeinsam sichtbar (§13.1)"
        );
    }

    // ------------------------------------------------------------------------
    // §13 + §11 KOMPONIEREN (beide pre-resolution, orthogonal): ein Umbau, dessen
    // Konstituent SOWOHL bereichs-beschränkt (out-of-scope) ALS AUCH inaktiv
    // (Marker fehlt) ist, bleibt verborgen — und zwar:
    //   - inaktiv  ⇒ verborgen für JEDEN (auch mit gewährtem Bereich),
    //   - aktiv aber out-of-scope ⇒ verborgen ohne den Bereich (VANISH §11.3),
    //   - aktiv UND in-scope ⇒ sichtbar.
    // ------------------------------------------------------------------------

    #[test]
    fn gate_and_section13_compose_out_of_scope_and_inactive_stays_hidden() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Vorbedingung: Bereich + Zugehörigkeits-Marker (unbedingt, sofort aktiv).
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();

        // Der Umbau-Konstituent: ein bereichs-beschränktes Daten (besitzt den
        // Zugehörigkeits-Kontext) — vorab ID berechnen.
        let restricted = Datum::node([membership]).unwrap();
        let restricted_id = ContentId::of_datum(&restricted);

        // --- gestaget (INAKTIV) ---------------------------------------------
        let handle = k.stage_restructuring(std::slice::from_ref(&restricted)).unwrap();
        let snap = k.pin_snapshot().unwrap();
        // Selbst MIT gewährtem Bereich bleibt es verborgen, weil es §13-inaktiv ist
        // (§13 läuft NEBEN dem §11-Filter; inaktiv ⇒ unsichtbar, unabhängig vom Recht).
        let cap_granted = k.authorize(GrantedScopes::from_scope_ids([area]), snap).unwrap();
        assert!(
            k.get_by_content_id(restricted_id, &cap_granted, snap).unwrap().is_none(),
            "inaktiv ⇒ verborgen, AUCH mit gewährtem Bereich (§13 ∧ §11)"
        );
        // Ohne den Bereich erst recht.
        let cap_denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(k.get_by_content_id(restricted_id, &cap_denied, snap).unwrap().is_none());

        // --- Marker committet (jetzt aktiv) ---------------------------------
        let marker = Datum::active_marker();
        k.commit_restructuring(handle, &marker).unwrap();
        let snap2 = k.pin_snapshot().unwrap();

        // Aktiv, aber OHNE den Bereich ⇒ weiterhin VANISH (§11.3 greift jetzt).
        let cap_denied2 = k.authorize(GrantedScopes::from_scope_ids([]), snap2).unwrap();
        assert!(
            k.get_by_content_id(restricted_id, &cap_denied2, snap2).unwrap().is_none(),
            "aktiv, aber out-of-scope ⇒ VANISH (§11.3)"
        );
        // Aktiv UND in-scope ⇒ endlich sichtbar (beide Prädikate erfüllt).
        let cap_granted2 = k.authorize(GrantedScopes::from_scope_ids([area]), snap2).unwrap();
        assert!(
            k.get_by_content_id(restricted_id, &cap_granted2, snap2).unwrap().is_some(),
            "aktiv ∧ in-scope ⇒ sichtbar (§13 ∧ §11 beide erfüllt)"
        );
    }

    // ------------------------------------------------------------------------
    // §13 WIPE-&-REBUILD (§8.4): nach dem Verwerfen aller reinen Derivate und Neu-
    // Bau aus dem Log ist die §13-Sichtbarkeit IDENTISCH rekonstruiert — der
    // regierende Marker-Offset jedes Konstituenten kommt aus dem Record-Header.
    // ------------------------------------------------------------------------

    #[test]
    fn wipe_and_rebuild_reconstructs_section13_visibility_identically() {
        let dir = tempdir().unwrap();

        // Einen vollständigen Umbau (stage + commit) anlegen, dann nach Reopen die
        // Sichtbarkeit prüfen (Reopen baut alle Derivate aus dem Log neu).
        let (c1_id, c2_id, marker_id);
        {
            let k = open_kernel(dir.path());
            let c1 = Datum::leaf(b"k13-a".to_vec());
            let c2 = Datum::leaf(b"k13-b".to_vec());
            c1_id = ContentId::of_datum(&c1);
            c2_id = ContentId::of_datum(&c2);
            let (cids, mid) = k
                .append_restructuring(&[c1, c2], &Datum::active_marker())
                .unwrap();
            assert_eq!(cids, vec![c1_id, c2_id]);
            marker_id = mid;

            // Vor dem Reopen: alle drei sichtbar (Marker committet).
            let snap = k.pin_snapshot().unwrap();
            let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
            assert!(k.get_by_content_id(c1_id, &cap, snap).unwrap().is_some());
            assert!(k.get_by_content_id(c2_id, &cap, snap).unwrap().is_some());
            assert!(k.get_by_content_id(marker_id, &cap, snap).unwrap().is_some());
        }

        // Reopen: Dedup-Karte, governing_marker und Index werden VOLLSTÄNDIG aus dem
        // Log rekonstruiert (§8.4). Die §13-Sichtbarkeit muss identisch sein.
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(
            k.get_by_content_id(c1_id, &cap, snap).unwrap().is_some(),
            "Konstituent nach Wipe-&-Rebuild sichtbar (Marker durabel, §13/§8.4)"
        );
        assert!(k.get_by_content_id(c2_id, &cap, snap).unwrap().is_some());
        assert!(k.get_by_content_id(marker_id, &cap, snap).unwrap().is_some());

        // Auch ein expliziter Index-Wipe + Neu-Bau ändert die Sichtbarkeit nicht.
        // (Die §13-Karte hängt am Record-Header, nicht am Kanten-Index — aber der
        // Neu-Bau muss konsistent bleiben.)
        let again = k.append(&Datum::leaf(b"k13-a".to_vec())).unwrap();
        assert_eq!(again, c1_id, "Dedup-Treffer: Konstituent aus dem Log rekonstruiert (§5.3)");
    }

    // ------------------------------------------------------------------------
    // §13: eine ATOMARE Anker-SPALTUNG (§9.4) gebaut auf Phase 4 — ein Repräsentant
    // wird per Ersetzungs-Kontext (§6.3) zu einem NEUEN Anker re-verwiesen. Alle
    // Konstituenten des Splits (neuer Anker, neue Mitgliedschaft, re-verwiesener
    // Repräsentant, Ersetzungs-Kontext) sind GEMEINSAM unsichtbar, bis der Marker
    // committet — danach atomar sichtbar. Der ALTE Anker/Repräsentant bleibt
    // unverändert (append-only §7.1).
    // ------------------------------------------------------------------------

    #[test]
    fn atomic_anchor_split_is_jointly_invisible_until_marker() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Vorbedingung (aktiv): alter Anker + Repräsentant + benötigte Marker-Atome.
        let class_old = k.append(&Datum::leaf(b"klasse-alt".to_vec())).unwrap();
        k.append(&Datum::anchor_marker()).unwrap();
        let anchor_old = k.append(&Datum::anchor([class_old])).unwrap();
        k.append(&Datum::membership_marker()).unwrap();
        k.append(&Datum::membership_grade_marker()).unwrap();
        let grade = k.append(&Datum::leaf(b"g".to_vec())).unwrap();
        k.append(&Datum::membership_grade(grade)).unwrap();
        let m_old = k.append(&Datum::membership(anchor_old, grade)).unwrap();
        let rep = k.append(&Datum::node([m_old]).unwrap()).unwrap();
        k.append(&Datum::supersession_marker()).unwrap();

        // Anfangs: der Repräsentant gehört dem ALTEN Anker an.
        let snap0 = k.pin_snapshot().unwrap();
        let cap0 = k.authorize(GrantedScopes::from_scope_ids([]), snap0).unwrap();
        assert_eq!(k.anchor_members_visible(anchor_old, &cap0, snap0).unwrap(), vec![rep]);

        // Der SPLIT als Mehr-Daten-Umbau (§9.4 + §6.3). Vorab alle ContentIds berechnen
        // (geschlossene Verweise: class_new ist ein neues Blatt-Konstituent).
        let class_new = Datum::leaf(b"klasse-neu".to_vec());
        let class_new_id = ContentId::of_datum(&class_new);
        let anchor_new = Datum::anchor([class_new_id]);
        let anchor_new_id = ContentId::of_datum(&anchor_new);
        let m_new = Datum::membership(anchor_new_id, grade);
        let m_new_id = ContentId::of_datum(&m_new);
        // Ersetzungs-Kontext: die NEUE Mitgliedschaft überholt die ALTE (§6.3).
        let sup = Datum::supersedes(m_old);
        let sup_id = ContentId::of_datum(&sup);
        // Re-verwiesener Repräsentant: besitzt die neue Mitgliedschaft UND den
        // Ersetzungs-Kontext (er überholt seine alte Mitgliedschaft, §9.4/§6.3).
        let rep_new = Datum::node([m_new_id, sup_id]).unwrap();
        let rep_new_id = ContentId::of_datum(&rep_new);

        let constituents = vec![class_new, anchor_new, m_new, sup, rep_new];
        let constituent_ids: Vec<ContentId> =
            vec![class_new_id, anchor_new_id, m_new_id, sup_id, rep_new_id];

        // --- stagen (INAKTIV): der ganze Split ist gemeinsam unsichtbar -------
        let handle = k.stage_restructuring(&constituents).unwrap();
        let snap_s = k.pin_snapshot().unwrap();
        let cap_s = k.authorize(GrantedScopes::from_scope_ids([]), snap_s).unwrap();
        // Kein Konstituent ist sichtbar.
        for id in &constituent_ids {
            assert!(
                k.get_by_content_id(*id, &cap_s, snap_s).unwrap().is_none(),
                "Split-Konstituent inaktiv ⇒ VANISH (§13.2)"
            );
        }
        // Der NEUE Anker hat noch keine sichtbaren Mitglieder.
        assert!(k.anchor_members_visible(anchor_new_id, &cap_s, snap_s).unwrap().is_empty());
        // Der ALTE Anker ist UNVERÄNDERT: sein ursprünglicher Repräsentant ist
        // weiterhin sichtbar (append-only §7.1; der Split mutiert nichts Bestehendes).
        // (Der Anker-Index kann zusätzlich strukturelle Erwähnungen über den
        // Ersetzungs-Kontext einschließen — eine Phase-4-Eigenschaft, von §13
        // unabhängig; entscheidend ist hier, dass `rep` unverändert erhalten bleibt.)
        assert!(
            k.anchor_members_visible(anchor_old, &cap_s, snap_s).unwrap().contains(&rep),
            "alter Repräsentant bleibt am alten Anker (append-only §7.1)"
        );

        // --- Marker committen: der ganze Split wird ATOMAR sichtbar ----------
        // Bloßes Marker-Atom (§13): der Konstituenten-Bereich liegt im Log-Header, das
        // Marker-Daten erzeugt keine semantischen Kanten.
        let marker = Datum::active_marker();
        k.commit_restructuring(handle, &marker).unwrap();
        let snap_d = k.pin_snapshot().unwrap();
        let cap_d = k.authorize(GrantedScopes::from_scope_ids([]), snap_d).unwrap();

        // Alle Konstituenten sind nun sichtbar (atomar gemeinsam, §13.1).
        for id in &constituent_ids {
            assert!(
                k.get_by_content_id(*id, &cap_d, snap_d).unwrap().is_some(),
                "Split atomar sichtbar nach Marker (§13.1)"
            );
        }
        // Der NEUE Anker hat jetzt den re-verwiesenen Repräsentanten als Mitglied.
        assert_eq!(
            k.anchor_members_visible(anchor_new_id, &cap_d, snap_d).unwrap(),
            vec![rep_new_id],
            "Repräsentant zum NEUEN Anker re-verwiesen (§9.4)"
        );
        // Der ALTE Anker (und der alte Repräsentant) bleiben unverändert bestehen
        // (append-only §7.1; der Split LÖSCHT nichts) — `rep` ist weiterhin Mitglied.
        assert!(
            k.anchor_members_visible(anchor_old, &cap_d, snap_d).unwrap().contains(&rep),
            "alter Repräsentant nach dem Split unverändert erhalten (append-only §7.1)"
        );
        // Die Ersetzungs-Relation ist beidseitig traversierbar (§6.3): die neue
        // Mitgliedschaft überholt die alte.
        assert_eq!(k.supersedes_visible(rep_new_id, &cap_d, snap_d).unwrap(), vec![m_old]);
        assert_eq!(k.superseded_by_visible(m_old, &cap_d, snap_d).unwrap(), vec![rep_new_id]);
    }

    // ------------------------------------------------------------------------
    // Phase 6: Materialisierung & Herkunft (§10). Der Kernel BERECHNET NICHTS —
    // die Schicht darüber reicht das fertige Ergebnis ein; der Kernel hält die
    // Herkunft als Kontext (§10.2), findet die Abhängigen rückwärts (§10.3) und
    // verknüpft ein neueres Ergebnis per Ersetzung (§6.3/§10.1).
    // ------------------------------------------------------------------------

    /// Sammelt die `to`-Knoten eines Step-Stroms (deterministisch geordnet).
    fn collect_to(stream: StepStream<'_>) -> Vec<ContentId> {
        stream.map(|s| s.expect("step").to).collect()
    }

    #[test]
    fn computed_result_records_origins_and_find_dependents_runs_backward() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Die schreibende Schicht reicht zwei Eingaben + das fertige Ergebnis ein.
        let in_a = k.append(&Datum::leaf(b"input-a".to_vec())).unwrap();
        let in_b = k.append(&Datum::leaf(b"input-b".to_vec())).unwrap();
        // Die Herkunfts-Kontexte MÜSSEN durabel sein, bevor das Ergebnis indiziert
        // wird (§3.6: Geschlossenheit erzwingt die schreibende Schicht).
        k.append(&Datum::origin_marker()).unwrap();
        k.append(&Datum::origin(in_a)).unwrap();
        k.append(&Datum::origin(in_b)).unwrap();
        let payload = k.append(&Datum::leaf(b"ergebnis".to_vec())).unwrap();
        let result = Datum::computed_result([payload], [in_a, in_b]).unwrap();
        // `materialize` ohne Ersetzung: nur anhängen (der Kernel berechnet nichts).
        let (result_id, link) = k.materialize(&result, None).unwrap();
        assert!(link.is_none(), "kein älteres Ergebnis ⇒ kein Verknüpfungs-Knoten");

        let snap = k.pin_snapshot().unwrap();

        // §10.2: das Ergebnis trägt strukturell BEIDE Eingaben (gegateter Vorwärts-Helfer).
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        let mut inputs = k.origin_inputs_visible(result_id, &cap, snap).unwrap();
        inputs.sort_unstable();
        let mut want = [in_a, in_b];
        want.sort_unstable();
        assert_eq!(inputs, want, "alle Herkunfts-Eingaben strukturell erfasst (§10.2)");

        // §10.3: find_dependents(input) läuft RÜCKWÄRTS zu den abhängigen Ergebnissen.
        let deps_a = collect_to(k.find_dependents(in_a, snap).unwrap());
        assert_eq!(deps_a, vec![result_id], "in_a → abhängiges Ergebnis (§10.3)");
        let deps_b = collect_to(k.find_dependents(in_b, snap).unwrap());
        assert_eq!(deps_b, vec![result_id], "in_b → abhängiges Ergebnis (§10.3)");
        // Ein Daten, das keine Eingabe ist, hat keine Abhängigen.
        assert!(collect_to(k.find_dependents(result_id, snap).unwrap()).is_empty());

        // traverse_provenance_backward(result) läuft zu den Eingaben (§10.2).
        let mut origins = collect_to(k.traverse_provenance_backward(result_id, 8, 100, snap).unwrap());
        origins.sort_unstable();
        assert_eq!(origins, want, "Provenance rückwärts: Ergebnis → Eingaben (§10.2)");

        // Die EINGABEN sind UNVERÄNDERT/immutabel (append-only §7.1): dieselbe ID,
        // dieselben Bytes — die Materialisierung mutiert nichts Bestehendes.
        let ca = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        let sealed_a = k.get_by_content_id(in_a, &ca, snap).unwrap().expect("in_a vorhanden");
        let opened = open(&sealed_a, &ca).expect("sichtbar");
        let decoded = strict_decode(opened.canonical_bytes()).unwrap();
        assert_eq!(decoded, Datum::leaf(b"input-a".to_vec()), "Eingabe unverändert (§7.1)");
        assert_eq!(ContentId::of_datum(&decoded), in_a, "Eingabe-ID stabil (§5.2)");
    }

    #[test]
    fn newer_materialized_result_supersedes_older_without_mutating_it() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let input = k.append(&Datum::leaf(b"quelle".to_vec())).unwrap();
        k.append(&Datum::origin_marker()).unwrap();
        k.append(&Datum::origin(input)).unwrap();
        k.append(&Datum::supersession_marker()).unwrap();

        // Erstes (älteres) berechnetes Ergebnis.
        let p_old = k.append(&Datum::leaf(b"ergebnis-v1".to_vec())).unwrap();
        let old_result = Datum::computed_result([p_old], [input]).unwrap();
        let (old_id, old_link) = k.materialize(&old_result, None).unwrap();
        assert!(old_link.is_none());

        // Neueres Ergebnis ERSETZT das ältere (§10.1/§6.3) — append-only.
        let p_new = k.append(&Datum::leaf(b"ergebnis-v2".to_vec())).unwrap();
        let new_result = Datum::computed_result([p_new], [input]).unwrap();
        let (new_id, new_link) = k.materialize(&new_result, Some(old_id)).unwrap();
        let link_id = new_link.expect("Verknüpfungs-Knoten verknüpft neu→alt (§6.3)");
        assert_ne!(new_id, old_id);

        let snap = k.pin_snapshot().unwrap();
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();

        // Die Ersetzung ist beidseitig traversierbar (§6.3): der Verknüpfungs-Knoten
        // (das Neuere besitzt den Ersetzungs-Kontext) überholt das ältere Ergebnis.
        assert_eq!(k.supersedes_visible(link_id, &cap, snap).unwrap(), vec![old_id]);
        assert_eq!(k.superseded_by_visible(old_id, &cap, snap).unwrap(), vec![link_id]);

        // Das ÄLTERE Ergebnis bleibt UNVERÄNDERT und über das Tor lesbar (§7.1) —
        // die Ersetzung LÖSCHT/MUTIERT es nicht.
        let sealed = k.get_by_content_id(old_id, &cap, snap).unwrap().expect("alt bleibt");
        let opened = open(&sealed, &cap).expect("sichtbar");
        let decoded = strict_decode(opened.canonical_bytes()).unwrap();
        assert_eq!(ContentId::of_datum(&decoded), old_id, "altes Ergebnis unverändert (§7.1)");

        // Beide Ergebnisse hängen weiterhin an derselben Eingabe (§10.2) — der Kernel
        // entscheidet NICHT, welches „aktuell" ist (§6.4/§8); beide sind Abhängige.
        let mut deps = collect_to(k.find_dependents(input, snap).unwrap());
        deps.sort_unstable();
        assert!(deps.contains(&old_id) && deps.contains(&new_id), "beide Ergebnisse abhängig (§10.3)");
    }

    #[test]
    fn provenance_is_cycle_safe_and_budget_bounded() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        k.append(&Datum::origin_marker()).unwrap();

        // Konstruiere einen ZYKLUS über Herkunfts-Kontexte: A entstand aus B, B aus A.
        // (Zyklen sind erlaubt §1.6; die mechanische Traversierung terminiert über die
        // Besuchsmenge §1.7 a.) Wir bauen zwei Daten, die einander als Eingabe nennen.
        let a_payload = ContentId::of_datum(&Datum::leaf(b"A".to_vec()));
        let b_payload = ContentId::of_datum(&Datum::leaf(b"B".to_vec()));
        // Vorab die IDs berechnen, um die wechselseitige Herkunft zu schließen.
        let a = Datum::computed_result([a_payload], [b_payload]).unwrap();
        let a_id = ContentId::of_datum(&a);
        let b = Datum::computed_result([b_payload], [a_id]).unwrap();
        let b_id = ContentId::of_datum(&b);
        // Schließe den Zyklus: A entsteht aus B (B existiert als Verweis-Ziel über die
        // schreibende Schicht; der Kernel validiert die Geschlossenheit nicht, §3.6).
        let a2 = Datum::computed_result([a_payload], [b_id]).unwrap();

        // Alle Herkunfts-Kontexte + Daten anhängen.
        k.append(&Datum::leaf(b"A".to_vec())).unwrap();
        k.append(&Datum::leaf(b"B".to_vec())).unwrap();
        k.append(&Datum::origin(b_payload)).unwrap();
        k.append(&b).unwrap();
        k.append(&Datum::origin(a_id)).unwrap();
        k.append(&Datum::origin(b_id)).unwrap();
        k.append(&a2).unwrap();
        let a2_id = ContentId::of_datum(&a2);

        let snap = k.pin_snapshot().unwrap();
        // Die Traversierung TERMINIERT trotz Zyklus (Besuchsmenge, §1.7 a).
        let steps = collect_to(k.traverse_provenance_backward(a2_id, u32::MAX, 1000, snap).unwrap());
        assert!(!steps.is_empty(), "Zyklus terminiert, liefert Schritte (§1.7 a)");

        // Budget: max_nodes = 0 ⇒ definierter Budget-Fehler, sobald ein Schritt
        // entstünde (kein unbeschränkter Speicher, §1.7 a).
        let r = k.traverse_provenance_backward(a2_id, u32::MAX, 0, snap);
        assert!(matches!(r, Err(KernelError::TraversalBudgetExceeded)));
    }

    #[test]
    fn non_visible_origin_input_vanishes() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Eine bereichs-beschränkte (geheime) Eingabe; das Ergebnis ist unbeschränkt.
        let area = k.append(&Datum::leaf(b"area".to_vec())).unwrap();
        let _am = k.append(&Datum::area_membership_marker()).unwrap();
        let membership = k.append(&Datum::area_membership(area)).unwrap();
        let secret_input = k.append(&Datum::node([membership]).unwrap()).unwrap();

        k.append(&Datum::origin_marker()).unwrap();
        k.append(&Datum::origin(secret_input)).unwrap();
        let payload = k.append(&Datum::leaf(b"erg".to_vec())).unwrap();
        let result = Datum::computed_result([payload], [secret_input]).unwrap();
        let (result_id, _) = k.materialize(&result, None).unwrap();

        let snap = k.pin_snapshot().unwrap();
        // Rechtloser Leser: die geheime Eingabe VANISHt aus der Herkunft (§11.3).
        let denied = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(
            k.origin_inputs_visible(result_id, &denied, snap).unwrap().is_empty(),
            "geheime Eingabe VANISHt (§11.3)"
        );
        // Auch die rückwärtige Provenance-Traversierung leakt sie nicht.
        assert!(collect_to(k.traverse_provenance_backward(result_id, 8, 100, snap).unwrap()).is_empty());

        // Mit gewährtem Bereich wird die Eingabe sichtbar.
        let granted = k.authorize(GrantedScopes::from_scope_ids([area]), snap).unwrap();
        assert_eq!(
            k.origin_inputs_visible(result_id, &granted, snap).unwrap(),
            vec![secret_input]
        );
    }

    #[test]
    fn origin_index_survives_reopen_and_wipe_and_rebuild() {
        let dir = tempdir().unwrap();
        let in_a;
        let result_id;
        {
            let k = open_kernel(dir.path());
            in_a = k.append(&Datum::leaf(b"in".to_vec())).unwrap();
            k.append(&Datum::origin_marker()).unwrap();
            k.append(&Datum::origin(in_a)).unwrap();
            let p = k.append(&Datum::leaf(b"out".to_vec())).unwrap();
            let result = Datum::computed_result([p], [in_a]).unwrap();
            result_id = k.materialize(&result, None).unwrap().0;

            let snap = k.pin_snapshot().unwrap();
            assert_eq!(collect_to(k.find_dependents(in_a, snap).unwrap()), vec![result_id]);
        }
        // Reopen: der Herkunfts-Index ist ein reines, neu-baubares Derivat (§8.4) —
        // beim Öffnen aus dem Log rekonstruiert.
        {
            let k = open_kernel(dir.path());
            let snap = k.pin_snapshot().unwrap();
            assert_eq!(collect_to(k.find_dependents(in_a, snap).unwrap()), vec![result_id],
                "Herkunfts-Index nach Reopen identisch (§8.4)");

            // Wipe & rebuild: explizit den Index verwerfen und aus dem Log neu bauen.
            {
                let mut store = k.store.write().unwrap();
                store.rebuild_index_from_log().unwrap();
            }
            let snap2 = k.pin_snapshot().unwrap();
            assert_eq!(collect_to(k.find_dependents(in_a, snap2).unwrap()), vec![result_id],
                "Wipe-&-Rebuild rekonstruiert den Herkunfts-Index identisch (§8.4)");
            let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap2).unwrap();
            let mut origins = collect_to(k.traverse_provenance_backward(result_id, 8, 100, snap2).unwrap());
            origins.sort_unstable();
            assert_eq!(origins, vec![in_a]);
            let _ = cap;
        }
    }

    // ------------------------------------------------------------------------
    // Phase 6 / HARTE GRENZE (§1.5/§10.3): der Kernel FINDET die Abhängigen, aber
    // er BERECHNET NIE NEU und MARKIERT NIE selbst als stale/invalide. Dieser Test
    // friert die Negativ-Garantie ein:
    //   - `find_dependents` ist ein reiner LESE-Pfad (`&self`, liefert einen
    //     Step-Strom) — er mutiert NICHTS (kein neuer Record, kein Ersetzungs-
    //     Kontext, keine §13-Epoche entsteht durch das bloße Finden);
    //   - es existiert KEIN Verb der Gestalt `recompute(input)` /
    //     `invalidate(input)` / `mark_stale(result)` auf dem Kernel — die einzige
    //     Antwort des Kernels auf eine geänderte Eingabe ist das FINDEN der
    //     Abhängigen; das Neu-Berechnen ist ein WEITERER Append der Schicht darüber
    //     (§1.5/§7.1), den der Test hier exemplarisch selbst vollzieht.
    // ------------------------------------------------------------------------

    #[test]
    fn find_dependents_only_finds_and_never_recomputes_or_marks_stale() {
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Eine Eingabe + ein berechnetes Ergebnis (die Schicht darüber reicht es ein).
        let input = k.append(&Datum::leaf(b"eingabe".to_vec())).unwrap();
        k.append(&Datum::origin_marker()).unwrap();
        k.append(&Datum::origin(input)).unwrap();
        let payload = k.append(&Datum::leaf(b"erg".to_vec())).unwrap();
        let result = Datum::computed_result([payload], [input]).unwrap();
        let (result_id, _) = k.materialize(&result, None).unwrap();

        // Vollständige Mechanik-Zähler VOR dem Finden festhalten (append_count,
        // committed_bytes, edge_count): das bloße FINDEN darf KEINEN davon bewegen.
        let before = k.stats().unwrap();

        // §10.3: die Eingabe „ändert sich" — der Kernel FINDET die Abhängigen. Wir
        // rufen den Lese-Pfad MEHRFACH auf; er ist idempotent und mutationsfrei.
        let snap = k.pin_snapshot().unwrap();
        for _ in 0..3 {
            let deps = collect_to(k.find_dependents(input, snap).unwrap());
            assert_eq!(deps, vec![result_id], "find_dependents FINDET nur (§10.3)");
        }
        // Auch die transitive Rückwärts-Traversierung ist reines Lesen.
        let _ = collect_to(k.traverse_provenance_backward(result_id, 8, 100, snap).unwrap());

        // KEINE Mutation durch das Finden (§1.5/§7.1): die Mechanik-Zähler sind
        // unverändert — kein neuer Record, keine neue Kante, keine neuen Log-Bytes.
        let after = k.stats().unwrap();
        assert_eq!(after.append_count, before.append_count, "kein neuer Record durch Finden");
        assert_eq!(after.committed_bytes, before.committed_bytes, "keine neuen Log-Bytes");
        assert_eq!(after.edge_count, before.edge_count, "keine neue Kante");

        // Das abhängige Ergebnis ist NICHT als stale markiert worden: der Kernel hat
        // KEINEN Ersetzungs-Kontext angehängt (§6.3) — `superseded_by(result)` ist
        // leer. Hätte der Kernel auto-invalidiert, läge hier eine Ersetzung.
        let cap = k.authorize(GrantedScopes::from_scope_ids([]), snap).unwrap();
        assert!(
            k.superseded_by_visible(result_id, &cap, snap).unwrap().is_empty(),
            "der Kernel markiert NICHTS selbst als stale (kein Auto-Invalidate, §1.5)"
        );

        // Das Neu-Berechnen liegt AUSSERHALB (§1.5): die Schicht darüber reagiert auf
        // den gefundenen Abhängigen mit einem WEITEREN Append/Ersetzung — NICHT der
        // Kernel. Hier exemplarisch: ein neues Ergebnis ersetzt das alte (§10.1/§6.3).
        let p2 = k.append(&Datum::leaf(b"erg-v2".to_vec())).unwrap();
        k.append(&Datum::supersession_marker()).unwrap();
        let result2 = Datum::computed_result([p2], [input]).unwrap();
        let (_r2, link) = k.materialize(&result2, Some(result_id)).unwrap();
        let link_id = link.expect("die SCHICHT DARÜBER ersetzt — per Append (§7.1)");
        // Erst JETZT — durch den Append der Schicht darüber, NICHT durch den Kernel —
        // ist das alte Ergebnis ersetzt; und das alte bleibt append-only erhalten (§7.1).
        let snap2 = k.pin_snapshot().unwrap();
        let cap2 = k.authorize(GrantedScopes::from_scope_ids([]), snap2).unwrap();
        assert_eq!(k.superseded_by_visible(result_id, &cap2, snap2).unwrap(), vec![link_id]);
        assert!(
            k.get_by_content_id(result_id, &cap2, snap2).unwrap().is_some(),
            "altes Ergebnis bleibt durabel erhalten (append-only §7.1)"
        );
    }

    // ------------------------------------------------------------------------
    // Erasure & Compaction (§15/§9.5) — gegatet, auditiert, crypto-geshreddet,
    // refcount-geschützt, live-Reader-sicher, Index rekonstruiert.
    // ------------------------------------------------------------------------

    #[test]
    fn erase_is_denied_without_the_erasure_right() {
        // §15/§11: ohne das spezifische Erasure-Recht geschieht NICHTS (fail-closed),
        // und es wird KEIN Audit-Daten angehängt.
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let target = k.append(&Datum::leaf(b"sensibel".to_vec())).unwrap();
        let before = k.content_set().unwrap().len();

        // Ein gewöhnliches Daten ist KEIN Erasure-Recht.
        let not_a_right = Datum::leaf(b"ich-bin-kein-recht".to_vec());
        let key = ErasureKey::from_bytes([0x01; 32]);
        let denied = k.erase(target, &not_a_right, key);
        assert!(matches!(denied, Err(KernelError::ErasureDenied)), "ohne Recht ⇒ verweigert");
        // Kein Audit angehängt (der Bestand ist unverändert).
        assert_eq!(k.content_set().unwrap().len(), before, "nichts angehängt ohne Recht");
    }

    #[test]
    fn erase_with_right_writes_an_audit_datum() {
        // §15/§7.1: mit dem Erasure-Recht hängt die Op ihr eigenes Audit-Daten an
        // (append-only) — der unveränderliche Beleg bleibt im Log (§3.6).
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let target = k.append(&Datum::leaf(b"vergiss-mich".to_vec())).unwrap();

        let right = Datum::erasure_right();
        let key = ErasureKey::from_bytes([0x02; 32]);
        let audit_id = k.erase(target, &right, key).expect("mit Recht erlaubt");

        // Das Audit-Daten ist im Bestand und zeigt strukturell auf das eraste Daten.
        let (cap, snap) = cap_and_snap(&k);
        let sealed = k.get_by_content_id(audit_id, &cap, snap).unwrap().expect("Audit vorhanden");
        let audit = strict_decode(open(&sealed, &cap).unwrap().canonical_bytes()).unwrap();
        assert_eq!(audit.erasure_audit_target(), Some(target), "Audit belegt das eraste Daten");
    }

    #[test]
    fn compact_crypto_shreds_erased_datum_keeping_refs_closed_and_others_alive() {
        // §15/§Crypto-Shred/§3.6/§5.3: erase + compact ⇒ die erasten Bytes sind nach
        // Zerstören des Schlüssels unrückholbar; ContentId/Kanten bleiben (Tombstone);
        // eine andere Dedup-Referenz überlebt (Refcount); der Index ist konsistent.
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        // Graph: zwei Blätter `a` (überlebt), `secret` (erast); ein Knoten `n` besitzt
        // beide (referenziert `secret` weiter ⇒ Kante bleibt §3.6).
        let a = k.append(&Datum::leaf(b"oeffentlich".to_vec())).unwrap();
        let secret = k.append(&Datum::leaf(b"streng-geheim".to_vec())).unwrap();
        let n = k.append(&Datum::node([a, secret]).unwrap()).unwrap();

        // Erasure (gegatet + auditiert).
        let key = ErasureKey::from_bytes([0x42; 32]);
        let audit_id = k.erase(secret, &Datum::erasure_right(), key).unwrap();

        // Compaction: die nächste Generation versiegelt `secret`.
        let (seg, mut ks, report) = k.compact().unwrap();
        assert_eq!(report.sealed, 1, "genau das eraste Daten versiegelt");
        assert!(seg.is_sealed(secret));
        // Live-Reader-sicher: das laufende Append-Log bleibt unangetastet lesbar.
        let (cap, snap) = cap_and_snap(&k);
        assert!(k.get_by_content_id(secret, &cap, snap).unwrap().is_some(),
            "altes Log (das ein Leser hält) wird NICHT unmappt (§15)");

        // Mit dem lebenden Schlüssel sind die Bytes in der Generation noch lesbar.
        assert_eq!(seg.datum(secret, &ks).unwrap(), Some(Datum::leaf(b"streng-geheim".to_vec())));

        // Schlüssel ZERSTÖREN ⇒ die Bytes sind unrückholbar (das „Recht auf Vergessen").
        assert!(ks.destroy(secret));
        assert_eq!(seg.canonical_bytes(secret, &ks).unwrap(), None, "Bytes geschreddert");
        // ABER: die ContentId bleibt als Adresse erreichbar (§3.6 — Verweis geschlossen).
        assert!(seg.contains(secret), "Tombstone: ContentId/Kante bleibt (§3.6)");
        // Eine andere Referenz (`a`) überlebt unverändert (Refcount §5.3).
        assert_eq!(seg.datum(a, &ks).unwrap(), Some(Datum::leaf(b"oeffentlich".to_vec())));
        // Der besitzende Knoten `n` referenziert `secret` strukturell weiter (Kante intakt).
        assert_eq!(seg.datum(n, &ks).unwrap(), Some(Datum::node([a, secret]).unwrap()));
        // Das Audit-Daten ist ebenfalls in der Generation (Beleg bleibt, §15).
        assert!(seg.contains(audit_id), "Audit überlebt die Compaction (§15)");
    }

    #[test]
    fn compact_with_explicit_drop_removes_orphaned_record_and_reconstructs_consistent_index() {
        // §15: die Schicht darüber (die §6.4/§8 die „gültige Version" entscheidet,
        // NICHT der Kernel) übergibt einen closure-konsistenten Fallenlass-Satz; ein
        // verwaistes (von nichts Behaltenem referenziertes) Daten wird physisch
        // entfernt. Die Generation hält jedes behaltene Daten über seine stabile
        // logische ID (ContentId) — ein erneutes Lesen ist konsistent (Index rekonstruiert).
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());

        let keep = k.append(&Datum::leaf(b"behalten".to_vec())).unwrap();
        // Ein eigenständiges, von NICHTS referenziertes Daten (z. B. eine alte,
        // ersetzte Version, deren Ersetzungs-Kette die Schicht darüber mit-entfernt).
        let orphan = k.append(&Datum::leaf(b"verwaiste-version".to_vec())).unwrap();

        let mut drop = HashSet::new();
        drop.insert(orphan);
        let (seg, ks, report) = k.compact_with_drop(drop).unwrap();
        assert!(report.dropped >= 1, "das verwaiste Daten fällt physisch weg (§15)");
        assert!(!seg.contains(orphan), "verwaistes Daten physisch entfernt (§15)");
        // Content-Adressierung des behaltenen Daten intakt + reproduzierbar.
        assert_eq!(seg.datum(keep, &ks).unwrap(), Some(Datum::leaf(b"behalten".to_vec())));

        // Index rekonstruiert: ein erneutes Lesen aus der Generation auf Platte liefert
        // dieselbe Sicht (deterministische Adress-Order, §5.2/§1.4).
        let gdir = crate::compaction::generation_dir(dir.path(), report.generation);
        let seg2 = CompactedSegment::read_from(&gdir).unwrap();
        assert_eq!(seg2.ids(), seg.ids(), "Generation deterministisch reproduzierbar");
        assert!(!seg2.contains(orphan));
    }

    #[test]
    fn compact_drop_is_closure_preserving_keeps_still_referenced_candidate() {
        // §3.6/§5.3: selbst wenn die Schicht darüber ein noch REFERENZIERTES Daten zum
        // Fallenlassen vorschlägt, behält der Closure-Fixpunkt es — kein behaltenes
        // Daten darf je auf ein entferntes verweisen (§3.6), und eine rechtmäßig
        // gehaltene Dedup-Referenz bewahrt ihr Daten (§5.3).
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let shared = k.append(&Datum::leaf(b"geteilt".to_vec())).unwrap();
        // Ein behaltener Knoten referenziert `shared` ⇒ Drop-Vorschlag wird ignoriert.
        let _owner = k.append(&Datum::node([shared]).unwrap()).unwrap();

        let mut drop = HashSet::new();
        drop.insert(shared);
        let (seg, ks, _report) = k.compact_with_drop(drop).unwrap();
        assert!(seg.contains(shared), "referenziertes Daten bleibt (Closure/Refcount §3.6/§5.3)");
        assert_eq!(seg.datum(shared, &ks).unwrap(), Some(Datum::leaf(b"geteilt".to_vec())));
    }

    #[test]
    fn compaction_refcount_protects_still_referenced_hidden_datum() {
        // §5.3-Refcount-Sicherheit: ein kuratorisch verborgenes Daten, das von einem
        // BEHALTENEN Daten (hier seinem Verbergen-Kontext) noch referenziert wird, wird
        // NICHT physisch fallengelassen — die Löschung/Verbergung einer Referenz
        // zerstört nicht die Daten, die eine andere Referenz rechtmäßig hält (§3.6).
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let hidden = k.append(&Datum::leaf(b"verborgen".to_vec())).unwrap();
        k.append(&Datum::curation_hide_marker()).unwrap();
        // Der Verbergen-Kontext besitzt `hidden` ⇒ Refcount(hidden) ≥ 1 ⇒ geschützt.
        k.append(&Datum::curation_hide(hidden)).unwrap();

        let (seg, ks, _report) = k.compact().unwrap();
        assert!(seg.contains(hidden), "referenziertes Daten bleibt (Refcount-Schutz §5.3)");
        assert_eq!(seg.datum(hidden, &ks).unwrap(), Some(Datum::leaf(b"verborgen".to_vec())));
    }

    #[test]
    fn compact_without_base_dir_is_inconsistent() {
        // from_store (ohne Pfad) ⇒ kein Ort für die Generation ⇒ Inconsistent.
        let dir = tempdir().unwrap();
        let log_dir = dir.path().join("log");
        std::fs::create_dir_all(&log_dir).unwrap();
        let log = SegmentLog::open(&log_dir).unwrap();
        let index = RedbEdgeIndex::open(dir.path().join("index.redb")).unwrap();
        let store = ContentStore::open(log, index).unwrap();
        let k = LakearchKernel::from_store(store);
        assert!(matches!(k.compact(), Err(KernelError::Inconsistent)));
    }
}
