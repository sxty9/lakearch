//! Die **mechanische Traversierung** (§1.2/§1.7 a) — deterministisch, beschränkt
//! über eine Besuchsmenge und damit **zyklensicher** (§1.6).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§1.2 Vor-/Rückwärts-
//! Traversierung; §1.6 Zyklen erlaubt; §1.7 a mechanische Traversierung;
//! §3.2 gerichteter Besitz; §10.3 Rückwärts-Traversierung; §11.3 Filter-vor-
//! Auflösen / VANISH) und der gehärtete Plan (Abschnitte „Kernel-API-Vertrag",
//! „Beschränkte Traversierung & Backpressure").
//!
//! ## Was diese Traversierung ist — und ausschließlich ist
//!
//! Sie **matcht nur** (§1.3); sie rechnet und wertet **nicht** (§1.4). Konkret:
//!
//! - **Richtung (§3.2):** `Forward` folgt `owner → contexts`
//!   ([`EdgeIndex::contexts_of`]); `Backward` folgt `target → referrers`
//!   ([`EdgeIndex::referrers_of`], die Rückwärts-Traversierung der Invalidierung,
//!   §10.3); `Both` die Vereinigung beider.
//! - **Beschränkt (§1.7 a):** ein server-seitiges **Visited-Set** (zyklensicher,
//!   §1.6), ein **Tiefen-Budget** `max_depth` (Schritte tieferer Ebene werden
//!   nicht erzeugt) und ein **Knoten-Budget** `max_nodes` (würde die Besuchsmenge
//!   es überschreiten, endet der Strom mit [`KernelError::TraversalBudgetExceeded`]
//!   — nie unbeschränkter Speicher). Ein **Cancel-Flag** wird kooperativ je
//!   Schritt geprüft (Client-Disconnect/Deadline am async-Rand bricht eine
//!   laufende sync-Traversierung ab → [`KernelError::Cancelled`]).
//! - **Deterministische Emission (§5.2/§1.4):** Schritte werden in **aufsteigender
//!   `ContentId`-Byte-Order** emittiert — erst nach `to`, dann nach `edge_ctx` als
//!   Tiebreak. Das ist eine **Adress**-Ordnung (föderationsstabil; §5.2
//!   „adressiert, urteilt nicht"), **kein** Wert-Sort (§1.4): sie ordnet die
//!   opaken Hash-Adressen, nicht die Inhalte.
//! - **`edge_type_filter` (§3.3):** ein optionales Set von `ContentId`s, gegen das
//!   **strukturell** die Kanten-/Relations-`ContentId` (`edge_ctx`, das besessene
//!   Kontext-Daten) gematcht wird — eine Kante bleibt nur, wenn ihr `edge_ctx` im
//!   Set liegt. Reines Adress-Matching (§1.3), **nie** Wert-Matching (§1.4).
//!
//! ## Das Tor (§11.3) — Filter-vor-Auflösen / VANISH
//!
//! Die Traversierung läuft **durch das Tor** (§11.2/§11.5): bevor ein Nachbar-
//! Knoten als [`Step`] **oberflächlich** sichtbar wird oder die Front in ihn
//! hinein weiterläuft, prüft die Phase-A-Front seine **Sichtbarkeit** (Bereiche
//! des Daten ∩ gewährte Bereiche, `gate::is_visible`). Ein nicht-
//! sichtbarer Nachbar ist ein **interner Front-Stopp** (§11.3): er wird **nicht**
//! als Knoten emittiert und **nicht** betreten — und er **verändert die
//! Ergebnisform nicht** (VANISH: keine Nachbarzahl, keine Tiefe, keine
//! Mengengröße variiert mit verborgenen Knoten). Das mutiert **keine**
//! gespeicherten Kanten (§3.6 bleibt gewahrt); VANISH betrifft allein die
//! Lesesicht.
//!
//! **Fail-closed (§11):** schlägt ein Index-/Log-Zugriff fehl, endet der Strom mit
//! einem definierten [`KernelError`] (DENY), **nie** mit einem stillen
//! Teilergebnis, das Unsichtbares durchsickern ließe.
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]` (mechanische Traversierung muss
//! beweisbar sicheres Rust sein).

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::api::{Direction, Step};
use crate::error::KernelError;
use crate::gate::Capability;
use crate::id::ContentId;
use crate::index::EdgeIndex;
use crate::store::ContentStore;

/// Kooperatives **Abbruch-Flag** der Traversierung (§„Beschränkte Traversierung &
/// Backpressure"). Der Aufrufer (am async-Rand) setzt es bei Client-Disconnect
/// oder Deadline; die laufende sync-Traversierung prüft es **je Schritt** und
/// endet dann mit [`KernelError::Cancelled`].
///
/// Ein geklonter Handle teilt dasselbe Flag (`Arc`). Standardmäßig nicht gesetzt
/// ([`CancelFlag::new`]); [`CancelFlag::cancel`] setzt es.
#[derive(Clone, Debug, Default)]
pub struct CancelFlag {
    flag: Arc<AtomicBool>,
}

impl CancelFlag {
    /// Ein frisches, **nicht** gesetztes Abbruch-Flag.
    pub fn new() -> Self {
        CancelFlag {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Setzt den Abbruch (idempotent). Jeder geteilte Handle sieht ihn.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    /// `true`, wenn der Abbruch gesetzt ist.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// Die **Parameter** einer beschränkten Traversierung (§1.7 a) — owned, damit der
/// Strom unabhängig vom Aufrufer-Lebenszyklus läuft.
#[derive(Clone, Debug)]
pub struct TraversalParams {
    /// Start-Daten (Tiefe 0).
    pub start: ContentId,
    /// Richtung entlang der Besitz-/Kontext-Kanten (§1.2/§3.2).
    pub dir: Direction,
    /// **Tiefen-Budget** (§1.7 a): Schritte mit `depth > max_depth` werden **nicht**
    /// erzeugt. `max_depth = 0` ⇒ nur der Start, keine Schritte.
    pub max_depth: u32,
    /// **Knoten-Budget** (§1.7 a): obere Schranke der Besuchsmenge. Würde sie
    /// überschritten, endet der Strom mit [`KernelError::TraversalBudgetExceeded`]
    /// (nie unbeschränkter Speicher).
    pub max_nodes: u64,
    /// Optionaler **Kanten-Typ-Filter** (§3.3): strukturelles `ContentId`-Matching
    /// auf `edge_ctx` (das besessene Relations-/Kontext-Daten). `None` ⇒ kein
    /// Filter. **Invariante:** aufsteigend sortiert + dedupliziert (für die
    /// `binary_search`-Mitgliedschafts-Prüfung in [`run_traversal`] **erforderlich**;
    /// ein unsortierter Filter ergäbe unspezifizierte — über-/unter-inklusive —
    /// Treffer und bräche damit das strukturelle Matching §1.3 **und** den
    /// Determinismus §1.7 a). Die Invariante wird durch [`TraversalParams::new`]
    /// **und** defensiv in [`run_traversal`] hergestellt; das Feld bleibt `pub`, weil
    /// es die Phase-2-Form ist, doch der maßgebliche Konstruktor ist
    /// [`TraversalParams::new`].
    pub edge_type_filter: Option<Vec<ContentId>>,
}

impl TraversalParams {
    /// Baut **invariant-sichere** Traversierungs-Parameter: der `edge_type_filter`
    /// wird **aufsteigend sortiert + dedupliziert** (die Invariante, die
    /// [`run_traversal`] für sein `binary_search`-Mitgliedschafts-Matching
    /// voraussetzt). So kann ein Aufrufer keinen unsortierten/doppelten Filter
    /// einschleusen, der das strukturelle Matching (§1.3) oder den Determinismus
    /// (§1.7 a) bräche — die Reihenfolge des übergebenen Filters ist
    /// **ergebnis-irrelevant** (föderationsstabile Adress-Order, §5.2/§1.4).
    pub fn new(
        start: ContentId,
        dir: Direction,
        max_depth: u32,
        max_nodes: u64,
        edge_type_filter: Option<Vec<ContentId>>,
    ) -> Self {
        let edge_type_filter = edge_type_filter.map(|mut f| {
            f.sort_unstable();
            f.dedup();
            f
        });
        TraversalParams {
            start,
            dir,
            max_depth,
            max_nodes,
            edge_type_filter,
        }
    }
}

/// Führt die **mechanische Traversierung** (§1.7 a) eager, aber **beschränkt** aus
/// und liefert die emittierten Schritte als owned `Vec` (durch `max_nodes`
/// speicher-beschränkt). Der [`crate::api::StepStream`] iteriert anschließend
/// über dieses `Vec`.
///
/// Die Traversierung läuft **durch das Tor** (§11.3): `capability` bestimmt die
/// gewährten Bereiche; nicht-sichtbare Nachbarn sind interne Front-Stopps (VANISH)
/// und beeinflussen die Ergebnisform **nicht**.
///
/// Determinismus: BFS Ebene für Ebene; je expandiertem Knoten werden die Kanten in
/// aufsteigender `(to, edge_ctx)`-Adress-Order emittiert (§5.2/§1.4 — kein
/// Wert-Sort). Über die Ebenen hinweg ist die Reihenfolge damit stabil und
/// föderations­stabil.
///
/// **Snapshot (Phase 2).** Der Snapshot ist am Start gepinnt; in Phase 1/2 ist die
/// Wahrheit alles bis zum committeten Watermark `W`. Der Token wird vom Aufrufer
/// gepinnt und hier nicht erneut aufgelöst (volle §13-Epochen-Semantik: Phase 5).
pub(crate) fn run_traversal<I: EdgeIndex>(
    store: &ContentStore<I>,
    capability: &Capability,
    params: &TraversalParams,
    cancel: &CancelFlag,
) -> Vec<Result<Step, KernelError>> {
    let mut out: Vec<Result<Step, KernelError>> = Vec::new();

    // **Defensive Filter-Normalisierung (§1.3/§1.7 a).** Die `binary_search`-
    // Mitgliedschafts-Prüfung unten ist **nur** auf einem aufsteigend sortierten,
    // duplikat-freien Slice korrekt. Ein unsortierter Filter (legaler Wert des
    // `pub`-Feldes; der frozen-Form-Einstieg `Kernel::traverse` und der Konstruktor
    // `TraversalParams::new` normalisieren ihn, doch ein direkt befülltes
    // `TraversalParams` könnte ihn unsortiert tragen) ergäbe sonst unspezifizierte
    // Treffer (über-/unter-inklusiv) und bräche das strukturelle Matching **und** den
    // Determinismus. Wir stellen die Invariante hier **unbrechbar** her: ist der
    // Filter bereits sortiert+dedupliziert, borgen wir ihn (kein Klon); sonst bauen
    // wir eine normalisierte Kopie. Die Reihenfolge des übergebenen Filters ist damit
    // ergebnis-irrelevant (föderationsstabile Adress-Order, §5.2/§1.4).
    let normalized_filter: Option<Vec<ContentId>> = params
        .edge_type_filter
        .as_ref()
        .filter(|f| !is_sorted_deduped(f))
        .map(|f| {
            let mut v = f.clone();
            v.sort_unstable();
            v.dedup();
            v
        });
    let filter: Option<&[ContentId]> = match (&normalized_filter, &params.edge_type_filter) {
        (Some(norm), _) => Some(norm.as_slice()),
        (None, Some(orig)) => Some(orig.as_slice()),
        (None, None) => None,
    };
    debug_assert!(
        filter.is_none_or(is_sorted_deduped),
        "edge_type_filter muss aufsteigend sortiert + dedupliziert sein (§1.3/§1.7 a)"
    );

    // Der Start ist selbst nicht sichtbar? Dann ist die ganze Front leer (VANISH):
    // ein nicht-sichtbarer Start ist ununterscheidbar von „existiert nicht". Keine
    // Schritte, kein Fehler — die Ergebnisform verrät nichts (§11.3).
    let granted = capability.scopes().scope_ids();
    match is_visible_node(store, params.start, granted) {
        Ok(true) => {}
        Ok(false) => return out, // VANISH: leere, nicht-unterscheidbare Sicht.
        Err(e) => {
            // Fail-closed (§11): bei Inkonsistenz DENY (definierter Fehler) + Metrik.
            store.note_fail_closed();
            out.push(Err(e));
            return out;
        }
    }

    // Visited-Set über **sichtbaren** Knoten (zyklensicher, §1.6). Der Start zählt
    // als erster besuchter Knoten gegen das Knoten-Budget.
    let mut visited: HashSet<ContentId> = HashSet::new();
    visited.insert(params.start);

    // **Schritt-/Kanten-Budget (§1.7 a — nie unbeschränkter Speicher).** Das
    // `max_nodes`-Budget bremst die **Besuchsmenge** (distinkte Knoten); ein
    // **einzelner** Knoten sehr hohen Ausgangsgrades (ein Owner mit N Kontexten)
    // könnte aber O(N) `Step`s in `level_steps`/`out` materialisieren, BEVOR der
    // knoten-basierte Budget-Check zünden kann — das bräche die „nie unbeschränkter
    // Speicher"-Zusage. Daher zählen wir **jede zugelassene** (gefilterte +
    // sichtbare) Kante gegen ein aus `max_nodes` abgeleitetes Schritt-Budget und
    // brechen mit [`KernelError::TraversalBudgetExceeded`] ab, sobald die gepufferten
    // Schritte es überschritten. So bleibt der Speicher O(`max_nodes`) — auch unter
    // adversariellem Fan-out. (`max_nodes == 0` ⇒ kein Schritt; ein konsistenter
    // Sonderfall, der ohnehin nicht in die Schleife eintritt, da der Start bereits
    // ein Knoten ist.)
    let step_budget: u64 = params.max_nodes;
    let mut admitted_steps: u64 = 0;

    // BFS-Front: Knoten der aktuellen Ebene. `depth` ist die Tiefe DIESER Front.
    let mut frontier: Vec<ContentId> = vec![params.start];
    let mut depth: u32 = 0;

    while depth < params.max_depth && !frontier.is_empty() {
        // Kooperativer Abbruch je Ebene **und** je Knoten (s. u.).
        if cancel.is_cancelled() {
            out.push(Err(KernelError::Cancelled));
            return out;
        }

        // Sammle die Schritte dieser Ebene; sortiere sie deterministisch, bevor wir
        // sie emittieren und die nächste Front aufbauen.
        let mut level_steps: Vec<Step> = Vec::new();
        // Die nächste Front: distinkte, neu besuchte, **sichtbare** Ziele.
        let mut next_frontier: Vec<ContentId> = Vec::new();
        let mut next_seen: HashSet<ContentId> = HashSet::new();

        for &from in &frontier {
            if cancel.is_cancelled() {
                out.push(Err(KernelError::Cancelled));
                return out;
            }
            let neighbors = match neighbors_of(store, from, params.dir) {
                Ok(n) => n,
                Err(e) => {
                    // Fail-closed (§11): DENY statt stillem Teilergebnis + Metrik.
                    store.note_fail_closed();
                    out.push(Err(e));
                    return out;
                }
            };
            for (edge_ctx, to) in neighbors {
                // Kooperativer Abbruch **innerhalb** der Nachbar-Expansion eines
                // Knotens (§„Beschränkte Traversierung"): bei sehr hohem Ausgangsgrad
                // (ein Owner mit N Kontexten) muss eine laufende Expansion abbrechbar
                // sein, nicht erst nach dem ganzen Knoten.
                if cancel.is_cancelled() {
                    out.push(Err(KernelError::Cancelled));
                    return out;
                }
                // Kanten-Typ-Filter (§3.3): strukturelles ContentId-Matching auf die
                // Relations-/Kontext-ID. Reines Adress-Matching (§1.3). `filter` ist
                // garantiert sortiert+dedupliziert (s. o.) ⇒ `binary_search` korrekt.
                if let Some(f) = filter {
                    if f.binary_search(&edge_ctx).is_err() {
                        continue;
                    }
                }
                // §11.3 Filter-vor-Auflösen / VANISH: ein nicht-sichtbares Ziel ist
                // ein interner Front-Stopp — weder Step noch Betreten, und es
                // verändert die Ergebnisform nicht.
                match is_visible_node(store, to, granted) {
                    Ok(true) => {}
                    Ok(false) => continue, // VANISH.
                    Err(e) => {
                        // Fail-closed (§11): DENY + Metrik.
                        store.note_fail_closed();
                        out.push(Err(e));
                        return out;
                    }
                }
                // **Schritt-Budget VOR dem Puffern** (§1.7 a): eine weitere zugelassene
                // Kante würde das aus `max_nodes` abgeleitete Schritt-Budget sprengen
                // ⇒ definierter Abbruch, BEVOR der `Step` `level_steps`/`out`
                // materialisiert (so wächst der Speicher nie über O(`max_nodes`),
                // selbst bei adversariellem Fan-out eines einzelnen Knotens).
                if admitted_steps >= step_budget {
                    out.push(Err(KernelError::TraversalBudgetExceeded));
                    return out;
                }
                admitted_steps += 1;
                level_steps.push(Step {
                    from,
                    edge_ctx,
                    to,
                    depth: depth + 1,
                });
            }
        }

        // Deterministische Emission (§5.2/§1.4): aufsteigende Adress-Order, erst
        // nach `to`, dann `edge_ctx`, dann `from` (alle Komponenten als
        // Tiebreak → eine totale, föderationsstabile Ordnung; kein Wert-Sort).
        level_steps.sort_unstable_by(|a, b| {
            (a.to, a.edge_ctx, a.from).cmp(&(b.to, b.edge_ctx, b.from))
        });

        for step in level_steps {
            // Neue, noch nicht besuchte Ziele bilden die nächste Front. Das
            // Knoten-Budget bremst das Wachstum der Besuchsmenge (§1.7 a).
            if !visited.contains(&step.to) && next_seen.insert(step.to) {
                // Würde dieser neue Knoten das Budget überschreiten? Dann definierter
                // Abbruch statt unbeschränkter Speicher (§1.7 a). Wir haben den Step
                // noch nicht emittiert; wir geben den Budget-Fehler und stoppen.
                let prospective = visited.len() as u64 + next_frontier.len() as u64 + 1;
                if prospective > params.max_nodes {
                    out.push(Err(KernelError::TraversalBudgetExceeded));
                    return out;
                }
                next_frontier.push(step.to);
            }
            out.push(Ok(step));
        }

        // Die neu entdeckten Knoten in die Besuchsmenge übernehmen.
        for n in &next_frontier {
            visited.insert(*n);
        }
        frontier = next_frontier;
        depth += 1;
    }

    out
}

/// Die **Nachbarn** eines Knotens in der gewünschten Richtung (§3.2), als Paare
/// `(edge_ctx, to)`:
///
/// - `Forward`: `owner → contexts` ⇒ `edge_ctx == to` (das besessene Kontext-Daten
///   ist zugleich das Ziel und die Kanten-Rolle, §3.1/§3.3).
/// - `Backward`: `target → referrers` ⇒ das Ziel `to` ist der Verweiser, und die
///   Kante wird von **ihm** über den hier durchlaufenen Knoten `node` gehalten —
///   `edge_ctx == node` (das besessene Kontext-Daten, auf das der Verweiser zeigt).
/// - `Both`: die Vereinigung beider; Duplikate sind harmlos (sie werden beim
///   Sortieren/Visited-Set zusammengeführt).
fn neighbors_of<I: EdgeIndex>(
    store: &ContentStore<I>,
    node: ContentId,
    dir: Direction,
) -> Result<Vec<(ContentId, ContentId)>, KernelError> {
    let mut out: Vec<(ContentId, ContentId)> = Vec::new();
    match dir {
        Direction::Forward => {
            for to in store.index().contexts_of(node)? {
                // Vorwärts: das besessene Kontext-Daten ist Ziel UND Kanten-Rolle.
                out.push((to, to));
            }
        }
        Direction::Backward => {
            for referrer in store.index().referrers_of(node)? {
                // Rückwärts: zum Verweiser; die durchlaufene Kante ist „referrer ⊳
                // node", also ist die Kanten-Rolle (`edge_ctx`) der hiesige Knoten.
                out.push((node, referrer));
            }
        }
        Direction::Both => {
            for to in store.index().contexts_of(node)? {
                out.push((to, to));
            }
            for referrer in store.index().referrers_of(node)? {
                out.push((node, referrer));
            }
        }
    }
    Ok(out)
}

/// `true`, wenn `xs` **strikt aufsteigend** ist (sortiert **und** duplikat-frei) —
/// die Invariante, die der `edge_type_filter` für seine `binary_search`-
/// Mitgliedschafts-Prüfung erfüllen muss (§1.3/§1.7 a). Linear, allokationsfrei.
fn is_sorted_deduped(xs: &[ContentId]) -> bool {
    xs.windows(2).all(|w| w[0] < w[1])
}

/// Sichtbarkeit eines Knotens am Tor (§11.3) — reines Mengen-Matching (§1.3):
/// `Bereiche(Daten) ∩ gewährte Bereiche` (oder das Daten ist unbeschränkt). Ein
/// **nicht vorhandenes** Daten gilt als nicht sichtbar (`false`) — ununterscheidbar
/// (VANISH).
fn is_visible_node<I: EdgeIndex>(
    store: &ContentStore<I>,
    id: ContentId,
    granted: &[ContentId],
) -> Result<bool, KernelError> {
    // Ein nicht vorhandenes Daten ist kein sichtbarer Knoten (VANISH; ein Verweis
    // auf ein fehlendes Ziel — die schreibende Schicht erzwingt Geschlossenheit,
    // §3.6 — wird als Front-Stopp behandelt, nicht als Fehler).
    if !store.contains(id) {
        return Ok(false);
    }
    // Fail-closed (§11): die Bereiche werden gegen die durable Wahrheit geprüft;
    // ein korrupter Bereichs-Index ⇒ `Inconsistent` (DENY), statt eine unsichere
    // Sicht zu liefern. Der Fail-closed-Vermerk geschieht in `areas_of_checked`.
    let areas = store.areas_of_checked(id)?;
    Ok(crate::gate::is_visible(&areas, granted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::RedbEdgeIndex;
    use crate::gate::{Capability, GrantedScopes};
    use crate::model::Datum;
    use tempfile::tempdir;

    fn open_store(dir: &std::path::Path) -> ContentStore<RedbEdgeIndex> {
        let log_dir = dir.join("log");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let log = crate::log::SegmentLog::open(&log_dir).expect("log");
        let index = RedbEdgeIndex::open(dir.join("index.redb")).expect("index");
        ContentStore::open(log, index).expect("store")
    }

    /// Eine Capability mit den gegebenen gewährten Bereichen (crate-intern;
    /// außerhalb von `gate` nicht konstruierbar — hier legitim, da Unit-Test).
    fn cap(scopes: impl IntoIterator<Item = ContentId>) -> Capability {
        Capability::issue(GrantedScopes::from_scope_ids(scopes))
    }

    /// Sammelt die `Ok`-Schritte; bricht bei einem Fehler kontrolliert ab und gibt
    /// ihn separat zurück.
    fn collect(
        steps: Vec<Result<Step, KernelError>>,
    ) -> (Vec<Step>, Option<KernelError>) {
        let mut ok = Vec::new();
        let mut err = None;
        for s in steps {
            match s {
                Ok(step) => ok.push(step),
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        (ok, err)
    }

    fn params(start: ContentId, dir: Direction, max_depth: u32, max_nodes: u64) -> TraversalParams {
        TraversalParams {
            start,
            dir,
            max_depth,
            max_nodes,
            edge_type_filter: None,
        }
    }

    // ------------------------------------------------------------------------
    // Forward-Nachbarschaft auf einem kleinen Graphen: A besitzt B und C.
    // ------------------------------------------------------------------------

    #[test]
    fn forward_neighborhood_is_correct() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let b = store.append_datum(&Datum::leaf(b"b".to_vec())).unwrap();
        let c = store.append_datum(&Datum::leaf(b"c".to_vec())).unwrap();
        let a = store.append_datum(&Datum::node([b, c]).unwrap()).unwrap();

        let p = params(a, Direction::Forward, 4, 100);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(err.is_none());
        // A → B und A → C (Tiefe 1), in aufsteigender Ziel-Order.
        let targets: Vec<ContentId> = steps.iter().map(|s| s.to).collect();
        let mut expected = vec![b, c];
        expected.sort_unstable();
        assert_eq!(targets, expected);
        assert!(steps.iter().all(|s| s.from == a && s.depth == 1));
    }

    // ------------------------------------------------------------------------
    // Backward-Nachbarschaft: B wird von A und D verwiesen ⇒ referrer(B) = {A, D}.
    // ------------------------------------------------------------------------

    #[test]
    fn backward_neighborhood_is_correct() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let b = store.append_datum(&Datum::leaf(b"b".to_vec())).unwrap();
        let a = store.append_datum(&Datum::node([b]).unwrap()).unwrap();
        // D besitzt B und ein weiteres Blatt, damit A != D.
        let e = store.append_datum(&Datum::leaf(b"e".to_vec())).unwrap();
        let d = store.append_datum(&Datum::node([b, e]).unwrap()).unwrap();

        let p = params(b, Direction::Backward, 1, 100);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(err.is_none());
        let referrers: Vec<ContentId> = steps.iter().map(|s| s.to).collect();
        let mut expected = vec![a, d];
        expected.sort_unstable();
        assert_eq!(referrers, expected);
    }

    // ------------------------------------------------------------------------
    // Zyklus terminiert über das Visited-Set (§1.6/§1.7 a). Wir bauen einen
    // strukturellen Zyklus über `Both`, der ohne Visited-Set nie endete.
    // ------------------------------------------------------------------------

    #[test]
    fn cycle_terminates_via_visited_set() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        // A besitzt B, B besitzt A wäre ein echter Zyklus — wegen
        // Inhaltsadressierung kann ein Knoten aber nur bereits vorhandene IDs
        // besitzen. Wir erzeugen den Zyklus daher über `Both`: A besitzt B; in der
        // `Both`-Sicht ist A Nachbar von B (referrer) und B Nachbar von A (context)
        // — das ist genau die Situation, in der ein naiver Lauf endlos pendelte.
        let b = store.append_datum(&Datum::leaf(b"b".to_vec())).unwrap();
        let a = store.append_datum(&Datum::node([b]).unwrap()).unwrap();

        let p = params(a, Direction::Both, 1000, 1000);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        // Terminiert (kein Hang); das Visited-Set verhindert das Pendeln A↔B.
        assert!(err.is_none(), "Zyklus terminiert ohne Budget-Fehler");
        // Es werden nur A und B je einmal besucht.
        let mut seen: HashSet<ContentId> = HashSet::new();
        seen.insert(a);
        for s in &steps {
            seen.insert(s.to);
        }
        assert_eq!(seen.len(), 2, "nur A und B besucht (Visited-Set, §1.6)");
    }

    // ------------------------------------------------------------------------
    // Tiefen-Budget kappt: eine Kette A→B→C→D, max_depth=2 ⇒ nur bis C.
    // ------------------------------------------------------------------------

    #[test]
    fn depth_budget_caps_results() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = store.append_datum(&Datum::leaf(b"d".to_vec())).unwrap();
        let c = store.append_datum(&Datum::node([d]).unwrap()).unwrap();
        let b = store.append_datum(&Datum::node([c]).unwrap()).unwrap();
        let a = store.append_datum(&Datum::node([b]).unwrap()).unwrap();

        // max_depth = 2 ⇒ Schritte bis Tiefe 2 (A→B Tiefe 1, B→C Tiefe 2), nicht C→D.
        let p = params(a, Direction::Forward, 2, 100);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(err.is_none());
        let max_d = steps.iter().map(|s| s.depth).max().unwrap_or(0);
        assert_eq!(max_d, 2, "kein Schritt tiefer als max_depth");
        assert!(steps.iter().all(|s| s.to != d), "D liegt jenseits der Tiefe");
        assert!(steps.iter().any(|s| s.to == c), "C wird erreicht");
    }

    // ------------------------------------------------------------------------
    // Knoten-Budget: derselbe Graph, max_nodes klein ⇒ definierter Budget-Fehler.
    // ------------------------------------------------------------------------

    #[test]
    fn node_budget_yields_defined_error() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = store.append_datum(&Datum::leaf(b"d".to_vec())).unwrap();
        let c = store.append_datum(&Datum::node([d]).unwrap()).unwrap();
        let b = store.append_datum(&Datum::node([c]).unwrap()).unwrap();
        let a = store.append_datum(&Datum::node([b]).unwrap()).unwrap();

        // max_nodes = 2 ⇒ A + ein weiterer Knoten; der zweite neue Knoten sprengt
        // das Budget ⇒ definierter TraversalBudgetExceeded.
        let p = params(a, Direction::Forward, 100, 2);
        let (_steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(matches!(err, Some(KernelError::TraversalBudgetExceeded)));
    }

    // ------------------------------------------------------------------------
    // HOHER AUSGANGSGRAD (Regression, §1.7 a „nie unbeschränkter Speicher"): ein
    // EINZELNER Knoten mit Ausgangsgrad ≫ max_nodes muss definiert mit
    // TraversalBudgetExceeded enden, OHNE alle Kanten zu materialisieren — das
    // Schritt-Budget greift, BEVOR der Puffer über O(max_nodes) wächst.
    // ------------------------------------------------------------------------

    #[test]
    fn high_out_degree_node_respects_step_budget() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        // Ein Owner A mit vielen (50) Kontexten — Ausgangsgrad weit über max_nodes.
        let mut leaves = Vec::new();
        for i in 0..50u8 {
            leaves.push(store.append_datum(&Datum::leaf(vec![0xD0, i])).unwrap());
        }
        let a = store.append_datum(&Datum::node(leaves).unwrap()).unwrap();

        // Winziges Budget: max_nodes = 3 ⇒ Schritt-Budget = 3. Die vierte zugelassene
        // Kante sprengt das Budget; der Lauf endet definiert, ohne alle 50 Kanten zu
        // puffern.
        let p = params(a, Direction::Forward, 1, 3);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(
            matches!(err, Some(KernelError::TraversalBudgetExceeded)),
            "hoher Ausgangsgrad ⇒ definierter Budget-Abbruch (§1.7 a)"
        );
        // Nur bis zum Budget materialisiert (≤ Schritt-Budget) — KEINE 50 Schritte.
        assert!(
            steps.len() as u64 <= 3,
            "Speicher O(max_nodes): nie alle Kanten gepuffert (war {})",
            steps.len()
        );
    }

    // ------------------------------------------------------------------------
    // Kooperativer Abbruch INNERHALB der Nachbar-Expansion eines hochgradigen
    // Knotens (§„Beschränkte Traversierung"): ein vor dem Lauf gesetztes Flag bricht
    // ab, ohne den ganzen Knoten zu expandieren.
    // ------------------------------------------------------------------------

    #[test]
    fn cancel_interrupts_high_out_degree_expansion() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let mut leaves = Vec::new();
        for i in 0..50u8 {
            leaves.push(store.append_datum(&Datum::leaf(vec![0xE0, i])).unwrap());
        }
        let a = store.append_datum(&Datum::node(leaves).unwrap()).unwrap();

        let flag = CancelFlag::new();
        flag.cancel();
        // Großes Budget, damit NICHT das Budget, sondern der Abbruch greift.
        let p = params(a, Direction::Forward, 1, 1000);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &flag));
        assert!(steps.is_empty(), "Abbruch vor jeder zugelassenen Kante");
        assert!(matches!(err, Some(KernelError::Cancelled)));
    }

    // ------------------------------------------------------------------------
    // edge_type_filter: A besitzt zwei Relations-Kontexte; Filter auf einen davon
    // beschränkt die Kanten strukturell (kein Wert-Matching, §1.4).
    // ------------------------------------------------------------------------

    #[test]
    fn edge_type_filter_restricts_to_matching_relations() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let r1 = store.append_datum(&Datum::leaf(b"rel-1".to_vec())).unwrap();
        let r2 = store.append_datum(&Datum::leaf(b"rel-2".to_vec())).unwrap();
        let a = store.append_datum(&Datum::node([r1, r2]).unwrap()).unwrap();

        let mut filter = vec![r1];
        filter.sort_unstable();
        let p = TraversalParams {
            start: a,
            dir: Direction::Forward,
            max_depth: 1,
            max_nodes: 100,
            edge_type_filter: Some(filter),
        };
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(err.is_none());
        // Nur die Kante mit edge_ctx == r1 bleibt.
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].edge_ctx, r1);
        assert_eq!(steps[0].to, r1);
    }

    // ------------------------------------------------------------------------
    // edge_type_filter UNSORTIERT/DOPPELT (Regression): `run_traversal` muss den
    // Filter defensiv normalisieren (aufsteigend sortiert + dedupliziert). Ein
    // unsortierter Filter darf KEINE passende Kante still fallen lassen, und die
    // Reihenfolge des Filters darf das Ergebnis NICHT verändern (§1.3/§1.7 a).
    // ------------------------------------------------------------------------

    #[test]
    fn unsorted_duplicated_filter_is_normalized_and_order_irrelevant() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        // Sechs Relations-Kontexte, A besitzt alle.
        let mut rels = Vec::new();
        for i in 0..6u8 {
            rels.push(store.append_datum(&Datum::leaf(vec![0xC0 ^ i, i])).unwrap());
        }
        let a = store.append_datum(&Datum::node(rels.clone()).unwrap()).unwrap();

        // Erwartung: ein bestimmtes Tripel von Relationen, in zwei verschiedenen
        // (beide UNSORTIERTEN, eine zusätzlich DOPPELTEN) Filter-Reihenfolgen.
        let wanted = [rels[4], rels[1], rels[3]];
        let mut expected_targets: Vec<ContentId> = wanted.to_vec();
        expected_targets.sort_unstable();

        // (a) Direkt befülltes TraversalParams mit UNSORTIERTEM Filter → run_traversal
        //     muss defensiv normalisieren.
        let p_a = TraversalParams {
            start: a,
            dir: Direction::Forward,
            max_depth: 1,
            max_nodes: 100,
            edge_type_filter: Some(vec![rels[4], rels[1], rels[3]]),
        };
        let (steps_a, err_a) = collect(run_traversal(&store, &cap([]), &p_a, &CancelFlag::new()));
        assert!(err_a.is_none());
        let mut tos_a: Vec<ContentId> = steps_a.iter().map(|s| s.to).collect();
        // Jede passende Kante bleibt erhalten (keine Unter-Inklusion).
        assert_eq!(steps_a.len(), 3, "alle drei passenden Kanten bleiben");
        tos_a.sort_unstable();
        assert_eq!(tos_a, expected_targets);

        // (b) Andere (ebenfalls unsortierte) Reihenfolge + ein Duplikat → identisches
        //     Ergebnis (Reihenfolge ist ergebnis-irrelevant; Dedup harmlos).
        let p_b = TraversalParams {
            start: a,
            dir: Direction::Forward,
            max_depth: 1,
            max_nodes: 100,
            edge_type_filter: Some(vec![rels[3], rels[4], rels[1], rels[4]]),
        };
        let (steps_b, err_b) = collect(run_traversal(&store, &cap([]), &p_b, &CancelFlag::new()));
        assert!(err_b.is_none());
        // Die emittierten Schritte sind über beide Filter-Reihenfolgen IDENTISCH
        // (deterministisch, kein Reihenfolge-Einfluss).
        assert_eq!(steps_a, steps_b, "Filter-Reihenfolge ist ergebnis-irrelevant");

        // (c) Der invariant-sichere Konstruktor liefert dasselbe.
        let p_c = TraversalParams::new(
            a,
            Direction::Forward,
            1,
            100,
            Some(vec![rels[1], rels[4], rels[3]]),
        );
        let (steps_c, err_c) = collect(run_traversal(&store, &cap([]), &p_c, &CancelFlag::new()));
        assert!(err_c.is_none());
        assert_eq!(steps_a, steps_c);
    }

    // ------------------------------------------------------------------------
    // Deterministische, aufsteigende ContentId-Order der Emission (§5.2/§1.4).
    // ------------------------------------------------------------------------

    #[test]
    fn emission_order_is_contentid_ascending_and_stable() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        // Mehrere Blätter, A besitzt alle ⇒ viele Kanten Tiefe 1.
        let mut leaves = Vec::new();
        for i in 0..6u8 {
            leaves.push(store.append_datum(&Datum::leaf(vec![i, 0xAA, i])).unwrap());
        }
        let a = store.append_datum(&Datum::node(leaves.clone()).unwrap()).unwrap();

        let p = params(a, Direction::Forward, 1, 100);
        let run1 = run_traversal(&store, &cap([]), &p, &CancelFlag::new());
        let run2 = run_traversal(&store, &cap([]), &p, &CancelFlag::new());
        let (s1, _) = collect(run1);
        let (s2, _) = collect(run2);
        // Stabil über Läufe.
        assert_eq!(s1, s2);
        // Aufsteigend in ContentId-(to)-Order.
        let tos: Vec<ContentId> = s1.iter().map(|s| s.to).collect();
        let mut sorted = tos.clone();
        sorted.sort_unstable();
        assert_eq!(tos, sorted, "Emission aufsteigend in ContentId-Adress-Order");
    }

    // ------------------------------------------------------------------------
    // Cancel-Flag: ein bereits gesetztes Flag bricht sofort definiert ab.
    // ------------------------------------------------------------------------

    #[test]
    fn cancel_flag_aborts_with_defined_error() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let b = store.append_datum(&Datum::leaf(b"b".to_vec())).unwrap();
        let a = store.append_datum(&Datum::node([b]).unwrap()).unwrap();
        let flag = CancelFlag::new();
        flag.cancel();
        let p = params(a, Direction::Forward, 4, 100);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &flag));
        assert!(steps.is_empty());
        assert!(matches!(err, Some(KernelError::Cancelled)));
    }

    // ------------------------------------------------------------------------
    // VANISH (§11.3): ein nicht-sichtbares Ziel ist ein Front-Stopp; es erscheint
    // weder als Step noch verändert es die Ergebnisform (keine Nachbar-Zahl-Leak).
    // ------------------------------------------------------------------------

    #[test]
    fn non_visible_neighbor_vanishes_without_count_leak() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        // Bereich-Daten + Zugehörigkeits-Kontext für ein „geheimes" Blatt.
        let area = store.append_datum(&Datum::leaf(b"area-secret".to_vec())).unwrap();
        // Marker-Atom muss vorhanden sein, damit der Zugehörigkeits-Kontext aufgelöst
        // werden kann (Geschlossenheit, §3.6).
        let _marker = store.append_datum(&Datum::area_membership_marker()).unwrap();
        let membership = store.append_datum(&Datum::area_membership(area)).unwrap();
        // Ein sichtbares (unbeschränktes) Blatt und ein geheimes Blatt, das dem
        // Bereich angehört (es besitzt den Zugehörigkeits-Kontext).
        let public_leaf = store.append_datum(&Datum::leaf(b"public".to_vec())).unwrap();
        let secret = store.append_datum(&Datum::node([membership]).unwrap()).unwrap();
        // A besitzt beides.
        let a = store.append_datum(&Datum::node([public_leaf, secret]).unwrap()).unwrap();

        // Subjekt OHNE den geheimen Bereich.
        let p = params(a, Direction::Forward, 2, 100);
        let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(err.is_none());
        // Das geheime Daten erscheint NIE als Ziel.
        assert!(steps.iter().all(|s| s.to != secret), "geheimes Ziel VANISHt");
        // Aber das öffentliche schon.
        assert!(steps.iter().any(|s| s.to == public_leaf));
        // Mit gewährtem Bereich wird das geheime sichtbar — die Ergebnisform wächst
        // erst DANN um den Knoten (kein Orakel ohne Recht).
        let p2 = params(a, Direction::Forward, 2, 100);
        let (steps2, err2) = collect(run_traversal(&store, &cap([area]), &p2, &CancelFlag::new()));
        assert!(err2.is_none());
        assert!(steps2.iter().any(|s| s.to == secret), "mit Recht sichtbar");
    }

    // ------------------------------------------------------------------------
    // VANISH-Ergebnisform-Invarianz (§11.3): die Zahl der VERBORGENEN Nachbarn
    // darf die für einen Leser sichtbare Ergebnisform NICHT verändern. Ein Knoten
    // mit einem öffentlichen Nachbarn und K geheimen Nachbarn liefert dem Leser
    // für jedes K dieselben sichtbaren Schritte (keine Nachbarzahl-Leak).
    // ------------------------------------------------------------------------

    #[test]
    fn hidden_neighbor_count_does_not_change_result_shape() {
        fn visible_targets(num_secrets: u8) -> Vec<ContentId> {
            let dir = tempdir().unwrap();
            let mut store = open_store(dir.path());
            let area = store.append_datum(&Datum::leaf(b"area-x".to_vec())).unwrap();
            let _marker = store.append_datum(&Datum::area_membership_marker()).unwrap();
            let membership = store.append_datum(&Datum::area_membership(area)).unwrap();
            let public_leaf = store.append_datum(&Datum::leaf(b"pub".to_vec())).unwrap();
            // Knoten A besitzt das öffentliche Blatt und K geheime Daten (jedes
            // gehört dem Bereich an, also für einen rechtlosen Leser unsichtbar).
            let mut owned = vec![public_leaf];
            for i in 0..num_secrets {
                // Jedes geheime Daten ist verschieden (anderes Begleit-Blatt) und
                // besitzt den Zugehörigkeits-Kontext ⇒ beschränkt.
                let tag = store.append_datum(&Datum::leaf(vec![0x50 ^ i, i])).unwrap();
                let secret = store
                    .append_datum(&Datum::node([membership, tag]).unwrap())
                    .unwrap();
                owned.push(secret);
            }
            let a = store.append_datum(&Datum::node(owned).unwrap()).unwrap();
            let p = params(a, Direction::Forward, 1, 1000);
            let (steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
            assert!(err.is_none());
            steps.iter().map(|s| s.to).collect()
        }
        // Ein rechtloser Leser sieht für 0, 1 und 5 geheime Nachbarn jeweils GENAU
        // den einen öffentlichen Nachbarn — die verborgene Anzahl leakt nicht.
        let zero = visible_targets(0);
        let one = visible_targets(1);
        let five = visible_targets(5);
        assert_eq!(zero.len(), 1);
        assert_eq!(one.len(), 1, "ein verborgener Nachbar leakt nicht in die Zahl");
        assert_eq!(five.len(), 1, "fünf verborgene Nachbarn leaken nicht in die Zahl");
    }

    // ------------------------------------------------------------------------
    // Telemetrie/Fehler sichtbarkeits-blind (§11.3): kein KernelError-Text nennt
    // eine konkrete (verborgene) Daten-ID oder einen Bereich. Negativ-Test.
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // FAIL-CLOSED bei korruptem Bereichs-Index (§11): weicht der gecachte
    // Bereichs-Index eines Nachbarn von der durablen Wahrheit ab, endet die
    // gegatete Traversierung fail-closed (`Inconsistent`, DENY) + Metrik — statt
    // einen Nachbarn fälschlich als sichtbar durchzulassen.
    // ------------------------------------------------------------------------

    #[test]
    fn traversal_fails_closed_on_corrupt_scope_index() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let area = store.append_datum(&Datum::leaf(b"area".to_vec())).unwrap();
        let _marker = store.append_datum(&Datum::area_membership_marker()).unwrap();
        let membership = store.append_datum(&Datum::area_membership(area)).unwrap();
        let secret = store.append_datum(&Datum::node([membership]).unwrap()).unwrap();
        let a = store.append_datum(&Datum::node([secret]).unwrap()).unwrap();

        // Bereichs-Index korrumpieren: der geheime Nachbar erscheint fälschlich als
        // unbeschränkt. `areas_of_checked` erkennt das beim Traversieren.
        store.corrupt_area_cache(secret, vec![]);

        let p = params(a, Direction::Forward, 2, 100);
        // Rechtloses Subjekt: ohne Korruption würde `secret` VANISHen; mit Korruption
        // DENY (fail-closed), nicht etwa als sichtbar durchlassen.
        let (_steps, err) = collect(run_traversal(&store, &cap([]), &p, &CancelFlag::new()));
        assert!(matches!(err, Some(KernelError::Inconsistent)), "fail-closed DENY (§11)");
        assert!(store.metrics().fail_closed_count >= 1, "Fail-closed gezählt (§11)");
    }

    #[test]
    fn error_texts_are_visibility_blind() {
        // Wir provozieren die Budget-/Abbruch-/Inkonsistenz-Fehler und prüfen, dass
        // ihr Text KEINE 64-stellige Hex-ID und kein „secret"/„area" leakt.
        let secret_id = ContentId::from_bytes([0xAB; 32]).to_hex();
        for e in [
            KernelError::TraversalBudgetExceeded,
            KernelError::Cancelled,
            KernelError::Inconsistent,
        ] {
            let text = e.to_string();
            assert!(
                !text.contains(&secret_id),
                "Fehlertext darf keine konkrete ID leaken (§11.3)"
            );
            // Keine domänen-/sichtbarkeits-spezifischen Begriffe.
            assert!(!text.to_lowercase().contains("secret"));
        }
    }
}
