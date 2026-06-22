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

use std::sync::RwLock;

use crate::api::{Direction, Kernel, SnapshotToken, StepStream};
use crate::error::KernelError;
use crate::gate::{Capability, GrantedScopes, SealedRecord};
use crate::id::ContentId;
use crate::index::EdgeIndex;
use crate::log::SegmentLog;
use crate::model::Datum;
use crate::store::ContentStore;
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
}

impl<I: EdgeIndex> LakearchKernel<I> {
    /// Baut einen Kernel über einem bereits geöffneten [`ContentStore`]. Beim
    /// Öffnen hat der Store seine reinen Derivate (Dedup-Karte, Index) bereits aus
    /// dem Log rekonstruiert/versöhnt (§8.4).
    pub fn from_store(store: ContentStore<I>) -> Self {
        LakearchKernel {
            store: RwLock::new(store),
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
    /// Snapshot ist am Start gepinnt (§1.7 a/§13); die volle §13-Epochen-Semantik
    /// folgt in Phase 5.
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
        // Snapshot wird am Start gepinnt; in Phase 1/2 ist die Wahrheit alles bis
        // zur committeten Watermark. Volle §13-Epochen-Semantik: Phase 5.
        let _ = snapshot;
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
        let steps = run_traversal(&store, capability, &params, cancel);
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
        Ok(LakearchKernel::from_store(store))
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
    /// `snapshot` wird formal entgegengenommen (volle §13-Epoche: Phase 5); jede
    /// Tor-Operation läuft über **dasselbe** S (§11.2).
    fn get_by_content_id(
        &self,
        id: ContentId,
        capability: &Capability,
        snapshot: SnapshotToken,
    ) -> Result<Option<SealedRecord>, KernelError> {
        // `snapshot` wird formal entgegengenommen (volle §13-Epoche: Phase 5).
        let _ = snapshot;
        let store = self.store.read().map_err(|_| KernelError::Poisoned)?;
        // Server-seitig versiegeln: `None` ⇒ nicht vorhanden.
        let sealed = match store.get_sealed(id)? {
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
        let _ = snapshot;
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
        let steps = run_traversal(&store, &capability, &params, &CancelFlag::new());
        Ok(Box::new(steps.into_iter()))
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
        // Nach Phase 2 sind Matching + Traversierung verdrahtet; die noch
        // unverdrahteten Verben (Aktiv-Marker = Phase 5, Provenance = Phase 6)
        // melden weiterhin ihre Phase, kein Verb panickt.
        let dir = tempdir().unwrap();
        let k = open_kernel(dir.path());
        let snap = k.pin_snapshot().unwrap();
        let a = ContentId::from_bytes([0x01; 32]);
        let b = ContentId::from_bytes([0x02; 32]);

        assert!(matches!(
            k.set_active_marker(&[a, b]),
            Err(KernelError::NotYetImplemented(5))
        ));
        assert!(matches!(
            k.find_dependents(a, snap).err(),
            Some(KernelError::NotYetImplemented(6))
        ));
        assert!(matches!(
            k.traverse_provenance_backward(a, 4, 100, snap).err(),
            Some(KernelError::NotYetImplemented(6))
        ));
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
        let snap = k.pin_snapshot().unwrap();

        let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();
        let c = k.append(&Datum::leaf(b"c".to_vec())).unwrap();
        let a = k.append(&Datum::node([b, c]).unwrap()).unwrap();

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
}
