//! Der **Content-Store** (§5.2/§5.3) — die Brücke zwischen dem abstrakten Daten
//! ([`crate::model::Datum`]) und dem durablen Append-Segment-Log
//! ([`crate::log::SegmentLog`]), plus die abgeleiteten Kanten-Indizes
//! ([`crate::index::EdgeIndex`]).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2 Speicher-Identität;
//! §5.3 Wert-Identität/Dedup; §7.1 append-only; §8.4 Log = alleinige Wahrheit)
//! und der gehärtete Plan (Abschnitte „Identitäts- & Hashing-Modell", „Log-als-
//! alleinige-Wahrheit + neu-baubarer Index").
//!
//! ## Was der Store tut (rein mechanisch, §1.4)
//!
//! - **[`ContentStore::append_datum`]** (§7.1): kanonisiert das Daten
//!   ([`crate::serialize::canonical_cbor`]), bildet seine [`ContentId`]
//!   ([`ContentId::of_datum`], §K5) und **dedupliziert** (§5.3): existiert die
//!   `ContentId` schon, wird **nichts** geschrieben und **keine** seq verbraucht —
//!   die vorhandene ID kommt zurück. Andernfalls wird der gerahmte Record an das
//!   Log angehängt **und committet** (Log-`fsync`); **erst danach** werden die
//!   abgeleiteten Kanten in den Index committet (Ordnung **log-fsync →
//!   index-commit**, §8.4).
//! - **[`ContentStore::get_by_content_id`]** (§5.2-Fetch): schlägt die `ContentId`
//!   in der (aus dem Log gebauten) Dedup-Karte nach und liest den durablen Record
//!   über das read-only-`mmap` des Logs zurück; die Prüfsumme ist dabei
//!   verifiziert (§Durability). Liefert die kanonischen Bytes bzw. das
//!   strikt-dekodierte [`Datum`] (§K6).
//!
//! ## Log-als-Wahrheit (§8.4): Dedup-Karte + Index sind reine Derivate
//!
//! Die **Dedup-Karte** (`ContentId → Record-Offset`) und **beide** Kanten-Indizes
//! sind **reine, neu-baubare** Projektionen über das Log. Beim Öffnen werden sie
//! aus dem Log **rekonstruiert/versöhnt**:
//! - Dedup-Karte: immer vollständig aus dem Log gebaut (sie ist klein und
//!   in-memory; das Log ist die Wahrheit, §8.4).
//! - Index: Watermark `W` (im Index persistiert) vs. durabler Log-Tail `T`:
//!   `W < T` ⇒ `[W..T)` nachspielen; `W > T` ⇒ Index unsicher ⇒ voller Neu-Bau
//!   ([`ContentStore::rebuild_index_from_log`]); `W == T` ⇒ in sync. **Keine**
//!   Suffix-Chirurgie (§8.4).
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: das `unsafe` lebt allein im
//! `mmap`-Leaf [`crate::log`].

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::KernelError;
use crate::gate::SealedRecord;
use crate::id::ContentId;
use crate::index::{Edge, EdgeIndex};
use crate::log::SegmentLog;
use crate::model::Datum;
use crate::serialize::{canonical_cbor, strict_decode};

/// Leichtgewichtige **Betriebs-Zähler** des Stores (§Betrieb). Reine Mechanik
/// (§1.4); keine Wertung, keine sichtbaren Daten/IDs in Labels.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StoreMetrics {
    /// Anzahl **physisch geschriebener** Daten (neue Records; ohne Dedup-Treffer).
    pub append_count: u64,
    /// Anzahl **Dedup-Treffer** (§5.3): inhaltsgleiches `append_datum`, das
    /// **nichts** geschrieben hat.
    pub dedup_hit_count: u64,
    /// Anzahl in den Index committeter Kanten (über alle Appends/Rebuilds).
    pub edge_count: u64,
    /// Anzahl **Fail-closed-Ereignisse** (§11): ein Lese-/Tor-/Traversier-Pfad
    /// hat wegen einer Index-/Log-Inkonsistenz oder unverifizierbaren Scopes
    /// **DENY** (leeres/abgebrochenes Ergebnis) gewählt. Reines Mechanik-Signal
    /// (§1.4), sichtbarkeits-blind (§11.3): es zählt nur **dass** ein Fail-closed
    /// auftrat, nennt **kein** Daten/keine ID/keinen Bereich. Wird über einen
    /// internen Atomic-Zähler auch auf `&self`-Lesepfaden erhöht.
    pub fail_closed_count: u64,
}

/// Der **Content-Store**: Append + Dedup über dem Log, plus die abgeleiteten
/// Kanten-Indizes. Generisch über die [`EdgeIndex`]-Engine (billig revidierbar,
/// §Storage-Engine).
///
/// **Nebenläufigkeit (Phase 1).** Wie [`SegmentLog`] ist dies der **eine**
/// Append-Pfad (`&mut self` für Mutationen); die volle MPSC-Pipeline folgt später.
pub struct ContentStore<I: EdgeIndex> {
    /// Das Append-Segment-Log — die **alleinige** Durability-Wahrheit (§8.4).
    log: SegmentLog,
    /// Die Kanten-Index-Engine — reines, neu-baubares Derivat (§8.4).
    index: I,
    /// In-memory **Dedup-Karte** `ContentId → Record-Offset` (§5.3). Reines
    /// Derivat aus dem Log; beim Öffnen rekonstruiert.
    dedup: HashMap<ContentId, u64>,
    /// In-memory **Bereichs-Zugehörigkeits-Index** `Daten → { Bereiche }` (§11.1):
    /// die Bereiche, denen ein Daten angehört. Ein Daten gehört einem Bereich an,
    /// wenn es einen **Zugehörigkeits-Kontext** besitzt (einen Knoten
    /// `{ Marker, Bereich }`, [`Datum::area_membership_target`]). Reines,
    /// neu-baubares Derivat aus dem Log (§8.4); beim Öffnen rekonstruiert. Das Tor
    /// (§11) liest es **vor** jeder Auflösung (Filter-vor-Auflösen, §11.3).
    areas: HashMap<ContentId, Vec<ContentId>>,
    /// In-memory **Berechtigungs-Karte** `Berechtigung-ContentId → (Subjekt,
    /// Bereich)` (§11.1): alle im Log vorliegenden Berechtigungs-*Fakten*. Reines,
    /// neu-baubares Derivat (§8.4). „Aktiv" entscheidet erst der Abgleich mit
    /// [`revoked`](ContentStore::revoked) (§11.4) — eine **strukturelle** Notion,
    /// **kein** Wall-Clock (§11.5).
    permissions: HashMap<ContentId, (ContentId, ContentId)>,
    /// In-memory **Entzugs-Menge** (§11.4): die `ContentId`s der Berechtigungen,
    /// die ein Entzugs-Kontext im Log benennt. Reines, neu-baubares Derivat (§8.4).
    /// Eine Berechtigung ist **aktiv** (für das Tor wirksam), wenn sie hier **nicht**
    /// enthalten ist (strukturell-aktiv-im-Snapshot, §11.5).
    revoked: HashSet<ContentId>,
    /// In-memory **Zeit-Aussage-Mitgliedschafts-Index** (§6.1/§6.2):
    /// `Zeit-Aussage-Kontext-ContentId → { Daten, die diesen Kontext tragen }`. Der
    /// Schlüssel ist die `ContentId` eines **Zeit-Aussage-Kontextes**
    /// (`{ Achsen-Marker, Zeit-Wert }`, [`Datum::recording_time`]/
    /// [`Datum::validity_time`]); der Wert sind die Daten, die ihn als besessenen
    /// Kontext **tragen**. Das erlaubt den **strukturellen LOOKUP** (Exakt-Match/
    /// Mitgliedschaft, §1.3): „welche Daten tragen diese Zeit-Aussage?" — **ohne**
    /// den opaken Zeit-Wert je zu parsen/ordnen/vergleichen (§1.4/§6.4). Reines,
    /// neu-baubares Derivat aus dem Log (§8.4). **Keine** geordnete Bereichs-Abfrage:
    /// der Index kennt nur Mengen-Zugehörigkeit, **kein** „T liegt zwischen A und B"
    /// (das wäre Ordnung → §1.4-Verstoß; es ist eine Leseregel der Schicht darüber,
    /// §6.4/§8).
    time_carriers: HashMap<ContentId, Vec<ContentId>>,
    /// In-memory **Ersetzungs-Index — Vorwärts** (§6.3): `neueres Daten → { ältere
    /// Daten, die es überholt }`. Ein Daten N überholt O, wenn N einen **Ersetzungs-
    /// Kontext** `{ supersession_marker, O }` ([`Datum::supersedes`]) besitzt. Reines,
    /// neu-baubares Derivat (§8.4) — *supersedes* (neuer → älter).
    supersedes: HashMap<ContentId, Vec<ContentId>>,
    /// In-memory **Ersetzungs-Index — Rückwärts** (§6.3): `älteres Daten → { neuere
    /// Daten, die es überholen }`. Die Umkehrung von [`supersedes`](ContentStore::supersedes)
    /// — *superseded-by* (älter → neuer). Damit ist die Ersetzungs-Relation in
    /// **beide** Richtungen traversierbar (§1.2). Reines, neu-baubares Derivat (§8.4).
    superseded_by: HashMap<ContentId, Vec<ContentId>>,
    /// Betriebs-Zähler (§Betrieb).
    metrics: StoreMetrics,
    /// **Fail-closed-Zähler** als Atomic (§11): er wird auch auf `&self`-Lese-/
    /// Tor-/Traversier-Pfaden erhöht, wenn fail-closed DENY gewählt wurde. In
    /// [`StoreMetrics::fail_closed_count`] gespiegelt.
    fail_closed: AtomicU64,
}

impl<I: EdgeIndex> ContentStore<I> {
    /// Öffnet einen Store über einem bereits geöffneten Log und Index. Baut die
    /// Dedup-Karte vollständig aus dem Log und **versöhnt** den Index mit dem
    /// durablen Log-Tail (§8.4): `W < T` ⇒ nachspielen, `W > T` ⇒ voller Neu-Bau.
    pub fn open(log: SegmentLog, index: I) -> Result<Self, KernelError> {
        let mut store = ContentStore {
            log,
            index,
            dedup: HashMap::new(),
            areas: HashMap::new(),
            permissions: HashMap::new(),
            revoked: HashSet::new(),
            time_carriers: HashMap::new(),
            supersedes: HashMap::new(),
            superseded_by: HashMap::new(),
            metrics: StoreMetrics::default(),
            fail_closed: AtomicU64::new(0),
        };
        store.rebuild_dedup_from_log()?;
        store.rebuild_areas_from_log()?;
        store.rebuild_permissions_from_log()?;
        store.rebuild_time_and_supersession_from_log()?;
        store.reconcile_index_with_log()?;
        Ok(store)
    }

    /// **append** (§7.1) — die einzige Mutation: kanonisiert `datum`, bildet seine
    /// [`ContentId`] (§K5) und **dedupliziert** (§5.3).
    ///
    /// - **Dedup-Treffer:** die `ContentId` existiert bereits ⇒ es wird **nichts**
    ///   geschrieben, **keine** seq verbraucht, und die vorhandene ID kommt zurück
    ///   ([`StoreMetrics::dedup_hit_count`] +1).
    /// - **Neu:** der gerahmte Record (kanonisches CBOR als Nutzlast) wird an das
    ///   Log angehängt **und committet** (Log-`fsync`, Durability-on-Ack);
    ///   **erst danach** werden die abgeleiteten Kanten (für einen besitzenden
    ///   Knoten) in den Index committet (Ordnung **log-fsync → index-commit**,
    ///   §8.4). Liefert die `ContentId` des neuen Daten.
    ///
    /// `append` **rechnet und wertet nicht** (§7.3): es findet **nicht** den Platz
    /// und beurteilt **nicht** die Verbindung (§7.2).
    pub fn append_datum(&mut self, datum: &Datum) -> Result<ContentId, KernelError> {
        let id = ContentId::of_datum(datum);

        // §5.3-Dedup: existiert das Daten schon, schreibe NICHTS und gib die
        // vorhandene ID zurück (ein primitives Daten existiert genau einmal).
        if self.dedup.contains_key(&id) {
            self.metrics.dedup_hit_count += 1;
            return Ok(id);
        }

        // Neu: kanonische Bytes (= Nutzlast des Records, §K5) ans Log anhängen und
        // committen (Log-`fsync` ZUERST, §8.4).
        let cbor = canonical_cbor(datum);
        let offset = self.log.committed_offset();
        self.log.append_and_commit(&cbor)?;
        self.dedup.insert(id, offset);
        self.metrics.append_count += 1;

        // ERST NACH dem Log-`fsync`: die abgeleiteten Kanten in den Index committen
        // (Ordnung log-fsync → index-commit, §8.4). Watermark = neuer committed
        // Log-Offset.
        let edges = edges_of(id, datum);
        let new_watermark = self.log.committed_offset();
        self.index.commit_edges(&edges, new_watermark)?;
        self.metrics.edge_count += edges.len() as u64;

        // Bereichs-Zugehörigkeits-Index (§11.1) nachziehen: besitzt das neue Daten
        // einen Zugehörigkeits-Kontext, gehört es dem darin benannten Bereich an.
        self.index_area_memberships_of(id, datum)?;
        // Berechtigungs-/Entzugs-Index (§11.1/§11.4) nachziehen.
        self.index_permission_or_revocation_of(id, datum)?;
        // Zeit-Aussage-Mitgliedschafts- und Ersetzungs-Index (§6.1–§6.3) nachziehen.
        self.index_time_and_supersession_of(id, datum)?;

        Ok(id)
    }

    /// **resolve_placeholder** (§3.6 + §6.3) — die strukturelle **Auflösung** eines
    /// Platzhalters: das echte Ziel ist eingetroffen.
    ///
    /// Ein Verweis zeigt **stets auf ein vorhandenes Daten**; ein noch nicht
    /// eingetroffenes Ziel ist ein **Platzhalter-Daten** ([`Datum::placeholder`],
    /// §3.6). Trifft das echte Daten ein, **ersetzt** es den Platzhalter (§6.3):
    /// diese Operation
    ///
    /// 1. hängt das echte Daten `real` an (§7.1, Dedup §5.3) → `real_id`,
    /// 2. baut den **Ersetzungs-Kontext** [`Datum::supersedes`]`(placeholder)`
    ///    (zeigt auf den älteren Platzhalter) und hängt ihn an,
    /// 3. hängt einen **Auflösungs-Knoten** `{ real_id, supersedes_ctx }` an, der den
    ///    Platzhalter (älter) per Ersetzungs-Kontext mit dem echten Daten (neuer)
    ///    **verknüpft** (§6.3) — append-only, der Platzhalter wird **nie** geändert
    ///    oder gelöscht (§7.1).
    ///
    /// So ist der Verweis **geschlossen**: vom Platzhalter ist über die bestehenden
    /// Indizes (`target→referrers` rückwärts: Platzhalter → Ersetzungs-Kontext →
    /// Auflösungs-Knoten → `real`; §1.2/§10.3) das auflösende echte Daten
    /// traversierbar, und vorwärts (`owner→contexts`) der umgekehrte Weg.
    ///
    /// Liefert `(real_id, resolution_id)`. Der Kernel **validiert nicht** (§1.4/§7.2):
    /// er prüft **nicht**, ob `placeholder` tatsächlich ein Platzhalter ist oder
    /// durabel vorliegt — die Geschlossenheit erzwingt die **schreibende Schicht**
    /// (§3.6). Er **verknüpft und traversiert** nur (§1.2/§1.3); welches Daten
    /// „aktuell" ist, ist eine Leseregel der Schicht darüber (§6.4/§8).
    pub fn resolve_placeholder(
        &mut self,
        placeholder: ContentId,
        real: &Datum,
    ) -> Result<(ContentId, ContentId), KernelError> {
        let real_id = self.append_datum(real)?;
        let supersedes_ctx = Datum::supersedes(placeholder);
        let supersedes_ctx_id = self.append_datum(&supersedes_ctx)?;
        // Der Auflösungs-Knoten besitzt das echte Daten UND den Ersetzungs-Kontext;
        // `node` kanonisiert (sortiert/dedupliziert, §K2.3).
        let resolution = Datum::node([real_id, supersedes_ctx_id])
            .ok_or(KernelError::Inconsistent)?;
        let resolution_id = self.append_datum(&resolution)?;
        Ok((real_id, resolution_id))
    }

    /// **get_canonical_bytes** (§5.2-Fetch, **un-gated**) — liefert die **kanonischen
    /// Bytes** des durablen Daten, falls vorhanden (sonst `None`). Die Prüfsumme ist
    /// beim Lesen verifiziert (§Durability).
    ///
    /// **`pub(crate)` mit Absicht (§11.2/§11.5).** Diese Methode gibt die Roh-Bytes
    /// **ohne** das Zugriffs-Tor heraus; sie ist daher **nicht** Teil der externen
    /// Crate-Oberfläche. Der **einzige** externe Lese-Pfad ist
    /// [`ContentStore::get_sealed`] (+ [`crate::gate::open`] gegen eine
    /// [`crate::gate::Capability`]) bzw. der [`crate::api::Kernel`]-Vertrag. Intern
    /// nutzen sie [`ContentStore::get_sealed`]/[`ContentStore::get_by_content_id`]
    /// und die Reconcile-/Rebuild-Pfade. So bleibt „ohne Tor lesen ist nicht
    /// darstellbar" eine Compile-Zeit-Eigenschaft (Tor-Modul-Doc, §11.5).
    pub(crate) fn get_canonical_bytes(&self, id: ContentId) -> Result<Option<Vec<u8>>, KernelError> {
        let offset = match self.dedup.get(&id) {
            Some(o) => *o,
            None => return Ok(None),
        };
        let rec = self.log.read_at(offset)?;
        Ok(Some(rec.payload))
    }

    /// **get_by_content_id** als strikt-dekodiertes [`Datum`] (§K6, **un-gated**).
    /// Liefert `None`, wenn die `ContentId` nicht im Store ist. Eine Inkonsistenz
    /// zwischen gespeicherter ID und dekodierten Bytes (dürfte nach erfolgreicher
    /// Recovery nie auftreten) ist [`KernelError::Inconsistent`] — **nie** still
    /// ignoriert.
    ///
    /// **`pub(crate)`, nur Tests (§11.2/§11.5).** Wie [`ContentStore::get_canonical_bytes`]
    /// gibt diese Methode ein **vollständig dekodiertes** [`Datum`] **ohne** das Tor
    /// heraus. Sie wird ausschließlich von crate-internen Tests genutzt (in denen
    /// roher, gate-loser Zugriff legitim ist) und ist daher `#[cfg(test)]`. Der
    /// externe Lese-Pfad ist [`ContentStore::get_sealed`] + das Tor.
    #[cfg(test)]
    pub(crate) fn get_by_content_id(&self, id: ContentId) -> Result<Option<Datum>, KernelError> {
        let bytes = match self.get_canonical_bytes(id)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let datum = strict_decode(&bytes)?;
        // Defensiv (§Durability): die zurückgelesene Form muss dieselbe ID tragen.
        if ContentId::of_datum(&datum) != id {
            return Err(KernelError::Inconsistent);
        }
        Ok(Some(datum))
    }

    /// **get_sealed** (§5.2-Fetch durchs Tor) — liefert ein opakes
    /// [`crate::gate::SealedRecord`] für die durablen kanonischen Bytes der
    /// `ContentId`, falls vorhanden (sonst `None`). Der Inhalt ist **versiegelt**:
    /// nur [`crate::gate::open`] gegen eine [`crate::gate::Capability`] legt ihn
    /// frei (§11.5). Die Prüfsumme ist beim Lesen verifiziert (§Durability).
    ///
    /// Das Versiegeln trägt die **Bereiche** bei, denen das Daten angehört (§11.1),
    /// server-seitig aus dem Zugehörigkeits-Index ([`ContentStore::areas_of`])
    /// bestimmt — das Tor ([`crate::gate::open`]) matcht sie **vor** der Freilegung
    /// gegen die gewährten Bereiche (Filter-vor-Auflösen, §11.3). `None` ⇒ nicht
    /// vorhanden; nicht-sichtbar wird **erst im Tor** zu `None` (VANISH, ununter-
    /// scheidbar von „nicht vorhanden").
    pub fn get_sealed(&self, id: ContentId) -> Result<Option<SealedRecord>, KernelError> {
        match self.get_canonical_bytes(id)? {
            Some(bytes) => {
                // Fail-closed (§11): die versiegelten Bereiche werden gegen die
                // durable Wahrheit geprüft; ein korrupter Bereichs-Index ⇒
                // `Inconsistent` (DENY + Metrik), statt eine unsichere Sicht zu
                // versiegeln.
                let areas = self.areas_of_checked(id)?;
                Ok(Some(SealedRecord::seal(id, bytes, areas)))
            }
            None => Ok(None),
        }
    }

    /// Die **Bereiche**, denen das Daten `id` angehört (§11.1) — owned, aufsteigend
    /// in 32-Byte-`ContentId`-Order (deterministisch, kein Wert-Sort §1.4). Leerer
    /// Vec ⇒ **unbeschränkt** (Policy-Default; das Tor behandelt es als für alle
    /// sichtbar). Reines strukturelles Lesen des Zugehörigkeits-Index (§1.3).
    pub fn areas_of(&self, id: ContentId) -> Vec<ContentId> {
        self.areas.get(&id).cloned().unwrap_or_default()
    }

    /// **Fail-closed** geprüfte Bereichs-Zugehörigkeit (§11): liefert die Bereiche
    /// von `id` **nur**, wenn der in-memory Zugehörigkeits-Index (reines Derivat,
    /// §8.4) mit der **durablen Wahrheit** (dem Log) übereinstimmt — andernfalls
    /// [`KernelError::Inconsistent`] (DENY) **und** ein Fail-closed-Vermerk (§11.3
    /// sichtbarkeits-blind).
    ///
    /// Begründung (§11): der Bereichs-Index ist sicherheits-tragend (er bestimmt,
    /// was VANISHt). Ein **stiller** Index-Defekt — etwa eine Zugehörigkeit, die im
    /// Index fehlt, obwohl das Daten den Zugehörigkeits-Kontext durabel besitzt —
    /// würde ein beschränktes Daten fälschlich als **unbeschränkt** (für alle
    /// sichtbar) ausweisen und so lecken. Daher wird die gecachte Bereichs-Menge
    /// gegen die aus dem durablen Inhalt **neu abgeleitete** Menge geprüft; bei
    /// Abweichung wird **fail-closed** verweigert, statt eine unsichere Sicht zu
    /// liefern (§11: „bei Index/Log-Inkonsistenz ⇒ DENY"). Fehlt das Daten gar nicht
    /// (`None`-Fall im Aufrufer), ist das **kein** Defekt — VANISH greift ohnehin.
    pub fn areas_of_checked(&self, id: ContentId) -> Result<Vec<ContentId>, KernelError> {
        // Die durable Wahrheit: aus dem gespeicherten Inhalt von `id` die Bereiche
        // neu ableiten (genau wie der Index-Aufbau, §8.4). Ist `id` nicht durabel
        // vorhanden (`None`), gibt es keine Zugehörigkeit — der Aufrufer behandelt
        // Nicht-Existenz separat via VANISH, der Cache muss dann leer sein.
        let truth = self.derive_areas_from_content(id)?.unwrap_or_default();
        let cached = self.areas_of(id);
        if cached != truth {
            // Index-/Log-Inkonsistenz ⇒ fail-closed DENY + Metrik (§11).
            self.note_fail_closed();
            return Err(KernelError::Inconsistent);
        }
        Ok(truth)
    }

    /// Leitet die **Bereiche** eines vorhandenen Daten `id` direkt aus seinem
    /// **durablen Inhalt** ab (§8.4) — die maßgebliche Wahrheit, gegen die
    /// [`areas_of_checked`](ContentStore::areas_of_checked) den Index prüft.
    /// `None`, wenn `id` nicht durabel vorhanden ist. Aufsteigend + dedupliziert
    /// (deterministisch, kein Wert-Sort §1.4).
    fn derive_areas_from_content(&self, id: ContentId) -> Result<Option<Vec<ContentId>>, KernelError> {
        let bytes = match self.get_canonical_bytes(id)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let datum = strict_decode(&bytes)?;
        let owns = match datum.owns() {
            Some(o) => o,
            None => return Ok(Some(Vec::new())), // Blatt: keine Zugehörigkeit.
        };
        let mut found: Vec<ContentId> = Vec::new();
        for ctx_id in owns {
            let ctx_bytes = match self.get_canonical_bytes(*ctx_id)? {
                Some(b) => b,
                None => continue, // fehlender Kontext: §3.6 Sache der Schreibschicht.
            };
            let ctx = strict_decode(&ctx_bytes)?;
            if let Some(area) = ctx.area_membership_target() {
                found.push(area);
            }
        }
        found.sort_unstable();
        found.dedup();
        Ok(Some(found))
    }

    /// **Test-Hook (§11-Fail-closed).** Überschreibt die **gecachten** Bereiche
    /// eines Daten direkt, um einen korrupten Bereichs-Index zu simulieren — der
    /// durable Inhalt im Log bleibt unberührt, sodass
    /// [`areas_of_checked`](ContentStore::areas_of_checked) die Abweichung erkennt
    /// und fail-closed verweigert. Nur in Tests verfügbar.
    #[cfg(test)]
    pub(crate) fn corrupt_area_cache(&mut self, id: ContentId, areas: Vec<ContentId>) {
        if areas.is_empty() {
            self.areas.remove(&id);
        } else {
            self.areas.insert(id, areas);
        }
    }

    /// Die **gewährten Bereiche** eines Subjekts (§11.1/§11.2) — abgeleitet aus den
    /// **aktiven** Berechtigungen im Store: alle Bereiche von Berechtigungen, deren
    /// Subjekt `subject` ist und die **nicht** entzogen sind (§11.4). „Aktiv" ist
    /// eine **strukturelle** Notion (§11.5): eine Berechtigung ist aktiv, solange
    /// kein Entzugs-Kontext sie benennt — **kein** Wall-Clock-Vergleich (§1.4).
    ///
    /// Reines Mengen-Matching (§1.3); owned, aufsteigend in 32-Byte-`ContentId`-
    /// Order (deterministisch, kein Wert-Sort §1.4). Das ist genau die Menge, mit
    /// der das Tor (§11.2) eine [`crate::gate::Capability`] ausstellt.
    pub fn granted_areas_for_subject(&self, subject: ContentId) -> Vec<ContentId> {
        let mut areas: Vec<ContentId> = self
            .permissions
            .iter()
            .filter(|(perm_id, _)| !self.revoked.contains(perm_id))
            .filter(|(_, (subj, _))| *subj == subject)
            .map(|(_, (_, area))| *area)
            .collect();
        areas.sort_unstable();
        areas.dedup();
        areas
    }

    /// Die **Daten, die eine bestimmte Zeit-Aussage tragen** (§6.1/§6.2) — reiner
    /// **struktureller LOOKUP** (Exakt-Match/Mitgliedschaft, §1.3). `statement` ist
    /// die `ContentId` eines **Zeit-Aussage-Kontextes** (`{ Achsen-Marker, Zeit-Wert }`,
    /// [`Datum::recording_time`]/[`Datum::validity_time`]); zurück kommen die Daten,
    /// die diesen Kontext besitzen — owned, aufsteigend in 32-Byte-`ContentId`-Order
    /// (deterministisch, **kein** Wert-Sort §1.4).
    ///
    /// Der Kernel **parst/ordnet/vergleicht** den opaken Zeit-Wert **nicht**
    /// (§1.4/§6.4): dies ist **keine** geordnete Bereichs-Abfrage („T zwischen A und
    /// B"), sondern reine Mengen-Zugehörigkeit zu **genau** dieser Aussage. „Welche
    /// Version gilt zum Zeitpunkt T" ist eine Leseregel der Schicht darüber (§6.4/§8).
    ///
    /// **Ungated** (`pub(crate)`): die Sichtbarkeit (VANISH) setzt die gegatete
    /// Kernel-Schicht durch ([`crate::kernel::LakearchKernel::time_carriers_visible`]),
    /// nicht dieser rohe Index-Lookup.
    pub(crate) fn time_carriers_of(&self, statement: ContentId) -> Vec<ContentId> {
        self.time_carriers.get(&statement).cloned().unwrap_or_default()
    }

    /// Die **älteren Daten, die `newer` überholt** (§6.3) — *supersedes* (neuer →
    /// älter). `newer` besitzt je einen Ersetzungs-Kontext, der auf ein überholtes
    /// `older` zeigt. Owned, aufsteigend in 32-Byte-`ContentId`-Order (kein
    /// Wert-Sort §1.4). Reines strukturelles Lesen (§1.3); der Kernel entscheidet
    /// **nicht**, welches „aktuell" ist (§6.4/§8). **Ungated** (`pub(crate)`).
    pub(crate) fn supersedes_of(&self, newer: ContentId) -> Vec<ContentId> {
        self.supersedes.get(&newer).cloned().unwrap_or_default()
    }

    /// Die **neueren Daten, die `older` überholen** (§6.3) — *superseded-by* (älter →
    /// neuer), die Umkehrung von [`supersedes_of`](ContentStore::supersedes_of). So
    /// ist die Ersetzungs-Relation in **beide** Richtungen traversierbar (§1.2).
    /// Owned, aufsteigend (kein Wert-Sort §1.4). **Ungated** (`pub(crate)`).
    pub(crate) fn superseded_by_of(&self, older: ContentId) -> Vec<ContentId> {
        self.superseded_by.get(&older).cloned().unwrap_or_default()
    }

    /// **Sichtbarkeits-geprüfte** Variante eines Lookup-Ergebnisses (§11.3): filtert
    /// die Kandidaten-IDs auf die für `granted` **sichtbaren** (VANISH). Ein nicht
    /// vorhandenes Daten ist ununterscheidbar verborgen (§3.6/§11.3). Fail-closed
    /// (§11): ein korrupter Bereichs-Index ⇒ [`KernelError::Inconsistent`] (DENY).
    ///
    /// Das ist der **gegatete** Pfad für die Zeit-/Ersetzungs-Lookups: er reicht
    /// **nur** sichtbare `ContentId`s heraus, materialisiert aber **keinen** Inhalt
    /// (den legt erst das Tor frei, §11.5). Owned, aufsteigend (kein Wert-Sort §1.4).
    pub fn visible_filter(
        &self,
        candidates: &[ContentId],
        granted: &[ContentId],
    ) -> Result<Vec<ContentId>, KernelError> {
        let mut out = Vec::new();
        for &id in candidates {
            // VANISH: ein nicht vorhandenes Daten ist kein sichtbarer Knoten.
            if !self.contains(id) {
                continue;
            }
            // Fail-closed (§11): Bereiche gegen die durable Wahrheit geprüft.
            let areas = self.areas_of_checked(id)?;
            if crate::gate::is_visible(&areas, granted) {
                out.push(id);
            }
        }
        // Der Index liefert bereits aufsteigend; defensiv erzwingen wir es (§5.2/§1.4).
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// `true`, wenn die `ContentId` durabel im Store vorhanden ist (§5.2). Reines
    /// Adress-Matching (§1.3); keine Wertung.
    pub fn contains(&self, id: ContentId) -> bool {
        self.dedup.contains_key(&id)
    }

    /// Anzahl distinkter durabler Daten (= Größe der Dedup-Karte).
    pub fn len(&self) -> usize {
        self.dedup.len()
    }

    /// `true`, wenn der Store leer ist.
    pub fn is_empty(&self) -> bool {
        self.dedup.is_empty()
    }

    /// Betriebs-Zähler des Stores (§Betrieb). Der Fail-closed-Zähler (§11) wird aus
    /// dem internen Atomic gespiegelt, da er auch auf `&self`-Pfaden wächst.
    pub fn metrics(&self) -> StoreMetrics {
        let mut m = self.metrics;
        m.fail_closed_count = self.fail_closed.load(Ordering::Relaxed);
        m
    }

    /// Vermerkt ein **Fail-closed-Ereignis** (§11) — rein das *Dass*, **kein**
    /// Daten/keine ID/kein Bereich (sichtbarkeits-blind, §11.3). Auf `&self`
    /// nutzbar (Atomic), damit Lese-/Tor-/Traversier-Pfade es zählen können.
    pub(crate) fn note_fail_closed(&self) {
        self.fail_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Lese-Sicht auf die Log-Metriken (§Betrieb).
    pub fn log_metrics(&self) -> crate::log::LogMetrics {
        self.log.metrics()
    }

    /// Lese-Zugriff auf die Index-Engine (für Traversierung/Tests; liefert owned
    /// `ContentId`s, §EdgeIndex).
    pub fn index(&self) -> &I {
        &self.index
    }

    // -- Neu-Bau / Versöhnung (§8.4) -----------------------------------------

    /// **rebuild_index_from_log** (§8.4 operationalisiert) — **wipet** den Index
    /// und baut **beide** Kanten-Richtungen aus dem **gesamten** Log neu auf
    /// (`owner→contexts` / `target→referrers`). Nach dem Neu-Bau steht das
    /// Watermark wieder am durablen Log-Tail.
    ///
    /// Der Neu-Bau ist der Beleg dafür, dass der Index ein **reines Derivat** ist:
    /// ein gewipter, neu gebauter Index hat **denselben** Inhalt wie der zuvor
    /// inkrementell gepflegte (Test `wipe_and_rebuild_is_identical`).
    ///
    /// **Mit-Neu-Bau aller reinen Derivate (§8.4).** Neben den persistenten redb-
    /// Kanten werden auch die in-memory Derivate (Bereichs-, Berechtigungs-/Entzugs-,
    /// **Zeit-Aussage-Mitgliedschafts-** und **Ersetzungs-Index**) verworfen und aus
    /// dem Log neu gebaut — so ist „wipe & rebuild" für **alle** Derivate identisch
    /// (operationalisiert „Log = alleinige Wahrheit"). Die Dedup-Karte bleibt
    /// unangetastet (sie ist die Offset-Auflösung, die der Neu-Bau selbst nutzt).
    pub fn rebuild_index_from_log(&mut self) -> Result<(), KernelError> {
        self.index.wipe()?;
        let records = self.log.read_all()?;
        let mut edges: Vec<Edge> = Vec::new();
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            edges.extend(edges_of(id, &datum));
        }
        // Den ganzen Neu-Bau in EINEM Index-Commit ablegen; Watermark = durabler
        // Log-Tail (alles nachgezogen).
        let watermark = self.log.committed_offset();
        self.index.commit_edges(&edges, watermark)?;
        // edge_count zählt nur inkrementelle Appends; ein Rebuild setzt ihn nicht
        // zurück (Mechanik-Zähler, §1.4) — wir vermerken die neu committeten Kanten.
        self.metrics.edge_count = self.metrics.edge_count.saturating_add(edges.len() as u64);
        // Auch die in-memory Derivate verwerfen und aus dem Log neu bauen (§8.4):
        // Bereichs-, Berechtigungs-/Entzugs-, Zeit-Aussage- und Ersetzungs-Index.
        self.rebuild_areas_from_log()?;
        self.rebuild_permissions_from_log()?;
        self.rebuild_time_and_supersession_from_log()?;
        Ok(())
    }

    /// Baut die in-memory **Dedup-Karte** (`ContentId → Offset`) vollständig aus
    /// dem Log neu (§8.4: Log = Wahrheit). Idempotent.
    fn rebuild_dedup_from_log(&mut self) -> Result<(), KernelError> {
        self.dedup.clear();
        let records = self.log.read_all()?;
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            // Erstes Vorkommen gewinnt (eine ContentId existiert genau einmal,
            // §5.3; ein zweiter physischer Record gleicher ID wäre ein Dedup-
            // Fehler oberhalb — er käme hier nie zustande).
            self.dedup.entry(id).or_insert(rec.offset);
        }
        Ok(())
    }

    /// Baut den in-memory **Bereichs-Zugehörigkeits-Index** (`Daten → { Bereiche }`,
    /// §11.1) vollständig aus dem Log neu (§8.4: Log = Wahrheit). Idempotent.
    /// Setzt voraus, dass die Dedup-Karte bereits gebaut ist (sie löst die
    /// besessenen Kontext-`ContentId`s zu deren Inhalt auf).
    fn rebuild_areas_from_log(&mut self) -> Result<(), KernelError> {
        self.areas.clear();
        let records = self.log.read_all()?;
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            self.index_area_memberships_of(id, &datum)?;
        }
        Ok(())
    }

    /// Trägt die **Bereichs-Zugehörigkeiten** eines Daten `id` (mit Inhalt `datum`)
    /// in den Zugehörigkeits-Index ein (§11.1) — rein **mechanisch** (§1.4): für
    /// jeden besessenen Kontext `K` wird `K`s durabler Inhalt aufgelöst; ist `K`
    /// ein **Zugehörigkeits-Kontext** (`{ Marker, Bereich }`,
    /// [`Datum::area_membership_target`]), gehört `id` dem benannten Bereich an.
    ///
    /// Ein Blatt oder ein Knoten ohne Zugehörigkeits-Kontexte trägt nichts ein.
    /// Ein noch nicht vorhandener Kontext (referenzielle Geschlossenheit erzwingt
    /// die schreibende Schicht, §3.6/§7.2) wird übersprungen — der Kernel
    /// **validiert nicht** (§1.4). Die eingetragene Bereichs-Liste ist aufsteigend
    /// sortiert und dedupliziert (deterministisch, kein Wert-Sort §1.4).
    fn index_area_memberships_of(
        &mut self,
        id: ContentId,
        datum: &Datum,
    ) -> Result<(), KernelError> {
        let owns = match datum.owns() {
            Some(o) => o,
            None => return Ok(()), // Blatt: keine Kontexte, keine Zugehörigkeit.
        };
        let mut found: Vec<ContentId> = Vec::new();
        for ctx_id in owns {
            // Den besessenen Kontext auflösen; fehlt er (Geschlossenheit ist Sache
            // der schreibenden Schicht, §3.6), überspringen — keine Wertung (§1.4).
            let bytes = match self.get_canonical_bytes(*ctx_id)? {
                Some(b) => b,
                None => continue,
            };
            let ctx = strict_decode(&bytes)?;
            if let Some(area) = ctx.area_membership_target() {
                found.push(area);
            }
        }
        if found.is_empty() {
            return Ok(());
        }
        // Aufsteigend + dedupliziert (deterministischer, föderationsstabiler
        // Tiebreak; §5.2/§1.4 — kein Wert-Sort).
        found.sort_unstable();
        found.dedup();
        self.areas.insert(id, found);
        Ok(())
    }

    /// Baut die in-memory **Berechtigungs-Karte** und **Entzugs-Menge** (§11.1/§11.4)
    /// vollständig aus dem Log neu (§8.4: Log = Wahrheit). Idempotent. Setzt voraus,
    /// dass die Dedup-Karte bereits gebaut ist (sie löst die Rollen-Kontexte auf).
    fn rebuild_permissions_from_log(&mut self) -> Result<(), KernelError> {
        self.permissions.clear();
        self.revoked.clear();
        let records = self.log.read_all()?;
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            self.index_permission_or_revocation_of(id, &datum)?;
        }
        Ok(())
    }

    /// Trägt eine **Berechtigung** (§11.1) oder einen **Entzug** (§11.4) eines Daten
    /// `id` (mit Inhalt `datum`) in die jeweiligen Karten ein — rein **mechanisch**
    /// (§1.4). Ein Entzug benennt die `ContentId` der entzogenen Berechtigung; eine
    /// Berechtigung liefert *(Subjekt, Bereich)* über ihre Rollen-Kontexte (deren
    /// Inhalt aus dem Store aufgelöst wird). Ein gewöhnliches Daten trägt nichts ein.
    ///
    /// Reine Reihenfolge-Unabhängigkeit (§6.3/§11.4): ein Entzug, der **vor** seiner
    /// Berechtigung im Log steht, wird trotzdem korrekt verbucht — die Entzugs-Menge
    /// referenziert nur die `ContentId` und [`granted_areas_for_subject`] gleicht
    /// stets gegen sie ab. „Neuester Offset gewinnt" gibt es **nicht** (§Append-
    /// Order-Semantik).
    fn index_permission_or_revocation_of(
        &mut self,
        id: ContentId,
        datum: &Datum,
    ) -> Result<(), KernelError> {
        // Entzug zuerst prüfen (kleinere, eindeutige Struktur).
        if let Some(perm_id) = datum.revocation_target() {
            self.revoked.insert(perm_id);
            return Ok(());
        }
        // Berechtigung: (Subjekt, Bereich) strukturell ablesen. Die Rollen-Kontexte
        // sind besessene Daten, die wir aus dem Store auflösen (Geschlossenheit ist
        // Sache der schreibenden Schicht, §3.6; fehlt einer, liefert die Ablesung
        // None — keine Wertung, §1.4).
        //
        // Der `resolve`-Closure liest die kanonischen Bytes über `&self`; wir sammeln
        // mögliche Lese-Inkonsistenzen separat ein, da der Closure selbst keinen
        // Fehler propagieren kann.
        let mut read_err: Option<KernelError> = None;
        let resolve = |ctx_id: ContentId| -> Option<Datum> {
            match self.get_canonical_bytes(ctx_id) {
                Ok(Some(bytes)) => match strict_decode(&bytes) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        read_err = Some(e);
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    read_err = Some(e);
                    None
                }
            }
        };
        let subject_area = datum.permission_subject_area(resolve);
        if let Some(e) = read_err {
            return Err(e);
        }
        if let Some((subject, area)) = subject_area {
            self.permissions.insert(id, (subject, area));
        }
        Ok(())
    }

    /// Baut den in-memory **Zeit-Aussage-Mitgliedschafts-Index** und **beide
    /// Richtungen des Ersetzungs-Index** (§6.1–§6.3) vollständig aus dem Log neu
    /// (§8.4: Log = Wahrheit). Idempotent. Setzt voraus, dass die Dedup-Karte bereits
    /// gebaut ist (sie löst die besessenen Kontexte zu deren Inhalt auf).
    fn rebuild_time_and_supersession_from_log(&mut self) -> Result<(), KernelError> {
        self.time_carriers.clear();
        self.supersedes.clear();
        self.superseded_by.clear();
        let records = self.log.read_all()?;
        for rec in &records {
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            self.index_time_and_supersession_of(id, &datum)?;
        }
        Ok(())
    }

    /// Trägt die **Zeit-Aussagen** (§6.1/§6.2) und **Ersetzungs-Verknüpfungen**
    /// (§6.3) eines Daten `id` (mit Inhalt `datum`) in die jeweiligen Indizes ein —
    /// rein **mechanisch** (§1.4): für jeden besessenen Kontext `K` wird `K`s durabler
    /// Inhalt aufgelöst; ist `K`
    ///
    /// - eine **Zeit-Aussage** (`{ Achsen-Marker, Zeit-Wert }`,
    ///   [`Datum::recording_time_value`]/[`Datum::validity_time_value`]), trägt `id`
    ///   diese Zeit-Aussage → `time_carriers[K]` += `id` (Mitgliedschafts-Lookup,
    ///   §1.3); der opake Zeit-Wert wird **nie** geparst/geordnet (§1.4/§6.4).
    /// - ein **Ersetzungs-Kontext** (`{ supersession_marker, O }`,
    ///   [`Datum::supersedes_target`]), so überholt `id` (das **neuere**) das benannte
    ///   `O` (das **ältere**, §6.3) → `supersedes[id]` += `O` **und**
    ///   `superseded_by[O]` += `id` (beide Richtungen traversierbar, §1.2).
    ///
    /// Ein Blatt oder ein Knoten ohne solche Kontexte trägt nichts ein. Ein noch
    /// nicht vorhandener Kontext (Geschlossenheit erzwingt die schreibende Schicht,
    /// §3.6/§7.2) wird übersprungen — der Kernel **validiert nicht** (§1.4). Die
    /// eingetragenen Listen sind aufsteigend sortiert + dedupliziert (deterministisch,
    /// kein Wert-Sort §1.4). Der Kernel entscheidet **nicht**, welches Daten „aktuell"
    /// ist (§6.4/§8) — er **verknüpft und indiziert** nur.
    fn index_time_and_supersession_of(
        &mut self,
        id: ContentId,
        datum: &Datum,
    ) -> Result<(), KernelError> {
        let owns = match datum.owns() {
            Some(o) => o,
            None => return Ok(()), // Blatt: keine Kontexte.
        };
        for ctx_id in owns {
            // Den besessenen Kontext auflösen; fehlt er (§3.6 Schreibschicht),
            // überspringen — keine Wertung (§1.4).
            let bytes = match self.get_canonical_bytes(*ctx_id)? {
                Some(b) => b,
                None => continue,
            };
            let ctx = strict_decode(&bytes)?;
            // Zeit-Aussage (beide Achsen sind strukturell distinkt, §6.2): trägt der
            // Kontext eine Achsen-Aussage, ist `id` ein Träger dieser Aussage.
            if ctx.recording_time_value().is_some() || ctx.validity_time_value().is_some() {
                push_sorted_dedup(self.time_carriers.entry(*ctx_id).or_default(), id);
            }
            // Ersetzungs-Kontext (§6.3): `id` (neuer) überholt das benannte `older`.
            if let Some(older) = ctx.supersedes_target() {
                push_sorted_dedup(self.supersedes.entry(id).or_default(), older);
                push_sorted_dedup(self.superseded_by.entry(older).or_default(), id);
            }
        }
        Ok(())
    }

    /// **Versöhnt** den Index mit dem durablen Log-Tail (§8.4-Recovery-
    /// Reconciliation). Watermark `W` vs. committed Log-Offset `T`:
    /// - `W == T` ⇒ in sync, nichts zu tun.
    /// - `W < T` ⇒ Normal-Lag ⇒ Records ab Offset `W` nachspielen, Watermark auf
    ///   `T` setzen.
    /// - `W > T` ⇒ der Index raste einem verlorenen Log-`fsync` voraus ⇒ Index
    ///   ist unsicher ⇒ **voller Neu-Bau** (keine Suffix-Chirurgie, §8.4).
    fn reconcile_index_with_log(&mut self) -> Result<(), KernelError> {
        let w = self.index.watermark()?;
        let t = self.log.committed_offset();
        if w == t {
            return Ok(());
        }
        if w > t {
            // Index lief dem Log voraus → komplett neu bauen.
            return self.rebuild_index_from_log();
        }
        // w < t: nur die Records ab Offset `w` nachspielen.
        let records = self.log.read_all()?;
        let mut edges: Vec<Edge> = Vec::new();
        for rec in &records {
            if rec.offset < w {
                continue;
            }
            let datum = strict_decode(&rec.payload)?;
            let id = ContentId::of_datum(&datum);
            edges.extend(edges_of(id, &datum));
        }
        self.index.commit_edges(&edges, t)?;
        self.metrics.edge_count = self.metrics.edge_count.saturating_add(edges.len() as u64);
        Ok(())
    }
}

/// Fügt `id` in eine aufsteigend sortierte, duplikat-freie `ContentId`-Liste ein
/// (Adress-Order, **kein** Wert-Sort §1.4) — die Invariante der in-memory
/// Lookup-Indizes (deterministischer, föderationsstabiler Tiebreak; §5.2). Ein
/// bereits vorhandenes `id` lässt die Liste unverändert (Mengen-Semantik).
fn push_sorted_dedup(list: &mut Vec<ContentId>, id: ContentId) {
    if let Err(pos) = list.binary_search(&id) {
        list.insert(pos, id);
    }
}

/// Die abgeleiteten **Kanten** eines Daten (§3.2): für einen besitzenden Knoten
/// `A` mit `owns = { K_1, …, K_n }` je eine Kante `A ⊳ K_i`. Ein Blatt hat
/// **keine** Kanten (es besitzt nichts, §K2.1).
///
/// Reines mechanisches Ableiten (§1.4): es wird nichts gewertet, nichts
/// validiert — die `owns`-Menge ist schon kanonisch sortiert/dedupliziert
/// (§K2.3).
fn edges_of(owner: ContentId, datum: &Datum) -> Vec<Edge> {
    match datum.owns() {
        Some(owns) => owns
            .iter()
            .map(|ctx| Edge {
                owner,
                context: *ctx,
            })
            .collect(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::RedbEdgeIndex;
    use tempfile::tempdir;

    /// Baut einen frischen Store (Log + redb-Index) in `dir`.
    fn open_store(dir: &std::path::Path) -> ContentStore<RedbEdgeIndex> {
        let log_dir = dir.join("log");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let log = SegmentLog::open(&log_dir).expect("log");
        let index = RedbEdgeIndex::open(dir.join("index.redb")).expect("index");
        ContentStore::open(log, index).expect("store")
    }

    #[test]
    fn append_two_data_owner_and_referrer_edges() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // B ist ein Blatt; A ist ein Knoten, der B besitzt.
        let b = Datum::leaf(b"target".to_vec());
        let b_id = store.append_datum(&b).unwrap();
        let a = Datum::node([b_id]).unwrap();
        let a_id = store.append_datum(&a).unwrap();

        // owner(A) → B und referrer(B) → A.
        assert_eq!(store.index().contexts_of(a_id).unwrap(), vec![b_id]);
        assert_eq!(store.index().referrers_of(b_id).unwrap(), vec![a_id]);
        // Beide Daten sind durabel lesbar.
        assert_eq!(store.get_by_content_id(b_id).unwrap(), Some(b));
        assert_eq!(store.get_by_content_id(a_id).unwrap(), Some(a));
    }

    #[test]
    fn append_returns_stable_content_id_and_get_round_trips() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = Datum::leaf(b"lakearch".to_vec());
        let id = store.append_datum(&d).unwrap();
        // §K5: die zurückgegebene ID ist die ContentId des Daten.
        assert_eq!(id, ContentId::of_datum(&d));
        // §5.2-Fetch: kanonische Bytes round-trippen.
        assert_eq!(
            store.get_canonical_bytes(id).unwrap(),
            Some(canonical_cbor(&d))
        );
        assert_eq!(store.get_by_content_id(id).unwrap(), Some(d));
        // Unbekannte ID ⇒ None (kein Panik, kein Orakel auf dieser Ebene).
        assert_eq!(
            store.get_by_content_id(ContentId::from_bytes([0xFE; 32])).unwrap(),
            None
        );
    }

    // ------------------------------------------------------------------------
    // Dedup (§5.3): zweimal dasselbe Daten ⇒ EIN Record; Log-Länge unverändert,
    // Dedup-Zähler erhöht, keine seq verbraucht.
    // ------------------------------------------------------------------------

    #[test]
    fn dedup_writes_one_record_and_counts_the_hit() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let d = Datum::leaf(b"einmalig".to_vec());

        let id1 = store.append_datum(&d).unwrap();
        let log_after_first = store.log_metrics();
        let committed_after_first = store.log_metrics().committed_bytes;

        // Zweites identisches append: KEIN Record, KEINE seq, Dedup-Treffer.
        let id2 = store.append_datum(&d).unwrap();
        assert_eq!(id1, id2, "inhaltsgleich ⇒ dieselbe ContentId (§5.3)");

        let log_after_second = store.log_metrics();
        // Log-Länge unverändert.
        assert_eq!(
            committed_after_first, log_after_second.committed_bytes,
            "Dedup-Treffer schreibt nichts (Log-Länge unverändert, §5.3)"
        );
        // Genau ein physischer Record / eine seq.
        assert_eq!(log_after_first.append_count, 1);
        assert_eq!(log_after_second.append_count, 1);
        // Store-Metriken: ein Append, ein Dedup-Treffer.
        assert_eq!(store.metrics().append_count, 1);
        assert_eq!(store.metrics().dedup_hit_count, 1);
        assert_eq!(store.len(), 1, "genau ein distinktes Daten");
    }

    // ------------------------------------------------------------------------
    // Watermark schreitet monoton voran (über mehrere Appends).
    // ------------------------------------------------------------------------

    #[test]
    fn watermark_advances_monotonically_over_appends() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let mut last = store.index().watermark().unwrap();
        assert_eq!(last, 0);
        for i in 0..5u8 {
            store.append_datum(&Datum::leaf(vec![i])).unwrap();
            let w = store.index().watermark().unwrap();
            assert!(w >= last, "Watermark nicht-fallend (§8.4)");
            // Nach jedem neuen Record ist das Watermark = committed Log-Offset.
            assert_eq!(w, store.log_metrics().committed_bytes);
            last = w;
        }
        assert!(last > 0);
    }

    // ------------------------------------------------------------------------
    // WIPE-AND-REBUILD (§8.4): Index löschen, aus dem Log neu bauen ⇒ identischer
    // Inhalt (operationalisiert „Log = alleinige Wahrheit").
    // ------------------------------------------------------------------------

    #[test]
    fn wipe_and_rebuild_is_identical() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // Ein kleiner Graph: drei Blätter, ein Knoten der zwei besitzt, ein Knoten
        // der den Knoten besitzt (Reifikation, §3.4) — beide Richtungen entstehen.
        let l1 = store.append_datum(&Datum::leaf(b"l1".to_vec())).unwrap();
        let l2 = store.append_datum(&Datum::leaf(b"l2".to_vec())).unwrap();
        let l3 = store.append_datum(&Datum::leaf(b"l3".to_vec())).unwrap();
        let n1 = store.append_datum(&Datum::node([l1, l2]).unwrap()).unwrap();
        let _n2 = store.append_datum(&Datum::node([n1, l3]).unwrap()).unwrap();

        // Schnappschuss aller owner→contexts UND target→referrers VOR dem Wipe.
        let all_ids = [l1, l2, l3, n1, _n2];
        let before: Vec<(Vec<ContentId>, Vec<ContentId>)> = all_ids
            .iter()
            .map(|id| {
                (
                    store.index().contexts_of(*id).unwrap(),
                    store.index().referrers_of(*id).unwrap(),
                )
            })
            .collect();
        let wm_before = store.index().watermark().unwrap();

        // Wipe + Neu-Bau aus dem Log.
        store.rebuild_index_from_log().unwrap();

        let after: Vec<(Vec<ContentId>, Vec<ContentId>)> = all_ids
            .iter()
            .map(|id| {
                (
                    store.index().contexts_of(*id).unwrap(),
                    store.index().referrers_of(*id).unwrap(),
                )
            })
            .collect();
        assert_eq!(before, after, "neu gebauter Index ist identisch (§8.4)");
        // Watermark wieder am durablen Log-Tail.
        assert_eq!(store.index().watermark().unwrap(), wm_before);
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reopen: nach Crash/Neustart ist der Store (Dedup + Index) konsistent mit dem
    // Log — Reconciliation versöhnt das Watermark, ohne Suffix-Chirurgie.
    // ------------------------------------------------------------------------

    #[test]
    fn reopen_recovers_store_consistent_with_log() {
        let dir = tempdir().unwrap();
        let l1;
        let n1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"persist".to_vec())).unwrap();
            n1 = store.append_datum(&Datum::node([l1]).unwrap()).unwrap();
        }
        // Reopen Log + Index (beide durabel) → Store rekonstruiert Dedup + versöhnt
        // den Index.
        let store = open_store(dir.path());
        assert!(store.contains(l1));
        assert!(store.contains(n1));
        assert_eq!(store.len(), 2);
        // Kanten sind nach Reopen unverändert.
        assert_eq!(store.index().contexts_of(n1).unwrap(), vec![l1]);
        assert_eq!(store.index().referrers_of(l1).unwrap(), vec![n1]);
        // Watermark ist nach Reopen = durabler Log-Tail (W == T, in sync).
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reconciliation: ein Index, der dem Log NACHHÄNGT (W < T), wird beim Öffnen
    // nachgespielt — OHNE Wipe (Normal-Lag).
    // ------------------------------------------------------------------------

    #[test]
    fn lagging_index_is_replayed_on_open() {
        let dir = tempdir().unwrap();
        // Erst Daten ins LOG schreiben, den Index aber NICHT mit-pflegen, um Lag
        // zu simulieren: wir öffnen einen Store, hängen an, und löschen dann den
        // Index per Wipe (W → 0), während das Log seine Records behält.
        let l1;
        let n1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"a".to_vec())).unwrap();
            n1 = store.append_datum(&Datum::node([l1]).unwrap()).unwrap();
            // Index künstlich auf 0 zurücksetzen (simuliert verlorenen Index-Tail).
            store.index.wipe().unwrap();
            assert_eq!(store.index().watermark().unwrap(), 0);
            assert!(store.index().contexts_of(n1).unwrap().is_empty());
        }
        // Reopen: W (0) < T ⇒ Reconciliation spielt den ganzen Log nach.
        let store = open_store(dir.path());
        assert_eq!(store.index().contexts_of(n1).unwrap(), vec![l1]);
        assert_eq!(store.index().referrers_of(l1).unwrap(), vec![n1]);
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Reconciliation: ein Index, der dem Log VORAUSEILT (W > T), wird voll neu
    // gebaut (keine Suffix-Chirurgie, §8.4).
    // ------------------------------------------------------------------------

    #[test]
    fn index_ahead_of_log_triggers_full_rebuild() {
        let dir = tempdir().unwrap();
        let l1;
        {
            let mut store = open_store(dir.path());
            l1 = store.append_datum(&Datum::leaf(b"only".to_vec())).unwrap();
            // Index künstlich VORAUS setzen (W > committed Log-Offset), als ob ein
            // Index-Commit einem verlorenen Log-fsync vorausraste.
            let t = store.log_metrics().committed_bytes;
            store.index.commit_edges(&[], t + 10_000).unwrap();
            assert!(store.index().watermark().unwrap() > t);
        }
        // Reopen: W > T ⇒ voller Neu-Bau; Watermark wieder am Log-Tail, Inhalt korrekt.
        let store = open_store(dir.path());
        assert!(store.contains(l1));
        assert_eq!(
            store.index().watermark().unwrap(),
            store.log_metrics().committed_bytes
        );
    }

    // ------------------------------------------------------------------------
    // Bereichs-Zugehörigkeits-Index (§11.1): ein Daten mit Zugehörigkeits-Kontext
    // wird dem Bereich zugeordnet; geprüfte Bereiche stimmen mit der durablen
    // Wahrheit überein.
    // ------------------------------------------------------------------------

    #[test]
    fn area_membership_is_indexed_and_checked() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let area = store.append_datum(&Datum::leaf(b"area".to_vec())).unwrap();
        let _marker = store.append_datum(&Datum::area_membership_marker()).unwrap();
        let membership = store.append_datum(&Datum::area_membership(area)).unwrap();
        let secret = store.append_datum(&Datum::node([membership]).unwrap()).unwrap();
        let public = store.append_datum(&Datum::leaf(b"public".to_vec())).unwrap();

        assert_eq!(store.areas_of(secret), vec![area]);
        assert_eq!(store.areas_of_checked(secret).unwrap(), vec![area]);
        // Ein unbeschränktes Daten hat keine Bereiche (Policy-Default).
        assert!(store.areas_of(public).is_empty());
        assert!(store.areas_of_checked(public).unwrap().is_empty());
    }

    // ------------------------------------------------------------------------
    // FAIL-CLOSED bei korruptem Bereichs-Index (§11): weicht der gecachte
    // Bereichs-Index von der durablen Wahrheit ab, verweigert `areas_of_checked`
    // mit `Inconsistent` (DENY) + Fail-closed-Metrik — statt eine unsichere
    // (leckende) Sicht zu liefern.
    // ------------------------------------------------------------------------

    #[test]
    fn corrupt_scope_index_fails_closed_with_metric() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let area = store.append_datum(&Datum::leaf(b"area".to_vec())).unwrap();
        let _marker = store.append_datum(&Datum::area_membership_marker()).unwrap();
        let membership = store.append_datum(&Datum::area_membership(area)).unwrap();
        let secret = store.append_datum(&Datum::node([membership]).unwrap()).unwrap();

        // Vorher konsistent, kein Fail-closed.
        assert_eq!(store.areas_of_checked(secret).unwrap(), vec![area]);
        assert_eq!(store.metrics().fail_closed_count, 0);

        // Korruptions-Szenario 1: der Index sagt fälschlich „unbeschränkt" (leere
        // Bereiche), obwohl das Daten durabel dem Bereich angehört → würde lecken.
        store.corrupt_area_cache(secret, vec![]);
        assert!(matches!(
            store.areas_of_checked(secret),
            Err(KernelError::Inconsistent)
        ));
        assert_eq!(store.metrics().fail_closed_count, 1, "Fail-closed gezählt (§11)");

        // Korruptions-Szenario 2: der Index nennt einen falschen Bereich.
        store.corrupt_area_cache(secret, vec![ContentId::from_bytes([0x99; 32])]);
        assert!(matches!(
            store.areas_of_checked(secret),
            Err(KernelError::Inconsistent)
        ));
        assert_eq!(store.metrics().fail_closed_count, 2);
    }

    // ------------------------------------------------------------------------
    // Berechtigung & Entzug (§11.1/§11.4): gewährte Bereiche eines Subjekts werden
    // aus aktiven (nicht entzogenen) Berechtigungen abgeleitet; ein Entzug verbirgt
    // den Bereich für künftige Ableitungen (strukturell, kein Wall-Clock §11.5).
    // ------------------------------------------------------------------------

    /// Hängt eine vollständige Berechtigung (Rollen-Kontexte + Marker + Knoten) an
    /// den Store und liefert ihre `ContentId`.
    fn append_permission(
        store: &mut ContentStore<RedbEdgeIndex>,
        subject: ContentId,
        area: ContentId,
    ) -> ContentId {
        store.append_datum(&Datum::permission_subject_marker()).unwrap();
        store.append_datum(&Datum::permission_area_marker()).unwrap();
        store.append_datum(&Datum::permission_marker()).unwrap();
        store.append_datum(&Datum::permission_subject_role(subject)).unwrap();
        store.append_datum(&Datum::permission_area_role(area)).unwrap();
        store.append_datum(&Datum::permission(subject, area)).unwrap()
    }

    #[test]
    fn granted_areas_derive_from_active_permissions() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let subject = store.append_datum(&Datum::leaf(b"subject".to_vec())).unwrap();
        let area1 = store.append_datum(&Datum::leaf(b"area-1".to_vec())).unwrap();
        let area2 = store.append_datum(&Datum::leaf(b"area-2".to_vec())).unwrap();

        let _p1 = append_permission(&mut store, subject, area1);
        let _p2 = append_permission(&mut store, subject, area2);

        let mut granted = store.granted_areas_for_subject(subject);
        granted.sort_unstable();
        let mut expected = vec![area1, area2];
        expected.sort_unstable();
        assert_eq!(granted, expected, "beide aktiven Bereiche gewährt (§11.1)");

        // Ein fremdes Subjekt bekommt nichts.
        let other = store.append_datum(&Datum::leaf(b"other".to_vec())).unwrap();
        assert!(store.granted_areas_for_subject(other).is_empty());
    }

    #[test]
    fn revocation_hides_area_from_future_authorizations() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let subject = store.append_datum(&Datum::leaf(b"subject".to_vec())).unwrap();
        let area = store.append_datum(&Datum::leaf(b"area".to_vec())).unwrap();
        let perm = append_permission(&mut store, subject, area);

        // Vor dem Entzug: der Bereich ist gewährt.
        assert_eq!(store.granted_areas_for_subject(subject), vec![area]);

        // Entzug anhängen (§11.4): künftige Ableitungen filtern die Berechtigung.
        store.append_datum(&Datum::revocation_marker()).unwrap();
        store.append_datum(&Datum::revocation(perm)).unwrap();

        // Nach dem Entzug: der Bereich ist nicht mehr gewährt (strukturell, §11.5).
        assert!(
            store.granted_areas_for_subject(subject).is_empty(),
            "Entzug verbirgt den Bereich künftiger Lesevorgänge (§11.4)"
        );
    }

    #[test]
    fn revocation_before_permission_in_log_still_filters() {
        // §6.3/§11.4-Reihenfolge-Unabhängigkeit: ein Entzug, der VOR seiner
        // Berechtigung im Log steht (etwa nach Neu-Aufbau), filtert trotzdem —
        // „neuester Offset gewinnt" gibt es nicht (§Append-Order-Semantik).
        let dir = tempdir().unwrap();
        let subject;
        let area;
        let perm_id;
        {
            let mut store = open_store(dir.path());
            subject = store.append_datum(&Datum::leaf(b"subj".to_vec())).unwrap();
            area = store.append_datum(&Datum::leaf(b"ar".to_vec())).unwrap();
            // Berechtigungs-ID vorab berechnen, um den Entzug ZUERST anzuhängen.
            perm_id = ContentId::of_datum(&Datum::permission(subject, area));
            store.append_datum(&Datum::revocation_marker()).unwrap();
            store.append_datum(&Datum::revocation(perm_id)).unwrap();
            // Erst danach die Berechtigung selbst.
            let actual = append_permission(&mut store, subject, area);
            assert_eq!(actual, perm_id);
            assert!(store.granted_areas_for_subject(subject).is_empty());
        }
        // Auch nach Reopen (Neu-Aufbau der Karten aus dem Log) bleibt sie gefiltert.
        let store = open_store(dir.path());
        assert!(store.granted_areas_for_subject(subject).is_empty());
    }

    #[test]
    fn leaf_has_no_edges() {
        // Ein Blatt besitzt nichts ⇒ keine Kanten in keiner Richtung (§K2.1).
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());
        let id = store.append_datum(&Datum::leaf(b"atom".to_vec())).unwrap();
        assert!(store.index().contexts_of(id).unwrap().is_empty());
        assert!(store.index().referrers_of(id).unwrap().is_empty());
        assert_eq!(store.metrics().edge_count, 0);
    }

    // ------------------------------------------------------------------------
    // Platzhalter-Auflösung (§3.6 + §6.3): das echte Daten ersetzt den
    // Platzhalter; die Verknüpfung Platzhalter↔real ist über die bestehenden
    // Indizes in BEIDE Richtungen traversierbar (append-only, der Platzhalter
    // bleibt unverändert lesbar, §7.1).
    // ------------------------------------------------------------------------

    #[test]
    fn placeholder_is_resolvable_and_traversable_both_directions() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // Ein Platzhalter wird angehängt (er ist als unaufgelöst markiert, §3.6).
        let placeholder = Datum::placeholder([]);
        let placeholder_id = store.append_datum(&placeholder).unwrap();
        // Der Platzhalter ist strukturell als solcher erkennbar.
        assert!(store
            .get_by_content_id(placeholder_id)
            .unwrap()
            .unwrap()
            .is_placeholder());

        // Das echte Ziel trifft ein und löst den Platzhalter auf (§6.3).
        let real = Datum::leaf(b"echtes-ziel".to_vec());
        let (real_id, resolution_id) =
            store.resolve_placeholder(placeholder_id, &real).unwrap();
        assert_eq!(real_id, ContentId::of_datum(&real));

        // Append-only: der Platzhalter ist NIE geändert/gelöscht (§7.1) — weiterhin
        // unverändert lesbar.
        assert_eq!(
            store.get_by_content_id(placeholder_id).unwrap(),
            Some(placeholder)
        );

        // Der Ersetzungs-Kontext zeigt vom Auflösungs-Knoten auf den Platzhalter.
        let supersedes_ctx = Datum::supersedes(placeholder_id);
        let supersedes_ctx_id = ContentId::of_datum(&supersedes_ctx);
        let supersession_marker_id = ContentId::of_datum(&Datum::supersession_marker());
        // Der Ersetzungs-Kontext liest strukturell den Platzhalter (das ÄLTERE) ab.
        assert_eq!(supersedes_ctx.supersedes_target(), Some(placeholder_id));

        // BEIDE Richtungen über die bestehenden Indizes (§1.2/§10.3):
        // Vorwärts: Auflösungs-Knoten besitzt { real, supersedes_ctx }.
        let mut fwd = store.index().contexts_of(resolution_id).unwrap();
        fwd.sort_unstable();
        let mut expected = vec![real_id, supersedes_ctx_id];
        expected.sort_unstable();
        assert_eq!(fwd, expected);
        // supersedes_ctx besitzt { supersession_marker, placeholder } (vorwärts);
        // der strukturell bedeutsame Verweis ist der Platzhalter (s. o.).
        let mut sup_fwd = store.index().contexts_of(supersedes_ctx_id).unwrap();
        sup_fwd.sort_unstable();
        let mut sup_expected = vec![supersession_marker_id, placeholder_id];
        sup_expected.sort_unstable();
        assert_eq!(sup_fwd, sup_expected);
        // Rückwärts vom Platzhalter: Platzhalter ← supersedes_ctx ← Auflösungs-Knoten
        // → real. So ist der auflösende Pfad vom Platzhalter erreichbar (§3.6).
        assert_eq!(
            store.index().referrers_of(placeholder_id).unwrap(),
            vec![supersedes_ctx_id]
        );
        assert_eq!(
            store.index().referrers_of(supersedes_ctx_id).unwrap(),
            vec![resolution_id]
        );

        // Wipe-&-Rebuild (§8.4): die Ersetzungs-/Zeit-Verknüpfungen sind reine
        // Derivate über die Kanten-Indizes — neu gebaut identisch.
        let before_fwd = store.index().contexts_of(resolution_id).unwrap();
        let before_bwd = store.index().referrers_of(placeholder_id).unwrap();
        store.rebuild_index_from_log().unwrap();
        assert_eq!(store.index().contexts_of(resolution_id).unwrap(), before_fwd);
        assert_eq!(
            store.index().referrers_of(placeholder_id).unwrap(),
            before_bwd
        );
    }

    // ------------------------------------------------------------------------
    // Zeit als Daten (§6.1/§6.2): die zwei Achsen-Aussagen eines Daten werden als
    // gewöhnliche Kanten indiziert (reine Derivate, §8.4) — der Kernel ordnet/
    // vergleicht den opaken Zeit-Wert NIE (§1.4/§6.4).
    // ------------------------------------------------------------------------

    #[test]
    fn both_time_axes_round_trip_as_ordinary_edges() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        // Zwei opake Zeit-Werte (gewöhnliche Blätter); divergierende Achsen (§6.2).
        let t_rec = store.append_datum(&Datum::leaf(b"erfahren@T1".to_vec())).unwrap();
        let t_val = store.append_datum(&Datum::leaf(b"gilt@T0".to_vec())).unwrap();
        store.append_datum(&Datum::recording_time_marker()).unwrap();
        store.append_datum(&Datum::validity_time_marker()).unwrap();
        let rec_stmt = store.append_datum(&Datum::recording_time(t_rec)).unwrap();
        let val_stmt = store.append_datum(&Datum::validity_time(t_val)).unwrap();

        // Ein Daten, das BEIDE Achsen trägt.
        let fact = store
            .append_datum(&Datum::node([rec_stmt, val_stmt]).unwrap())
            .unwrap();

        // Beide Aussagen sind als Vorwärts-Kanten am Daten vorhanden.
        let mut ctxs = store.index().contexts_of(fact).unwrap();
        ctxs.sort_unstable();
        let mut expected = vec![rec_stmt, val_stmt];
        expected.sort_unstable();
        assert_eq!(ctxs, expected, "beide Zeitachsen als gewöhnliche Kanten (§6.2)");

        // Die Aussage-Daten zeigen strukturell auf ihre opaken Zeit-Werte — der
        // Kernel parst/vergleicht sie NICHT (§1.4/§6.4).
        let rec = store.get_by_content_id(rec_stmt).unwrap().unwrap();
        let val = store.get_by_content_id(val_stmt).unwrap().unwrap();
        assert_eq!(rec.recording_time_value(), Some(t_rec));
        assert_eq!(val.validity_time_value(), Some(t_val));
        // Die Achsen sind distinkt/unabhängig (verschiedene Werte, §6.2).
        assert_ne!(t_rec, t_val);
        assert_ne!(rec_stmt, val_stmt);
    }

    // ------------------------------------------------------------------------
    // Zeit-Aussage-Mitgliedschafts-Index (§6.1/§6.2, §8.4): der LOOKUP liefert die
    // Daten, die eine gegebene Zeit-Aussage tragen — Exakt-Match/Mitgliedschaft
    // (§1.3), KEINE Ordnung (§1.4/§6.4).
    // ------------------------------------------------------------------------

    #[test]
    fn time_statement_membership_lookup_returns_carriers() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        let t1 = store.append_datum(&Datum::leaf(b"t1".to_vec())).unwrap();
        let t2 = store.append_datum(&Datum::leaf(b"t2".to_vec())).unwrap();
        store.append_datum(&Datum::recording_time_marker()).unwrap();
        store.append_datum(&Datum::validity_time_marker()).unwrap();
        let rec_t1 = store.append_datum(&Datum::recording_time(t1)).unwrap();
        let val_t2 = store.append_datum(&Datum::validity_time(t2)).unwrap();

        // Zwei Daten tragen dieselbe Aufzeichnungszeit-Aussage (rec_t1).
        let a = store.append_datum(&Datum::node([rec_t1]).unwrap()).unwrap();
        let payload_b = store.append_datum(&Datum::leaf(b"b-fact".to_vec())).unwrap();
        let b = store.append_datum(&Datum::node([rec_t1, payload_b]).unwrap()).unwrap();
        // Ein drittes trägt die Gültigkeitszeit-Aussage (val_t2).
        let c = store.append_datum(&Datum::node([val_t2]).unwrap()).unwrap();

        // Lookup nach der Aussage rec_t1 ⇒ genau {a, b} (Exakt-Match, §1.3).
        let mut carriers = store.time_carriers_of(rec_t1);
        carriers.sort_unstable();
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(carriers, expected, "Träger der Aufzeichnungszeit-Aussage");
        // Lookup nach val_t2 ⇒ {c}; die Achsen sind distinkt (§6.2).
        assert_eq!(store.time_carriers_of(val_t2), vec![c]);
        // Eine nie getragene Aussage ⇒ leer (keine Ordnung, kein „nächstgelegen").
        let unused_stmt = ContentId::of_datum(&Datum::recording_time(t2));
        assert!(store.time_carriers_of(unused_stmt).is_empty());
    }

    // ------------------------------------------------------------------------
    // Ersetzungs-Index in BEIDE Richtungen (§6.3, §8.4): supersedes (neuer→älter)
    // und superseded-by (älter→neuer); der Kernel verknüpft nur, ordnet nicht.
    // ------------------------------------------------------------------------

    #[test]
    fn supersession_index_is_traversable_both_directions() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path());

        let older = store.append_datum(&Datum::leaf(b"v1".to_vec())).unwrap();
        store.append_datum(&Datum::supersession_marker()).unwrap();
        let sup_ctx = store.append_datum(&Datum::supersedes(older)).unwrap();
        let payload = store.append_datum(&Datum::leaf(b"v2".to_vec())).unwrap();
        // Das neuere Daten besitzt den Ersetzungs-Kontext (§6.3).
        let newer = store.append_datum(&Datum::node([sup_ctx, payload]).unwrap()).unwrap();

        // Vorwärts: newer supersedes older.
        assert_eq!(store.supersedes_of(newer), vec![older]);
        // Rückwärts: older superseded-by newer.
        assert_eq!(store.superseded_by_of(older), vec![newer]);
        // Eine Kette: newer2 überholt newer.
        let sup_ctx2 = store.append_datum(&Datum::supersedes(newer)).unwrap();
        let p2 = store.append_datum(&Datum::leaf(b"v3".to_vec())).unwrap();
        let newer2 = store.append_datum(&Datum::node([sup_ctx2, p2]).unwrap()).unwrap();
        assert_eq!(store.supersedes_of(newer2), vec![newer]);
        assert_eq!(store.superseded_by_of(newer), vec![newer2]);
        // Append-only: das Älteste bleibt unverändert lesbar (§7.1).
        assert_eq!(
            store.get_by_content_id(older).unwrap(),
            Some(Datum::leaf(b"v1".to_vec()))
        );
    }

    // ------------------------------------------------------------------------
    // WIPE-AND-REBUILD der Zeit-/Ersetzungs-Indizes (§8.4): nach Wipe + Neu-Bau aus
    // dem Log sind beide reine Derivate identisch — UND sie überstehen einen Reopen.
    // ------------------------------------------------------------------------

    #[test]
    fn time_and_supersession_survive_wipe_rebuild_and_reopen() {
        let dir = tempdir().unwrap();
        let (rec_stmt, carrier, older, newer);
        {
            let mut store = open_store(dir.path());
            let t = store.append_datum(&Datum::leaf(b"T".to_vec())).unwrap();
            store.append_datum(&Datum::recording_time_marker()).unwrap();
            rec_stmt = store.append_datum(&Datum::recording_time(t)).unwrap();
            carrier = store.append_datum(&Datum::node([rec_stmt]).unwrap()).unwrap();

            older = store.append_datum(&Datum::leaf(b"alt".to_vec())).unwrap();
            store.append_datum(&Datum::supersession_marker()).unwrap();
            let sup = store.append_datum(&Datum::supersedes(older)).unwrap();
            let p = store.append_datum(&Datum::leaf(b"neu".to_vec())).unwrap();
            newer = store.append_datum(&Datum::node([sup, p]).unwrap()).unwrap();

            // Schnappschuss vor dem Wipe.
            let tc_before = store.time_carriers_of(rec_stmt);
            let sup_before = store.supersedes_of(newer);
            let supby_before = store.superseded_by_of(older);

            // Wipe + Neu-Bau aller Derivate aus dem Log (§8.4).
            store.rebuild_index_from_log().unwrap();

            assert_eq!(store.time_carriers_of(rec_stmt), tc_before, "Zeit-Index identisch");
            assert_eq!(store.supersedes_of(newer), sup_before, "supersedes identisch");
            assert_eq!(store.superseded_by_of(older), supby_before, "superseded-by identisch");
            assert_eq!(tc_before, vec![carrier]);
            assert_eq!(sup_before, vec![older]);
            assert_eq!(supby_before, vec![newer]);
        }
        // Reopen von Platte: die Indizes werden aus dem Log rekonstruiert (§8.4).
        let store = open_store(dir.path());
        assert_eq!(store.time_carriers_of(rec_stmt), vec![carrier]);
        assert_eq!(store.supersedes_of(newer), vec![older]);
        assert_eq!(store.superseded_by_of(older), vec![newer]);
    }
}
