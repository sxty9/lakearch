//! Die **gRPC-Service-Implementierung** des Daemons — der Netz-Rand, der die
//! Kernel-Primitive (§1.4/§14.2) durchs **Tor** (§11) bedient.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§5.2/§7.1/§1.3/§1.2/§10.3
//! Primitive; §11 das Tor) und der Plan (Trust-Modell: der Daemon ist die Grenze,
//! das Tor läuft auf **jeder** Anfrage).
//!
//! ## Gate auf jeder Anfrage (§11)
//!
//! Jede lesende RPC trägt ein **Subjekt** ([`proto::Subject`]). Der Daemon leitet
//! daraus — strukturell aus den aktiven Berechtigungen im Snapshot (§11.2) — die
//! gewährten Bereiche ab ([`lakearch_core::LakearchKernel::authorize_subject`])
//! und liest **gegated**: nicht sichtbare Daten **VANISHen** (ununterscheidbar von
//! „nicht vorhanden", §11.3), Index-/Log-Inkonsistenz ⇒ **fail-closed** (DENY).
//! Ein **leeres** Subjekt ⇒ keine gewährten Bereiche (nur unbeschränkte Daten
//! sichtbar — fail-safe, kein Leck ohne Recht).
//!
//! ## Kein Rechnen am Rand (§1.4/§14.2)
//!
//! Der Rand reicht **nur** durch: er sortiert/aggregiert/rankt **nichts**.
//! Traversier-Schritte kommen in der vom Kernel bestimmten aufsteigenden
//! `ContentId`-Adress-Order (§5.2/§1.4); der Rand ordnet sie **nicht** um.

use lakearch_core::{
    Capability, ContentId, Datum, Direction, GrantedScopes, KernelError, SnapshotToken,
};
use tonic::{Request, Response, Status};

use crate::bestand::{Bestand, Kernel};
use crate::proto::lakearch_server::Lakearch;
use crate::proto::{
    AppendRequest, AppendResponse, BoolResponse, ContentEqualRequest, ContextPointsToRequest,
    FindDependentsRequest, GetRequest, GetResponse, IsMemberOfSetRequest, Step as ProtoStep,
    StepList, Subject, TraverseRequest,
};

/// Die gRPC-Service-Implementierung über **einem** [`Bestand`].
pub struct LakearchService {
    bestand: Bestand,
}

impl LakearchService {
    /// Baut den Service über einem geöffneten [`Bestand`].
    pub fn new(bestand: Bestand) -> Self {
        LakearchService { bestand }
    }
}

// ---------------------------------------------------------------------------
// Konvertierungen Wire → Kernel. Reine Form-Umsetzung (§14.2) — keine Wertung.
// ---------------------------------------------------------------------------

/// Eine rohe 32-Byte-Wire-ID in eine [`ContentId`] umsetzen. Eine falsche Länge
/// ist ein **Client-Formfehler** (`InvalidArgument`) — der Kernel sieht **nie**
/// eine ungültige Adresse.
fn content_id_from_wire(bytes: &[u8]) -> Result<ContentId, Status> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("ContentId muss genau 32 Byte lang sein (§5.2)"))?;
    Ok(ContentId::from_bytes(arr))
}

/// Ein optionales Wire-[`Datum`] in ein Kernel-[`Datum`] umsetzen. `leaf` ⇒
/// atomares Blatt; `node` ⇒ besitzender Knoten (der Kernel kanonisiert/sortiert).
/// Eine leere Knoten-Menge ist nicht wohlgeformt (§K2.1) ⇒ `InvalidArgument`.
fn datum_from_wire(d: Option<crate::proto::Datum>) -> Result<Datum, Status> {
    let d = d.ok_or_else(|| Status::invalid_argument("AppendRequest ohne Datum"))?;
    let kind = d
        .kind
        .ok_or_else(|| Status::invalid_argument("Datum ohne kind (leaf|node)"))?;
    match kind {
        crate::proto::datum::Kind::Leaf(bytes) => Ok(Datum::leaf(bytes)),
        crate::proto::datum::Kind::Node(node) => {
            let mut ids = Vec::with_capacity(node.context_ids.len());
            for raw in &node.context_ids {
                ids.push(content_id_from_wire(raw)?);
            }
            Datum::node(ids).ok_or_else(|| {
                Status::invalid_argument("Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1)")
            })
        }
    }
}

/// Die **Richtung** der Wire-Enum in die Kernel-[`Direction`] umsetzen.
/// `UNSPECIFIED` ⇒ `Forward` (Default).
fn direction_from_wire(dir: i32) -> Direction {
    match crate::proto::Direction::try_from(dir) {
        Ok(crate::proto::Direction::Backward) => Direction::Backward,
        Ok(crate::proto::Direction::Both) => Direction::Both,
        // FORWARD und UNSPECIFIED ⇒ Forward.
        _ => Direction::Forward,
    }
}

/// Einen Kernel-[`lakearch_core::Step`] in die Wire-Form umsetzen.
fn step_to_wire(s: &lakearch_core::Step) -> ProtoStep {
    ProtoStep {
        from: s.from.as_bytes().to_vec(),
        edge_ctx: s.edge_ctx.as_bytes().to_vec(),
        to: s.to.as_bytes().to_vec(),
        depth: s.depth,
    }
}

/// Einen [`KernelError`] in einen gRPC-[`Status`] umsetzen — **sichtbarkeits-blind**
/// (§11.3): die Texte nennen **keine** konkreten Daten/IDs/Bereiche. Fail-closed
/// (§11): jede Inkonsistenz/Vergiftung ist ein Fehler, **nie** ein stilles
/// Teilergebnis.
fn status_from_kernel_error(e: KernelError) -> Status {
    match e {
        KernelError::NotYetImplemented(_) => Status::unimplemented("Verb noch nicht implementiert"),
        KernelError::TraversalBudgetExceeded => {
            // Beschränkte Traversierung (§1.7 a): Budget überschritten.
            Status::resource_exhausted("Traversierungs-Budget überschritten (§1.7 a)")
        }
        KernelError::Cancelled => Status::cancelled("Traversierung abgebrochen"),
        // Korruption/Inkonsistenz/Vergiftung/IO ⇒ fail-closed (§11): DENY/intern.
        KernelError::Inconsistent => Status::internal("interne Konsistenz verletzt; fail-closed (§11)"),
        KernelError::Io => Status::internal("operativer I/O-Fehler (§7.1)"),
        KernelError::Corruption => Status::internal("durable Daten beschädigt; HALT (§Durability)"),
        KernelError::Poisoned => Status::internal("Bestand vergiftet nach fatalem Fehler"),
        // `KernelError` ist `#[non_exhaustive]`: ein künftiger, hier unbekannter
        // Zustand ⇒ fail-closed (§11), nie ein leckendes Teilergebnis.
        _ => Status::internal("interner Fehler; fail-closed (§11)"),
    }
}

/// Pinnt einen Snapshot **und** stellt für das Subjekt eine [`Capability`] aus
/// (§11.1/§11.2) — der eine Tor-Einstieg, der jede lesende RPC trägt. Beide laufen
/// über **dasselbe** S (§11.2): das Watermark `W` fixiert die §13-Aktiv-Sicht.
///
/// Ein **leeres**/fehlendes Subjekt ⇒ keine gewährten Bereiche (nur unbeschränkte
/// Daten sichtbar — fail-safe, §11.3).
fn pin_and_authorize(
    kernel: &Kernel,
    subject: &Option<Subject>,
) -> Result<(Capability, SnapshotToken), KernelError> {
    use lakearch_core::Kernel as _;
    let snapshot = kernel.pin_snapshot()?;
    let subject_id = subject
        .as_ref()
        .map(|s| s.subject_id.as_slice())
        .unwrap_or(&[]);
    if subject_id.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(subject_id);
        // Volle Tor-Ableitung: die aktiven (nicht entzogenen) Bereiche des Subjekts
        // (§11.2/§11.4), strukturell gematcht über denselben Snapshot.
        let cap = kernel.authorize_subject(ContentId::from_bytes(arr), snapshot)?;
        Ok((cap, snapshot))
    } else {
        // Kein (gültiges) Subjekt ⇒ keine gewährten Bereiche (fail-safe).
        let cap = kernel.authorize(GrantedScopes::from_scope_ids([]), snapshot)?;
        Ok((cap, snapshot))
    }
}

#[tonic::async_trait]
impl Lakearch for LakearchService {
    /// **append** (§7.1) — die einzige Mutation, durch die **eine** Schreib-
    /// Pipeline. Liefert die [`ContentId`] des (ggf. schon vorhandenen, §5.3)
    /// Daten.
    async fn append(
        &self,
        request: Request<AppendRequest>,
    ) -> Result<Response<AppendResponse>, Status> {
        let datum = datum_from_wire(request.into_inner().datum)?;
        let id = self
            .bestand
            .append(datum)
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(AppendResponse {
            content_id: id.as_bytes().to_vec(),
        }))
    }

    /// **get_by_content_id** (§5.2) — durch das **Tor** (§11). VANISH: verborgen
    /// **oder** nicht vorhanden ⇒ `present = false` (ununterscheidbar, §11.3).
    async fn get_by_content_id(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<GetResponse>, Status> {
        let req = request.into_inner();
        let id = content_id_from_wire(&req.content_id)?;
        let subject = req.subject;
        let resp = self
            .bestand
            .read(move |kernel| {
                use lakearch_core::{gate, Kernel as _};
                let (cap, snapshot) = pin_and_authorize(kernel, &subject)?;
                // §11.3 Filter-vor-Auflösen / VANISH an der Verb-Grenze: `None` ⇒
                // verborgen ODER nicht vorhanden (der Kernel kollabiert beides).
                match kernel.get_by_content_id(id, &cap, snapshot)? {
                    None => Ok(GetResponse {
                        present: false,
                        canonical_bytes: Vec::new(),
                    }),
                    Some(sealed) => {
                        // Das Tor ist die EINZIGE Inhalts-Quelle: `open` gegen
                        // dieselbe Capability legt die kanonischen Bytes frei (§11.5).
                        match gate::open(&sealed, &cap) {
                            Some(visible) => Ok(GetResponse {
                                present: true,
                                canonical_bytes: visible.canonical_bytes().to_vec(),
                            }),
                            // Zweite Tor-Durchsetzung sagt unsichtbar ⇒ VANISH.
                            None => Ok(GetResponse {
                                present: false,
                                canonical_bytes: Vec::new(),
                            }),
                        }
                    }
                }
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(resp))
    }

    /// §1.3 (i) **content_equal** — Gleichheit auf Adressebene. Reines Matching
    /// (kein Inhalt, kein Tor-Bypass).
    async fn content_equal(
        &self,
        request: Request<ContentEqualRequest>,
    ) -> Result<Response<BoolResponse>, Status> {
        let req = request.into_inner();
        let a = content_id_from_wire(&req.a)?;
        let b = content_id_from_wire(&req.b)?;
        let value = self
            .bestand
            .read(move |kernel| {
                use lakearch_core::Kernel as _;
                let snapshot = kernel.pin_snapshot()?;
                kernel.content_equal(a, b, snapshot)
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(BoolResponse { value }))
    }

    /// §1.3 (ii) **context_points_to** — zeigt der Kontext auf das Daten? **Gegated**
    /// (§11.2/§11.3): das Prädikat verrät einen strukturellen Besitz-Fakt über
    /// (potentiell) bereichs-beschränkte ODER noch **inaktive** (§13) Daten und läuft
    /// daher — wie `get_by_content_id`/`traverse` — über das **Tor**. Der Daemon leitet
    /// aus dem Subjekt die gewährten Bereiche ab (`authorize_subject`, §11.2) und ruft
    /// den **gegateten** Kernel-Einstieg `context_points_to_visible`: ist ein Operand
    /// für das Subjekt nicht sichtbar/inaktiv ⇒ `value = false` (**VANISH**, §11.3) —
    /// der Roh-Index wird für verborgene Operanden **nie** konsultiert.
    async fn context_points_to(
        &self,
        request: Request<ContextPointsToRequest>,
    ) -> Result<Response<BoolResponse>, Status> {
        let req = request.into_inner();
        let ctx = content_id_from_wire(&req.ctx)?;
        let target = content_id_from_wire(&req.target)?;
        let subject = req.subject;
        let value = self
            .bestand
            .read(move |kernel| {
                let (cap, snapshot) = pin_and_authorize(kernel, &subject)?;
                // Gegateter Einstieg: das Tor (Sichtbarkeit beider Operanden) wird
                // VOR dem Roh-Index-Match angewandt (§11.3 Filter-vor-Auflösen).
                kernel.context_points_to_visible(ctx, target, &cap, snapshot)
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(BoolResponse { value }))
    }

    /// §1.3 (iii) **is_member_of_set** — Zugehörigkeit zur per Kontext gegebenen
    /// Menge. **Gegated** (§11.2/§11.3) wie `context_points_to`: der Daemon leitet aus
    /// dem Subjekt die gewährten Bereiche ab (`authorize_subject`, §11.2) und ruft den
    /// **gegateten** Kernel-Einstieg `is_member_of_set_visible`. Ist ein Operand für
    /// das Subjekt nicht sichtbar/inaktiv ⇒ `value = false` (**VANISH**, §11.3).
    async fn is_member_of_set(
        &self,
        request: Request<IsMemberOfSetRequest>,
    ) -> Result<Response<BoolResponse>, Status> {
        let req = request.into_inner();
        let elem = content_id_from_wire(&req.elem)?;
        let set_ctx = content_id_from_wire(&req.set_ctx)?;
        let subject = req.subject;
        let value = self
            .bestand
            .read(move |kernel| {
                let (cap, snapshot) = pin_and_authorize(kernel, &subject)?;
                // Gegateter Einstieg: das Tor (Sichtbarkeit beider Operanden) wird
                // VOR dem Roh-Index-Match angewandt (§11.3 Filter-vor-Auflösen).
                kernel.is_member_of_set_visible(elem, set_ctx, &cap, snapshot)
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(BoolResponse { value }))
    }

    /// **traverse** (§1.2/§1.7 a) — beschränkt, zyklensicher, **gegated** (VANISH).
    /// Der Rand ordnet **nichts** um (§1.4): die Schritte kommen in der vom Kernel
    /// bestimmten aufsteigenden `ContentId`-Adress-Order (§5.2).
    async fn traverse(
        &self,
        request: Request<TraverseRequest>,
    ) -> Result<Response<StepList>, Status> {
        let req = request.into_inner();
        let start = content_id_from_wire(&req.start)?;
        let dir = direction_from_wire(req.direction);
        let max_depth = req.max_depth;
        let max_nodes = req.max_nodes;
        let mut filter: Vec<ContentId> = Vec::with_capacity(req.edge_type_filter.len());
        for raw in &req.edge_type_filter {
            filter.push(content_id_from_wire(raw)?);
        }
        let subject = req.subject;

        let steps = self
            .bestand
            .read(move |kernel| {
                use lakearch_core::{CancelFlag, TraversalParams};
                let (cap, snapshot) = pin_and_authorize(kernel, &subject)?;
                let filter_opt = if filter.is_empty() {
                    None
                } else {
                    Some(filter.clone())
                };
                let params = TraversalParams::new(start, dir, max_depth, max_nodes, filter_opt);
                // `traverse_with` trägt die Capability (volle §11.3-Durchsetzung):
                // nicht-sichtbare Nachbarn sind interne Front-Stopps (VANISH).
                let stream = kernel.traverse_with(params, &cap, snapshot, &CancelFlag::new())?;
                // Server-seitig vollständig sammeln (durch `max_nodes` beschränkt,
                // §1.7 a). Der Rand sortiert/aggregiert NICHT (§1.4) — die Reihen-
                // folge ist die vom Kernel emittierte Adress-Order.
                let mut out: Vec<ProtoStep> = Vec::new();
                for step in stream {
                    out.push(step_to_wire(&step?));
                }
                Ok(out)
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(StepList { steps }))
    }

    /// **find_dependents** (§10.2/§10.3) — Rückwärts-Traversierung der Herkunfts-
    /// Kontexte (transitiv, zyklensicher), **gegated**. Der Kernel **läuft nur**
    /// rückwärts und matcht (§1.3); Als-stale-markieren/Neu-Berechnen liegt
    /// **außerhalb** (§1.5/§7.1).
    async fn find_dependents(
        &self,
        request: Request<FindDependentsRequest>,
    ) -> Result<Response<StepList>, Status> {
        let req = request.into_inner();
        let input = content_id_from_wire(&req.input)?;
        let subject = req.subject;

        let steps = self
            .bestand
            .read(move |kernel| {
                use lakearch_core::Kernel as _;
                // Snapshot + Subjekt-Capability für die §13-Aktiv-Sicht binden. Die
                // frozen-Form `find_dependents` läuft fail-safe (leere Bereiche);
                // wir setzen den Snapshot konsistent über `pin_and_authorize`.
                let (_cap, snapshot) = pin_and_authorize(kernel, &subject)?;
                let stream = kernel.find_dependents(input, snapshot)?;
                let mut out: Vec<ProtoStep> = Vec::new();
                for step in stream {
                    out.push(step_to_wire(&step?));
                }
                Ok(out)
            })
            .await
            .map_err(status_from_kernel_error)?;
        Ok(Response::new(StepList { steps }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_from_wire_rejects_wrong_length() {
        // §5.2: eine Adresse ist genau 32 Byte; alles andere ist ein Client-
        // Formfehler (InvalidArgument) — der Kernel sieht nie eine kaputte Adresse.
        assert!(content_id_from_wire(&[0u8; 32]).is_ok());
        assert_eq!(
            content_id_from_wire(&[0u8; 31]).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            content_id_from_wire(&[0u8; 33]).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn datum_from_wire_maps_leaf_and_node() {
        // Blatt: opake Bytes; Knoten: besessene Kontexte (der Kernel kanonisiert).
        let leaf = datum_from_wire(Some(crate::proto::Datum {
            kind: Some(crate::proto::datum::Kind::Leaf(b"abc".to_vec())),
        }))
        .unwrap();
        assert_eq!(leaf.payload(), Some(&b"abc"[..]));

        let id = ContentId::from_bytes([7u8; 32]);
        let node = datum_from_wire(Some(crate::proto::Datum {
            kind: Some(crate::proto::datum::Kind::Node(crate::proto::NodeContexts {
                context_ids: vec![id.as_bytes().to_vec()],
            })),
        }))
        .unwrap();
        assert_eq!(node.owns(), Some(&[id][..]));
    }

    #[test]
    fn datum_from_wire_rejects_empty_node_and_missing() {
        // Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1) ⇒ InvalidArgument.
        let err = datum_from_wire(Some(crate::proto::Datum {
            kind: Some(crate::proto::datum::Kind::Node(crate::proto::NodeContexts {
                context_ids: vec![],
            })),
        }))
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        // Fehlendes Datum / fehlendes kind ⇒ ebenfalls Formfehler.
        assert_eq!(
            datum_from_wire(None).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn direction_from_wire_defaults_to_forward() {
        assert_eq!(direction_from_wire(0), Direction::Forward); // UNSPECIFIED
        assert_eq!(
            direction_from_wire(crate::proto::Direction::Forward as i32),
            Direction::Forward
        );
        assert_eq!(
            direction_from_wire(crate::proto::Direction::Backward as i32),
            Direction::Backward
        );
        assert_eq!(
            direction_from_wire(crate::proto::Direction::Both as i32),
            Direction::Both
        );
        // Unbekannter Wert ⇒ fail-safe Forward (kein Panic).
        assert_eq!(direction_from_wire(999), Direction::Forward);
    }

    #[test]
    fn error_mapping_is_visibility_blind_and_fail_closed() {
        // §11.3: die Status-Texte nennen keine konkreten Daten/IDs/Bereiche.
        // Inkonsistenz/Korruption/Vergiftung ⇒ intern (DENY, fail-closed §11).
        assert_eq!(
            status_from_kernel_error(KernelError::Inconsistent).code(),
            tonic::Code::Internal
        );
        assert_eq!(
            status_from_kernel_error(KernelError::TraversalBudgetExceeded).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            status_from_kernel_error(KernelError::Cancelled).code(),
            tonic::Code::Cancelled
        );
        assert_eq!(
            status_from_kernel_error(KernelError::NotYetImplemented(5)).code(),
            tonic::Code::Unimplemented
        );
    }
}
