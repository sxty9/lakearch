//! lakearchd — der **lakearch-Daemon** (Bibliotheks-Kern).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` und der gehärtete Plan
//! (Abschnitte „Architektur & Topologie", „Protokoll + Interaktionsmodell",
//! Trust-Modell). Der Daemon ist die **Sicherheits-Grenze** (§11/§Trust-Modell):
//! er besitzt **einen** Bestand (= **ein** [`lakearch_core::LakearchKernel`])
//! hinter **einer** Schreib-Pipeline und exponiert die **Kernel-Primitive** über
//! das Netz, wobei das **Tor** (§11) auf **jeder** Anfrage durchgesetzt wird.
//!
//! ## Was der Daemon-Rand exponiert — und ausschließlich exponiert (§1.4/§14.2)
//!
//! Genau die Kernel-Primitive: `append` (§7.1), `get_by_content_id` (§5.2, durch
//! das Tor §11), die **drei** §1.3-Match-Prädikate, die **beschränkte**
//! Traversierung (§1.2/§1.7 a) und `find_dependents` (§10.3). **Kein** Sortieren/
//! Aggregieren/Ranken/Rechnen am Rand — die Auflösungs-/Rechen-Schicht liegt
//! darüber (§1.4/§1.5) und wird hier **nicht** gebaut.
//!
//! ## Topologie (Plan: „Architektur & Topologie")
//!
//! - Ein [`bestand::Bestand`] = ein Kernel. Schreibvorgänge laufen über **eine**
//!   serielle Pipeline (ein Writer-Thread); Leser laufen **nebenläufig** über
//!   einen am Watermark gepinnten MVCC-Snapshot (§8.4/§13).
//! - **Async am Rand, sync im Kern:** der gRPC-Rand ist `tokio`; der Kernel bleibt
//!   sync/threaded und wird über `spawn_blocking` (Leser) bzw. den Writer-Thread
//!   (Schreiber) bedient.
//! - **Gate pro Anfrage:** jede Anfrage trägt ein Subjekt; der Daemon leitet
//!   daraus die gewährten Bereiche ab ([`lakearch_core::LakearchKernel::authorize_subject`])
//!   und liest **gegated** (VANISH/fail-closed, §11.3).

pub mod bestand;
pub mod service;

/// Der von `tonic-prost-build` aus `proto/lakearch.proto` generierte Code (§14.2:
/// die Wire-Form ist eine **billig revidierbare** Rand-Entscheidung, nicht der
/// Kernel).
pub mod proto {
    #![allow(clippy::doc_overindented_list_items)]
    tonic::include_proto!("lakearch.v1");
}

pub use bestand::Bestand;
pub use service::LakearchService;
