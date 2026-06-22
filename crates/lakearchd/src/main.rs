//! `lakearchd` — der Daemon-Einstiegspunkt.
//!
//! Öffnet **einen** Bestand (ein [`lakearch_core::LakearchKernel`]) und bedient die
//! Kernel-Primitive über gRPC (tonic). Der Daemon ist die **Sicherheits-Grenze**
//! (§11/§Trust-Modell): das Tor läuft auf **jeder** Anfrage.
//!
//! Konfiguration über Umgebung/Argumente, bewusst minimal:
//! - `arg[1]` (optional): Bestand-Verzeichnis (Default `./lakearch-data`).
//! - `LAKEARCHD_ADDR` (optional): Bind-Adresse (Default `127.0.0.1:50051`).
//! - `LAKEARCHD_WRITE_QUEUE` (optional): Kapazität der Schreib-Pipeline (Default 1024).

use std::net::SocketAddr;

use lakearchd::proto::lakearch_server::LakearchServer;
use lakearchd::{Bestand, LakearchService};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Beobachtbarkeit am Rand (§8.4: Lesen erzeugt im Kernel nichts; Tracing lebt
    // am Daemon-Rand). `RUST_LOG` steuert die Filterung.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./lakearch-data".to_string());
    std::fs::create_dir_all(&dir)?;

    let addr: SocketAddr = std::env::var("LAKEARCHD_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;

    let write_queue: usize = std::env::var("LAKEARCHD_WRITE_QUEUE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);

    // Ein Bestand = ein Kernel hinter EINER Schreib-Pipeline (§7.1).
    let bestand = Bestand::open(&dir, write_queue)?;
    let service = LakearchService::new(bestand);

    tracing::info!(%addr, %dir, "lakearchd startet (ein Bestand, gegateter Rand §11)");

    Server::builder()
        .add_service(LakearchServer::new(service))
        .serve_with_shutdown(addr, async {
            // Sauberes Herunterfahren bei SIGINT (Ctrl-C): der Bestand-Drop joint
            // den Writer-Thread (letzter Append durabel).
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("lakearchd fährt herunter (SIGINT)");
        })
        .await?;

    Ok(())
}
