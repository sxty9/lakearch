//! Der **Bestand** (§8) — der gemeinsam besessene Zustand des Daemons: **ein**
//! [`LakearchKernel`] hinter **einer** Schreib-Pipeline mit **vielen** neben-
//! läufigen Lesern.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` und der gehärtete Plan
//! („Architektur & Topologie", „Durability, Recovery & Atomarität"). Topologie-
//! Entscheidung des Plans: der Daemon besitzt **einen** Bestand = **ein**
//! `LakearchKernel`, dessen **einzige** Mutation (`append`, §7.1) über **eine**
//! serielle Schreib-Pipeline läuft (ein dedizierter Writer-Thread), während Leser
//! **nebenläufig** über einen am Watermark gepinnten MVCC-Snapshot laufen (§8.4/
//! §13).
//!
//! ## Sync-Kern, async-Rand
//!
//! Der Kernel ist **sync/threaded** (kein `async` im Kern — `async` lebt nur am
//! Netz-Rand). Schreibvorgänge werden über einen `mpsc`-Kanal an **einen**
//! Writer-Thread gereicht (die eine Append-Pipeline); Lesevorgänge laufen über
//! [`tokio::task::spawn_blocking`] direkt am `&self`-Kernel (der `RwLock` im
//! Kernel erlaubt viele gleichzeitige Leser). So bleibt der Schreibpfad **seriell
//! linearisiert** (eine Append-Reihenfolge, §7.1) und der Lesepfad **nebenläufig**.

use std::sync::Arc;
use std::thread::JoinHandle;

use lakearch_core::{ContentId, Datum, Kernel as _, KernelError, LakearchKernel, RedbEdgeIndex};
use tokio::sync::{mpsc, oneshot};

/// Die konkrete Kernel-Instanz des Daemons (Standard-Engine redb).
pub type Kernel = LakearchKernel<RedbEdgeIndex>;

/// Ein an die **eine** Schreib-Pipeline gereichter Auftrag: ein `append` (§7.1)
/// plus ein `oneshot`-Rückkanal für das Ergebnis (die [`ContentId`] bzw. ein
/// [`KernelError`]).
struct WriteJob {
    datum: Datum,
    reply: oneshot::Sender<Result<ContentId, KernelError>>,
}

/// Der **Bestand**: der gemeinsam besessene Daemon-Zustand. Klonbar (`Arc`), damit
/// jede gRPC-Anfrage ihn billig teilt; der eigentliche Zustand (Kernel +
/// Writer-Kanal) liegt **einmal** dahinter.
#[derive(Clone)]
pub struct Bestand {
    inner: Arc<BestandInner>,
}

struct BestandInner {
    /// Der **eine** Kernel (ein Bestand). `&self`-Lesepfade laufen hier neben-
    /// läufig (MVCC-Snapshot über das Watermark); der `RwLock` im Kernel
    /// serialisiert nur den Schreib-Lock.
    kernel: Arc<Kernel>,
    /// Der Sende-Endpunkt der **einen** Schreib-Pipeline. Alle `append`s laufen
    /// hier durch — der Writer-Thread verarbeitet sie **seriell** (eine
    /// Append-Reihenfolge, §7.1). In einer [`Option`] hinter einem `Mutex`, damit
    /// `Drop` ihn **vor** dem Join freigeben kann (sonst hinge der Join, weil der
    /// Writer erst endet, wenn der **letzte** Sender fällt).
    writer: std::sync::Mutex<Option<mpsc::Sender<WriteJob>>>,
    /// Handle des Writer-Threads (für sauberes Herunterfahren beim Drop).
    writer_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Bestand {
    /// Öffnet den Bestand unter `dir` (Standard-Engine redb) und startet die
    /// **eine** Schreib-Pipeline (ein Writer-Thread). Beim Öffnen läuft die
    /// Log-Recovery + Index-Versöhnung (§8.4).
    ///
    /// `write_queue` ist die Kapazität des Writer-Kanals (Backpressure: ist die
    /// Pipeline voll, wartet der async-Rand, statt unbeschränkt zu puffern —
    /// §1.7 a sinngemäß für den Schreibpfad).
    pub fn open(
        dir: impl AsRef<std::path::Path>,
        write_queue: usize,
    ) -> Result<Self, KernelError> {
        let kernel = Arc::new(LakearchKernel::<RedbEdgeIndex>::open(dir)?);
        let (tx, mut rx) = mpsc::channel::<WriteJob>(write_queue.max(1));

        // Die EINE Schreib-Pipeline: ein dedizierter Thread, der Append-Aufträge
        // SERIELL abarbeitet. Der Kernel bleibt sync; dieser Thread ist der
        // einzige Schreiber (§7.1 — eine Append-Reihenfolge, keine konkurrierenden
        // Schreiber).
        let writer_kernel = Arc::clone(&kernel);
        let writer_handle = std::thread::Builder::new()
            .name("lakearchd-writer".to_string())
            .spawn(move || {
                // `blocking_recv` blockiert diesen dedizierten Thread bis zum
                // nächsten Auftrag oder bis alle Sender fallen (Shutdown).
                while let Some(job) = rx.blocking_recv() {
                    let result = writer_kernel.append(&job.datum);
                    // Ein abgebrochener Empfänger (Client weg) ist kein Fehler des
                    // Writers — der Append ist dennoch durabel (§7.1).
                    let _ = job.reply.send(result);
                }
            })
            .map_err(|_| KernelError::Io)?;

        Ok(Bestand {
            inner: Arc::new(BestandInner {
                kernel,
                writer: std::sync::Mutex::new(Some(tx)),
                writer_handle: std::sync::Mutex::new(Some(writer_handle)),
            }),
        })
    }

    /// Reicht ein `append` (§7.1) an die **eine** Schreib-Pipeline und wartet
    /// async auf das Ergebnis. Inhaltsgleiches dedupliziert der Kernel (§5.3).
    ///
    /// Schlägt der Kanal/Rückkanal fehl (Writer-Thread weg, z. B. im Shutdown),
    /// ist das ein operativer Fehler ([`KernelError::Io`]) — **nie** ein stilles
    /// „Erfolg ohne Schreiben".
    pub async fn append(&self, datum: Datum) -> Result<ContentId, KernelError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job = WriteJob {
            datum,
            reply: reply_tx,
        };
        // Einen Sender-Klon herausziehen (kurz gehaltener Lock); die Pipeline
        // bleibt **eine** (der Writer-Thread ist der einzige Empfänger). Ist der
        // Sender bereits weg (Shutdown), ist das ein operativer Fehler.
        let sender = {
            let guard = self
                .inner
                .writer
                .lock()
                .map_err(|_| KernelError::Poisoned)?;
            guard.as_ref().ok_or(KernelError::Io)?.clone()
        };
        sender.send(job).await.map_err(|_| KernelError::Io)?;
        reply_rx.await.map_err(|_| KernelError::Io)?
    }

    /// Führt einen **sync** Lesevorgang am Kernel **nebenläufig** über
    /// [`tokio::task::spawn_blocking`] aus (der Kernel-`RwLock` erlaubt viele
    /// gleichzeitige Leser). `f` bekommt eine geteilte Referenz auf den Kernel; es
    /// **mutiert nichts** (Lesen erzeugt nichts, §8.4) und läuft über einen am
    /// Watermark gepinnten Snapshot (§13).
    ///
    /// So bleibt der **async-Rand** reaktiv, während der **sync-Kern** die Arbeit
    /// auf dem Blocking-Pool leistet — viele Leser parallel zu einem laufenden
    /// Schreibvorgang (MVCC, keine Leser-Blockade).
    pub async fn read<T, F>(&self, f: F) -> Result<T, KernelError>
    where
        F: FnOnce(&Kernel) -> Result<T, KernelError> + Send + 'static,
        T: Send + 'static,
    {
        let kernel = Arc::clone(&self.inner.kernel);
        tokio::task::spawn_blocking(move || f(&kernel))
            .await
            // Ein abgestürzter Blocking-Task (Panic) ⇒ fail-closed (§11): DENY,
            // statt undefiniert fortzufahren.
            .map_err(|_| KernelError::Poisoned)?
    }
}

impl Drop for BestandInner {
    fn drop(&mut self) {
        // ZUERST den Sender freigeben: der Writer-Thread verlässt seine
        // `blocking_recv`-Schleife erst, wenn der **letzte** Sender fällt. Würden
        // wir vorher joinen, hinge der Join. (Etwaige `append`-Aufrufer haben ihre
        // eigenen kurzlebigen Klone; im Drop ist der Bestand exklusiv.)
        if let Ok(mut guard) = self.writer.lock() {
            guard.take();
        }
        // DANN joinen, damit der letzte committete Append durabel verarbeitet ist,
        // bevor der Prozess weiterläuft (sauberes Herunterfahren).
        if let Ok(mut guard) = self.writer_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}
