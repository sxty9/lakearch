//! Kernel-Fehler.
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md`. Der Kernel **wertet nicht**
//! (§1.4) — er meldet ausschließlich **mechanische** Fehlerzustände: ein noch
//! nicht in seiner Roadmap-Phase implementiertes Verb, eine verletzte
//! Beschränkung der mechanischen Traversierung (§1.7 a), eine
//! Speicher-/Index-Inkonsistenz, die das Tor **fail-closed** (§11, leeres
//! Ergebnis) statt undefiniert behandeln muss. Fehlertexte sind
//! **sichtbarkeits-blind** (§11.3): sie nennen **niemals** nicht-sichtbare
//! Daten, IDs oder Bereiche.

/// Mechanischer Fehlerzustand eines Kernel-Verbs. Trägt **keine** Wertung
/// (§1.4); jede Variante ist ein struktureller/operativer Zustand.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KernelError {
    /// Das Verb ist in der angegebenen Roadmap-**Phase** vorgesehen, aber in
    /// diesem Stand noch nicht implementiert. Friert die **Form** der API ein,
    /// ohne vorzeitige Semantik (Phasen-Disziplin). Der Wert ist die Phase, in
    /// der das Verb seine Logik erhält.
    #[error("Verb ist noch nicht implementiert (geplant für Phase {0})")]
    NotYetImplemented(u8),

    /// Eine mechanische Traversierung (§1.7 a) hat ihr **Budget** überschritten
    /// (Tiefe, Knoten- bzw. Schrittzahl). Definierter Abbruch statt
    /// unbeschränkter Lauf (§1.7 a „beschränkt"). Reines Mechanik-Signal, keine
    /// Wertung.
    #[error("Traversierungs-Budget überschritten")]
    TraversalBudgetExceeded,

    /// Die Traversierung wurde **kooperativ abgebrochen** (Client-Disconnect /
    /// Deadline am async-Rand setzt das Cancel-Flag). Definierter Zustand, kein
    /// Teilergebnis-Versprechen.
    #[error("Traversierung abgebrochen")]
    Cancelled,

    /// Speicher-/Index-Inkonsistenz: das Tor antwortet **fail-closed** (§11,
    /// leeres Ergebnis), statt undefiniert fortzufahren. Der Text ist
    /// sichtbarkeits-blind (§11.3) und nennt **keine** konkreten Daten/IDs.
    #[error("interne Konsistenz verletzt; fail-closed (§11)")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_yet_implemented_names_its_phase() {
        // Die Phase ist im Fehlertext sichtbar, damit Phasen-Disziplin auch
        // zur Laufzeit lesbar ist.
        let e = KernelError::NotYetImplemented(2);
        assert!(e.to_string().contains("Phase 2"));
    }

    #[test]
    fn error_is_send_sync() {
        // Der Fehler muss über die eine Append-Pipeline und MVCC-Leser hinweg
        // transportierbar sein (Send + Sync).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KernelError>();
    }
}
