//! Die **C-ABI-Fehlercodes** (`LakearchStatus`) der FFI-Schicht.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§1.4 „der Kernel wertet
//! nicht"; §11 fail-closed; §11.3 sichtbarkeits-blind) und der gehärtete Plan
//! (Trust-Modell: das IN-PROZESS-Embedding bedient **eine** Vertrauenszone).
//!
//! Die Grenze gibt **rein mechanische** Zustände als kleine `int32`-Codes heraus
//! — **niemals** eine Wertung (§1.4) und **niemals** nicht-sichtbare Daten/IDs/
//! Bereiche (§11.3): die Codes sind kategorisch, nicht inhaltlich. Ein
//! [`KernelError`](lakearch_core::KernelError) wird in **genau einen** Code
//! abgebildet; ein über die C-ABI durchgereichter Rust-Panic (UB!) wird als
//! [`LakearchStatus::Panic`] zurückgegeben, **nie** als Unwind.

use lakearch_core::KernelError;

/// Fehlercode jeder `extern "C"`-Funktion (`int32`, C-ABI-stabil).
///
/// `Ok = 0`; alles andere ist ein definierter Fehlerzustand. Die Reihenfolge/
/// Werte sind Teil des ABI-Vertrags und dürfen sich nicht verschieben (append-only
/// erweitern, nie umnummerieren). Die Codes sind **sichtbarkeits-blind** (§11.3):
/// kategorisch, kein Inhalt.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LakearchStatus {
    /// Erfolg.
    Ok = 0,
    /// Ein über die C-ABI gefangener **Panic** (`catch_unwind`): die FFI-Funktion
    /// hätte sonst über die Grenze unwound (UB). Statt UB → definierter Code.
    Panic = 1,
    /// Ein **Null-Pointer** kam, wo ein gültiger Pointer verlangt war, oder ein
    /// Längen-/Argument-Vertrag wurde verletzt. Reiner Form-Fehler an der Grenze.
    NullArgument = 2,
    /// Ein übergebenes Handle ist ungültig/bereits geschlossen (Pointer ist nicht
    /// `null`, aber nicht als gültiges Handle interpretierbar) oder eine UTF-8-/
    /// Pfad-Konvertierung schlug fehl.
    InvalidHandle = 3,
    /// Das Daten ist **nicht sichtbar oder nicht vorhanden** (VANISH, §11.3) —
    /// ununterscheidbar von „existiert nicht". Kein Existenz-Orakel.
    NotFound = 4,
    /// Der vom Aufrufer bereitgestellte Puffer war **zu klein**; die benötigte
    /// Länge wird über den `out_len`-Parameter zurückgemeldet (kein Datenverlust,
    /// erneut mit größerem Puffer aufrufen).
    BufferTooSmall = 5,

    // -- Abbildung der mechanischen `KernelError`-Zustände (§1.4) ---------------
    /// Ein Verb ist in seiner Roadmap-Phase noch nicht implementiert.
    NotYetImplemented = 10,
    /// Eine beschränkte Traversierung (§1.7 a) hat ihr Budget überschritten.
    TraversalBudgetExceeded = 11,
    /// Eine Traversierung wurde kooperativ abgebrochen.
    Cancelled = 12,
    /// Speicher-/Index-Inkonsistenz; fail-closed (§11) — DENY statt undefiniert.
    Inconsistent = 13,
    /// Operativer I/O-Fehler des Segment-Logs (§7.1).
    Io = 14,
    /// Beschädigte durable Daten vor dem letzten Footer; HALT für den Operator.
    Corruption = 15,
    /// Das Segment-Log/der Lock ist nach einem fatalen Fehler vergiftet.
    Poisoned = 16,
    /// Ein hier (noch) nicht kategorisierter mechanischer Zustand; fail-closed.
    Other = 99,
}

impl LakearchStatus {
    /// Der rohe `int32`-Code (für die Tests und die `extern "C"`-Rückgabe).
    pub fn code(self) -> i32 {
        self as i32
    }
}

impl From<KernelError> for LakearchStatus {
    /// Bildet einen mechanischen [`KernelError`] (§1.4) in **genau einen**
    /// C-ABI-Code ab — kategorisch, sichtbarkeits-blind (§11.3).
    fn from(e: KernelError) -> Self {
        match e {
            KernelError::NotYetImplemented(_) => LakearchStatus::NotYetImplemented,
            KernelError::TraversalBudgetExceeded => LakearchStatus::TraversalBudgetExceeded,
            KernelError::Cancelled => LakearchStatus::Cancelled,
            KernelError::Inconsistent => LakearchStatus::Inconsistent,
            KernelError::Io => LakearchStatus::Io,
            KernelError::Corruption => LakearchStatus::Corruption,
            KernelError::Poisoned => LakearchStatus::Poisoned,
            // `KernelError` ist `#[non_exhaustive]`: ein künftiger, hier unbekannter
            // Zustand ⇒ fail-closed (§11), nie ein stiller Erfolg.
            _ => LakearchStatus::Other,
        }
    }
}
