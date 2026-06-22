//! lakearch-ffi — die **C-ABI** für das **IN-PROZESS-Embedding** von lakearch.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§1.4/§1.5/§14.2 die
//! Grenze exponiert **nur** Kernel-Primitive; §11 das Tor; §11.3 VANISH/
//! sichtbarkeits-blind) und der gehärtete Plan (Trust-Modell + „Architektur &
//! Topologie").
//!
//! ## Wofür diese Schicht ist — und ausschließlich ist (Trust-Modell)
//!
//! Embedding bedient **nur eine einzige Vertrauenszone**: der Einbetter ist die
//! vertrauenswürdige Schicht-darüber (er hält das Read-Audit, die Berechtigungs-
//! Ausstellung, die Auflösung/Rechnung). **Mandantenfähig/reguliert ⇒ der Daemon**
//! ([`lakearchd`]), nicht diese FFI. Diese C-ABI legt daher die Kernel-Primitive
//! für einen vertrauenswürdigen In-Prozess-Einbetter offen — sie ist **keine**
//! Mehr-Mandanten-Sicherheitsgrenze.
//!
//! ## Was die Grenze exponiert (§1.4/§14.2)
//!
//! Genau Kernel-Primitive über **opake Handle-Pointer**:
//! - [`lakearch_open`]/[`lakearch_close`] — einen Kernel auf einem Pfad öffnen/
//!   schließen (RAII über das Handle; `close` ist der einzige Freigabe-Pfad).
//! - [`lakearch_append`] — Bytes als atomares Daten anhängen (§7.1); liefert die
//!   32-Byte-[`ContentId`].
//! - [`lakearch_get_by_content_id`] — ein Daten **durchs Tor** (§11) lesen;
//!   füllt einen Aufrufer-Puffer mit den kanonischen Bytes (§K4) oder meldet die
//!   benötigte Länge. VANISH (§11.3): verborgen/abwesend sind ununterscheidbar.
//! - [`lakearch_traverse`] — beschränkte, zyklensichere Traversierung (§1.2/§1.7 a);
//!   **streamt** jeden Schritt über einen Aufrufer-Callback (Backpressure: der
//!   Callback kann abbrechen) **oder** füllt einen Schritt-Puffer.
//!
//! **Kein** Sortieren/Aggregieren/Ranken/Rechnen an der Grenze (§1.4/§14.2): die
//! Auflösungs-/Rechen-Schicht liegt darüber und wird hier **nicht** gebaut.
//!
//! ## ABI-Sicherheit: kein Panic über die C-Grenze (UB-Schutz)
//!
//! Ein über die C-ABI **unwindender** Rust-Panic ist **undefiniertes Verhalten**.
//! Daher umschließt **jede** `extern "C"`-Funktion ihren ganzen Rumpf in
//! [`std::panic::catch_unwind`] und wandelt einen gefangenen Panic in
//! [`LakearchStatus::Panic`] — der Strom kehrt **immer** geordnet über die Grenze
//! zurück. In den FFI-Pfaden gibt es **kein** `unwrap`/`expect`/`panic!`; Fehler
//! sind ausschließlich Rückgabe-Codes (§11 fail-closed).
//!
//! Diese Schicht ist `#![deny(unsafe_op_in_unsafe_fn)]`: jedes `unsafe` (Pointer-
//! Deref, Slice-aus-Roh-Pointer) trägt einen expliziten `unsafe`-Block mit
//! SAFETY-Begründung.

#![deny(unsafe_op_in_unsafe_fn)]

mod error;
mod handle;

pub use error::LakearchStatus;
pub use handle::KernelHandle;

use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

use lakearch_core::{
    gate, CancelFlag, Capability, ContentId, Datum, Direction, GrantedScopes, Kernel as _,
    LakearchKernel, RedbEdgeIndex, SnapshotToken, TraversalParams,
};

/// Die Standard-Kernel-Instanz hinter dem opaken Handle (Engine: redb).
type FfiKernel = LakearchKernel<RedbEdgeIndex>;

/// Länge einer [`ContentId`] in Bytes (§5.2) — Teil des C-ABI-Vertrags.
pub const LAKEARCH_CONTENT_ID_LEN: usize = 32;

/// **Panik-Wächter** (§ABI-Sicherheit): führt `body` unter
/// [`catch_unwind`] aus. Panickt `body`, wird der Unwind **gefangen** (statt über
/// die C-Grenze zu propagieren, was UB wäre) und [`LakearchStatus::Panic`]
/// zurückgegeben. Sonst wird der von `body` gelieferte Status durchgereicht.
///
/// `AssertUnwindSafe`: die FFI-Closures arbeiten über rohe Pointer/`&self`-Reads;
/// ein Panic hinterlässt **keinen** beobachtbar inkonsistenten Rust-Zustand, der
/// die Aufrufer-Sicherheit verletzt (der Kernel selbst meldet Lock-Vergiftung
/// fail-closed als [`LakearchStatus::Poisoned`]).
fn guard<F: FnOnce() -> LakearchStatus>(body: F) -> LakearchStatus {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(_) => LakearchStatus::Panic,
    }
}

/// Reicht ein `Result<_, KernelError>` an einen Erfolgs-Pfad weiter und bildet
/// einen Fehler auf seinen C-ABI-Code ab (§1.4 mechanisch, §11.3 sichtbarkeits-
/// blind).
fn map_result<T, F: FnOnce(T) -> LakearchStatus>(
    r: Result<T, lakearch_core::KernelError>,
    on_ok: F,
) -> LakearchStatus {
    match r {
        Ok(v) => on_ok(v),
        Err(e) => LakearchStatus::from(e),
    }
}

// ---------------------------------------------------------------------------
// Öffnen / Schließen — RAII über das opake Handle.
// ---------------------------------------------------------------------------

/// Öffnet einen Kernel auf dem Verzeichnis `dir_utf8` (`dir_len` Bytes, UTF-8,
/// **ohne** terminierende NUL) und schreibt das opake Handle nach `*out_handle`.
///
/// Beim Öffnen laufen die Log-Recovery + Index-Versöhnung (§8.4). Das Verzeichnis
/// muss existieren. Der Aufrufer **muss** das Handle später mit
/// [`lakearch_close`] freigeben (RAII; einziger Freigabe-Pfad).
///
/// # Safety
/// `dir_utf8` muss auf `dir_len` lesbare Bytes zeigen (oder `dir_len == 0`).
/// `out_handle` muss auf einen beschreibbaren `*mut KernelHandle` zeigen. Bei
/// einem anderen Code als [`LakearchStatus::Ok`] wird `*out_handle` **nicht**
/// gesetzt (bzw. auf `null`); der Aufrufer darf es dann nicht freigeben.
#[no_mangle]
pub unsafe extern "C" fn lakearch_open(
    dir_utf8: *const c_char,
    dir_len: usize,
    out_handle: *mut *mut KernelHandle,
) -> LakearchStatus {
    guard(|| {
        if out_handle.is_null() {
            return LakearchStatus::NullArgument;
        }
        // SAFETY: der Aufrufer-Vertrag garantiert einen beschreibbaren Slot; wir
        // setzen ihn vorsorglich auf null, damit ein Fehlerpfad nie ein wildes
        // Handle hinterlässt.
        unsafe { *out_handle = std::ptr::null_mut() };

        if dir_utf8.is_null() && dir_len != 0 {
            return LakearchStatus::NullArgument;
        }
        // SAFETY: `dir_utf8` zeigt laut Vertrag auf `dir_len` lesbare Bytes (oder
        // `dir_len == 0` ⇒ leerer Slice ohne Deref).
        let bytes: &[u8] = if dir_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(dir_utf8 as *const u8, dir_len) }
        };
        let dir = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            // Ein nicht-UTF-8-Pfad ist ein Aufrufer-Formfehler an der Grenze.
            Err(_) => return LakearchStatus::InvalidHandle,
        };

        map_result(FfiKernel::open(dir), |kernel| {
            let handle = KernelHandle::into_raw(kernel);
            // SAFETY: `out_handle` ist (oben geprüft) nicht-null und laut Vertrag
            // beschreibbar.
            unsafe { *out_handle = handle };
            LakearchStatus::Ok
        })
    })
}

/// Schließt ein mit [`lakearch_open`] geöffnetes Handle und gibt **alle**
/// Ressourcen frei (Log/Index sauber geschlossen). Nach diesem Aufruf ist der
/// Pointer ungültig; ein doppelter `close` desselben Handles ist **verboten**.
/// `null` ⇒ no-op ([`LakearchStatus::Ok`], idempotent-freundlich).
///
/// # Safety
/// `handle` muss `null` **oder** ein von [`lakearch_open`] geliefertes, noch
/// nicht geschlossenes Handle sein.
#[no_mangle]
pub unsafe extern "C" fn lakearch_close(handle: *mut KernelHandle) -> LakearchStatus {
    guard(|| {
        if handle.is_null() {
            return LakearchStatus::Ok;
        }
        // SAFETY: laut Vertrag ein gültiges, noch nicht freigegebenes Handle; wir
        // rekonstruieren den Box und droppen ihn (genau einmal).
        unsafe { KernelHandle::drop_raw(handle) };
        LakearchStatus::Ok
    })
}

// ---------------------------------------------------------------------------
// append (§7.1) — die einzige Mutation.
// ---------------------------------------------------------------------------

/// Hängt `len` Bytes ab `data` als **atomares Blatt-Daten** an (§7.1; Dedup §5.3)
/// und schreibt die 32-Byte-[`ContentId`] nach `out_content_id` (genau
/// [`LAKEARCH_CONTENT_ID_LEN`] Bytes).
///
/// Inhaltsgleiches dedupliziert automatisch (§5.3) und schreibt **nichts** Neues —
/// es liefert dieselbe ID. `len == 0` ist ein wohlgeformtes leeres Blatt.
///
/// # Safety
/// `data` muss auf `len` lesbare Bytes zeigen (oder `len == 0`). `out_content_id`
/// muss auf [`LAKEARCH_CONTENT_ID_LEN`] beschreibbare Bytes zeigen.
#[no_mangle]
pub unsafe extern "C" fn lakearch_append(
    handle: *const KernelHandle,
    data: *const u8,
    len: usize,
    out_content_id: *mut u8,
) -> LakearchStatus {
    guard(|| {
        // SAFETY: Vertrag wie dokumentiert; `kernel_ref` prüft null + leiht den Kernel.
        let kernel = match unsafe { KernelHandle::kernel_ref(handle) } {
            Some(k) => k,
            None => return LakearchStatus::InvalidHandle,
        };
        if out_content_id.is_null() {
            return LakearchStatus::NullArgument;
        }
        if data.is_null() && len != 0 {
            return LakearchStatus::NullArgument;
        }
        // SAFETY: `data` zeigt laut Vertrag auf `len` lesbare Bytes (oder leer).
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        let datum = Datum::leaf(bytes.to_vec());
        map_result(kernel.append(&datum), |id| {
            // SAFETY: `out_content_id` zeigt laut Vertrag auf 32 beschreibbare Bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    id.as_bytes().as_ptr(),
                    out_content_id,
                    LAKEARCH_CONTENT_ID_LEN,
                );
            }
            LakearchStatus::Ok
        })
    })
}

// ---------------------------------------------------------------------------
// get_by_content_id (§5.2) — durch das Tor (§11).
// ---------------------------------------------------------------------------

/// Liest das Daten mit der 32-Byte-[`ContentId`] `content_id` **durch das Tor**
/// (§11) und füllt `out_buf`/`*out_len` mit seinen **kanonischen Bytes** (§K4).
///
/// Ablauf (single-trust-domain Embedding): der Einbetter ist die vertrauens-
/// würdige Schicht — der Lesevorgang läuft mit **leeren** gewährten Bereichen
/// (nur unbeschränkte Daten sind ohne explizite Berechtigung sichtbar; bereichs-
/// beschränkte Daten VANISHen, fail-safe §11.3). Die Sichtbarkeit wird dennoch
/// **durchs Tor** durchgesetzt — kein Read-Bypass.
///
/// Puffer-Protokoll:
/// - `*out_len` muss beim Aufruf die **Kapazität** von `out_buf` in Bytes tragen;
///   nach Erfolg trägt es die **geschriebene** Länge.
/// - Ist der Puffer zu klein, wird [`LakearchStatus::BufferTooSmall`] geliefert und
///   `*out_len` auf die **benötigte** Länge gesetzt (erneut mit größerem Puffer).
/// - Ist das Daten nicht sichtbar/nicht vorhanden ⇒ [`LakearchStatus::NotFound`]
///   (VANISH, §11.3 — ununterscheidbar). `out_buf` darf `null` sein, solange
///   `*out_len == 0` (Längen-Abfrage).
///
/// # Safety
/// `content_id` muss auf [`LAKEARCH_CONTENT_ID_LEN`] lesbare Bytes zeigen.
/// `out_len` muss auf einen les-/beschreibbaren `usize` zeigen. `out_buf` muss
/// auf `*out_len` (Eingangswert) beschreibbare Bytes zeigen (oder `null`, wenn der
/// Eingangswert 0 ist).
#[no_mangle]
pub unsafe extern "C" fn lakearch_get_by_content_id(
    handle: *const KernelHandle,
    content_id: *const u8,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> LakearchStatus {
    guard(|| {
        // SAFETY: Vertrag wie dokumentiert.
        let kernel = match unsafe { KernelHandle::kernel_ref(handle) } {
            Some(k) => k,
            None => return LakearchStatus::InvalidHandle,
        };
        if content_id.is_null() || out_len.is_null() {
            return LakearchStatus::NullArgument;
        }
        // SAFETY: `content_id` zeigt laut Vertrag auf 32 lesbare Bytes.
        let id = unsafe { read_content_id(content_id) };
        // SAFETY: `out_len` zeigt laut Vertrag auf einen lesbaren `usize`.
        let capacity = unsafe { *out_len };
        if out_buf.is_null() && capacity != 0 {
            return LakearchStatus::NullArgument;
        }

        // Den gegateten Lesepfad genau wie ein In-Process-Einbetter fahren:
        // pin_snapshot → authorize(leere Scopes) → get_by_content_id → gate::open.
        let snapshot: SnapshotToken = match kernel.pin_snapshot() {
            Ok(s) => s,
            Err(e) => return LakearchStatus::from(e),
        };
        let capability: Capability =
            match kernel.authorize(GrantedScopes::from_scope_ids([]), snapshot) {
                Ok(c) => c,
                Err(e) => return LakearchStatus::from(e),
            };

        let sealed = match kernel.get_by_content_id(id, &capability, snapshot) {
            // VANISH (§11.3): verborgen ODER nicht vorhanden — ununterscheidbar.
            Ok(None) => return LakearchStatus::NotFound,
            Ok(Some(s)) => s,
            Err(e) => return LakearchStatus::from(e),
        };
        // Das Tor ist die EINZIGE Inhalts-Quelle (§11.5): `open` gegen dieselbe
        // Capability legt die kanonischen Bytes frei — oder VANISH.
        let visible = match gate::open(&sealed, &capability) {
            Some(v) => v,
            None => return LakearchStatus::NotFound,
        };
        let bytes = visible.canonical_bytes();
        let needed = bytes.len();
        // SAFETY: `out_len` ist (oben geprüft) nicht-null und beschreibbar.
        unsafe { *out_len = needed };
        if needed > capacity {
            // Kein Datenverlust: die benötigte Länge steht in `*out_len`.
            return LakearchStatus::BufferTooSmall;
        }
        if needed > 0 {
            // SAFETY: `out_buf` hält laut Vertrag `capacity >= needed` beschreibbare
            // Bytes; Quelle und Ziel überlappen nicht (frische FFI-Puffer).
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, needed);
            }
        }
        LakearchStatus::Ok
    })
}

// ---------------------------------------------------------------------------
// traverse (§1.2/§1.7 a) — beschränkt, zyklensicher, gegated.
// ---------------------------------------------------------------------------

/// Ein **Schritt** der Traversierung in C-ABI-Form (§1.2) — drei 32-Byte-Adressen
/// + Tiefe. `#[repr(C)]`, damit das Layout stabil über die Grenze ist.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LakearchStep {
    /// Quell-Daten der Kante.
    pub from: [u8; LAKEARCH_CONTENT_ID_LEN],
    /// Das besessene Kontext-Daten in seiner Kanten-Rolle (§3.1/§3.3).
    pub edge_ctx: [u8; LAKEARCH_CONTENT_ID_LEN],
    /// Ziel-Daten der Kante.
    pub to: [u8; LAKEARCH_CONTENT_ID_LEN],
    /// Tiefe ab dem Start (Start = 0); reines Mechanik-Maß (§1.7 a), kein Wert.
    pub depth: u32,
}

/// Der Callback-Typ für das **Streaming** der Traversier-Schritte. Wird je
/// emittiertem Schritt aufgerufen; `user_data` ist der vom Aufrufer übergebene
/// opake Kontext. Liefert der Callback **0**, wird die Traversierung kooperativ
/// abgebrochen (Backpressure/Deadline; ⇒ [`LakearchStatus::Cancelled`]); jeder
/// andere Rückgabewert setzt sie fort.
pub type LakearchStepCallback =
    extern "C" fn(step: *const LakearchStep, user_data: *mut c_void) -> i32;

/// Beschränkte, zyklensichere Vor-/Rückwärts-Traversierung (§1.2/§1.7 a) ab
/// `start`, die jeden Schritt über `callback` **streamt** (single-trust-domain
/// Embedding; gegated mit leeren Bereichen — beschränkte Nachbarn VANISHen, §11.3).
///
/// - `direction`: 0 = Forward, 1 = Backward, 2 = Both (jeder andere Wert ⇒ Forward).
/// - `max_depth`/`max_nodes`: das **Budget** (§1.7 a); Überschreitung ⇒
///   [`LakearchStatus::TraversalBudgetExceeded`].
/// - `callback`: wird je Schritt aufgerufen; gibt er 0 zurück, bricht die
///   Traversierung ab (⇒ [`LakearchStatus::Cancelled`]).
/// - `out_emitted` (optional, darf `null` sein): erhält die Zahl der dem Callback
///   übergebenen Schritte.
///
/// Die Schritte kommen in der vom Kernel bestimmten aufsteigenden `ContentId`-
/// Adress-Order (§5.2/§1.4) — diese Schicht ordnet **nichts** um (§14.2). Ein
/// `edge_type_filter` wird in v1 dieser FFI **nicht** angeboten (kein Filter); die
/// volle Filter-Signatur lebt am Kernel/Daemon (siehe `DECISIONS-FOR-REVIEW.md`).
///
/// # Safety
/// `start` muss auf [`LAKEARCH_CONTENT_ID_LEN`] lesbare Bytes zeigen. `out_emitted`
/// muss `null` oder ein beschreibbarer `usize` sein. `callback` muss eine gültige
/// Funktion sein; `user_data` wird unverändert durchgereicht.
#[no_mangle]
pub unsafe extern "C" fn lakearch_traverse(
    handle: *const KernelHandle,
    start: *const u8,
    direction: u32,
    max_depth: u32,
    max_nodes: u64,
    callback: LakearchStepCallback,
    user_data: *mut c_void,
    out_emitted: *mut usize,
) -> LakearchStatus {
    guard(|| {
        // SAFETY: Vertrag wie dokumentiert.
        let kernel = match unsafe { KernelHandle::kernel_ref(handle) } {
            Some(k) => k,
            None => return LakearchStatus::InvalidHandle,
        };
        if start.is_null() {
            return LakearchStatus::NullArgument;
        }
        // SAFETY: `start` zeigt laut Vertrag auf 32 lesbare Bytes.
        let start_id = unsafe { read_content_id(start) };
        let dir = match direction {
            1 => Direction::Backward,
            2 => Direction::Both,
            // 0 und alles andere ⇒ Forward (fail-safe, kein Panic).
            _ => Direction::Forward,
        };

        let snapshot = match kernel.pin_snapshot() {
            Ok(s) => s,
            Err(e) => return LakearchStatus::from(e),
        };
        // Single-trust-domain: leere Bereiche (nur unbeschränkte Daten sichtbar,
        // beschränkte VANISHen). Der volle berechtigungs-gegatete Pfad lebt am
        // Daemon (Trust-Modell).
        let capability = match kernel.authorize(GrantedScopes::from_scope_ids([]), snapshot) {
            Ok(c) => c,
            Err(e) => return LakearchStatus::from(e),
        };

        let params = TraversalParams::new(start_id, dir, max_depth, max_nodes, None);
        let cancel = CancelFlag::new();
        let stream = match kernel.traverse_with(params, &capability, snapshot, &cancel) {
            Ok(s) => s,
            Err(e) => return LakearchStatus::from(e),
        };

        let mut emitted: usize = 0;
        for step in stream {
            let step = match step {
                Ok(s) => s,
                Err(e) => {
                    if !out_emitted.is_null() {
                        // SAFETY: oben als nicht-null geprüft, laut Vertrag beschreibbar.
                        unsafe { *out_emitted = emitted };
                    }
                    return LakearchStatus::from(e);
                }
            };
            let c_step = LakearchStep {
                from: *step.from.as_bytes(),
                edge_ctx: *step.edge_ctx.as_bytes(),
                to: *step.to.as_bytes(),
                depth: step.depth,
            };
            // Callback aufrufen. Liefert er 0 ⇒ kooperativer Abbruch. Ein Panic im
            // Callback (fremder C-Code) ist nicht unser UB, aber `guard` fängt
            // einen etwaigen Rust-Unwind ohnehin ab.
            let cont = callback(&c_step as *const LakearchStep, user_data);
            emitted += 1;
            if cont == 0 {
                cancel.cancel();
                if !out_emitted.is_null() {
                    // SAFETY: oben als nicht-null geprüft, laut Vertrag beschreibbar.
                    unsafe { *out_emitted = emitted };
                }
                return LakearchStatus::Cancelled;
            }
        }
        if !out_emitted.is_null() {
            // SAFETY: oben als nicht-null geprüft, laut Vertrag beschreibbar.
            unsafe { *out_emitted = emitted };
        }
        LakearchStatus::Ok
    })
}

// ---------------------------------------------------------------------------
// Test-Stütze: erzwingt einen Panic INNERHALB des `guard`-Wächters, um zu
// beweisen, dass `catch_unwind` ihn fängt (statt UB über die C-Grenze). Diese
// Funktion ist `#[doc(hidden)]` und ausschließlich für den Panic-Sicherheits-Test
// gedacht; sie spiegelt exakt den `guard`-Rumpf, der JEDE echte FFI-Funktion
// umschließt — ein Panic im Rumpf einer `lakearch_*`-Funktion (z. B. ein
// unerwarteter Bibliotheks-Bug) kehrt damit als [`LakearchStatus::Panic`] zurück.
//
// (Anmerkung: ein Panic, der durch eine FREMDE `extern "C"`-Callback-Funktion
// unwindet, abortet bereits am Callback-Rand — das ist Sache des C-Aufrufers, der
// keinen Rust-Panic durch seinen Callback lassen darf. `guard` schützt den
// **eigenen** Rust-Rumpf, der die UB-relevante Stelle ist.)
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn lakearch_force_panic_for_testing() -> LakearchStatus {
    guard(|| {
        panic!("erzwungener Panic im FFI-Rumpf (nur Test): muss von catch_unwind gefangen werden");
    })
}

// ---------------------------------------------------------------------------
// Interne Helfer.
// ---------------------------------------------------------------------------

/// Liest 32 Bytes ab `ptr` in eine [`ContentId`].
///
/// # Safety
/// `ptr` muss auf [`LAKEARCH_CONTENT_ID_LEN`] lesbare Bytes zeigen.
unsafe fn read_content_id(ptr: *const u8) -> ContentId {
    let mut arr = [0u8; LAKEARCH_CONTENT_ID_LEN];
    // SAFETY: laut Vertrag zeigt `ptr` auf 32 lesbare Bytes; `arr` ist 32 Bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, arr.as_mut_ptr(), LAKEARCH_CONTENT_ID_LEN);
    }
    ContentId::from_bytes(arr)
}
