//! Integrationstest, der die `extern "C"`-Funktionen **direkt** ansteuert — so wie
//! ein C-Einbetter es täte (Roh-Pointer, kein Rust-Komfort).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§7.1 append, §5.2 Fetch
//! durchs Tor §11, §1.2/§1.7 a Traversierung) und der gehärtete Plan (Trust-
//! Modell: IN-PROZESS-Embedding, eine Vertrauenszone). Zwei Schwerpunkte:
//!
//! 1. **Roundtrip:** open → append → get (kanonische Bytes zurück) → traverse
//!    (Streaming-Callback) über die rohe C-ABI.
//! 2. **Panic-Sicherheit (UB-Schutz):** ein erzwungener Panic **innerhalb** eines
//!    FFI-Aufrufs wird von `catch_unwind` gefangen und als
//!    [`LakearchStatus::Panic`] zurückgegeben — **kein** Abort, **kein** Unwind
//!    über die C-Grenze.

use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use lakearch_ffi::{
    lakearch_append, lakearch_close, lakearch_force_panic_for_testing, lakearch_get_by_content_id,
    lakearch_open, lakearch_traverse, KernelHandle, LakearchStatus, LakearchStep,
    LAKEARCH_CONTENT_ID_LEN,
};

/// Öffnet einen frischen Kernel in einem temporären Verzeichnis über die rohe
/// C-ABI und liefert das Handle (der Aufrufer muss `lakearch_close` rufen).
fn open_handle(dir: &std::path::Path) -> *mut KernelHandle {
    let path = dir.to_str().expect("utf-8 tempdir");
    let mut handle: *mut KernelHandle = ptr::null_mut();
    let status = unsafe {
        lakearch_open(
            path.as_ptr() as *const std::os::raw::c_char,
            path.len(),
            &mut handle as *mut *mut KernelHandle,
        )
    };
    assert_eq!(status, LakearchStatus::Ok, "open muss gelingen");
    assert!(!handle.is_null(), "open liefert ein nicht-null Handle");
    handle
}

/// Hängt Bytes an und liefert die 32-Byte-ContentId.
fn append(handle: *mut KernelHandle, data: &[u8]) -> [u8; LAKEARCH_CONTENT_ID_LEN] {
    let mut id = [0u8; LAKEARCH_CONTENT_ID_LEN];
    let status = unsafe {
        lakearch_append(
            handle,
            data.as_ptr(),
            data.len(),
            id.as_mut_ptr(),
        )
    };
    assert_eq!(status, LakearchStatus::Ok, "append muss gelingen");
    id
}

#[test]
fn open_append_get_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let handle = open_handle(dir.path());

    // append: ein atomares Blatt.
    let payload = b"lakearch-ffi roundtrip";
    let id = append(handle, payload);
    // Eine ID ist nicht voll-null (BLAKE3 eines nicht-leeren Preimage).
    assert_ne!(id, [0u8; LAKEARCH_CONTENT_ID_LEN]);

    // Dedup (§5.3): zweites identisches append ⇒ dieselbe ID, kein neuer Record.
    let id2 = append(handle, payload);
    assert_eq!(id, id2, "inhaltsgleich ⇒ dieselbe ContentId (§5.3)");

    // get_by_content_id durch das Tor: zuerst die Längen-Abfrage (out_buf=null,
    // out_len=0) ⇒ BufferTooSmall + benötigte Länge.
    let mut needed: usize = 0;
    let status = unsafe {
        lakearch_get_by_content_id(handle, id.as_ptr(), ptr::null_mut(), &mut needed as *mut usize)
    };
    assert_eq!(status, LakearchStatus::BufferTooSmall);
    assert!(needed > 0, "kanonische Bytes haben eine Länge");

    // Jetzt mit ausreichendem Puffer: die kanonischen Bytes (§K4) kommen zurück.
    let mut buf = vec![0u8; needed];
    let mut cap: usize = buf.len();
    let status = unsafe {
        lakearch_get_by_content_id(handle, id.as_ptr(), buf.as_mut_ptr(), &mut cap as *mut usize)
    };
    assert_eq!(status, LakearchStatus::Ok);
    assert_eq!(cap, needed, "geschriebene Länge == benötigte Länge");

    // Die kanonischen Bytes dekodieren strikt zum Original-Blatt (§K6).
    let decoded = lakearch_core::strict_decode(&buf[..cap]).expect("strict_decode");
    assert_eq!(decoded.payload(), Some(&payload[..]));

    // VANISH-Vorform: eine unbekannte ID ⇒ NotFound (ununterscheidbar, §11.3).
    let missing = [0xEEu8; LAKEARCH_CONTENT_ID_LEN];
    let mut len2: usize = 4096;
    let mut sink = vec![0u8; 4096];
    let status = unsafe {
        lakearch_get_by_content_id(
            handle,
            missing.as_ptr(),
            sink.as_mut_ptr(),
            &mut len2 as *mut usize,
        )
    };
    assert_eq!(status, LakearchStatus::NotFound);

    let close = unsafe { lakearch_close(handle) };
    assert_eq!(close, LakearchStatus::Ok);
}

/// Callback: zählt die Schritte (über `user_data` als `*const AtomicUsize`) und
/// gibt 1 (=fortfahren) zurück.
extern "C" fn counting_callback(_step: *const LakearchStep, user_data: *mut c_void) -> i32 {
    if !user_data.is_null() {
        let counter = unsafe { &*(user_data as *const AtomicUsize) };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    1
}

#[test]
fn traverse_streams_steps_through_callback() {
    let dir = tempfile::tempdir().unwrap();
    let handle = open_handle(dir.path());

    // Einen kleinen Graphen bauen: zwei Blätter (über die FFI eingefügt) und ein
    // Knoten, der beide besitzt. Die FFI `lakearch_append` schreibt nur atomare
    // Blätter; den besitzenden Knoten hängt der Einbetter über die crate-
    // öffentliche Kernel-API an (single-trust-domain: der Einbetter ist die
    // vertrauenswürdige Schicht). Da ein Bestand = ein Kernel ist (§8.4), schließen
    // wir das FFI-Handle, hängen den Knoten an denselben durablen Bestand an und
    // öffnen ein frisches Handle (append-only + Dedup garantieren Konsistenz).
    let leaf_x = append(handle, b"x");
    let leaf_y = append(handle, b"y");
    let node = lakearch_core::Datum::node([
        lakearch_core::ContentId::from_bytes(leaf_x),
        lakearch_core::ContentId::from_bytes(leaf_y),
    ])
    .expect("Knoten ist wohlgeformt");

    let close = unsafe { lakearch_close(handle) };
    assert_eq!(close, LakearchStatus::Ok);

    {
        use lakearch_core::Kernel as _;
        let kernel =
            lakearch_core::LakearchKernel::<lakearch_core::RedbEdgeIndex>::open(dir.path()).unwrap();
        let written = kernel.append(&node).unwrap();
        assert_eq!(written, lakearch_core::ContentId::of_datum(&node));
    }

    let handle = open_handle(dir.path());

    // Vorwärts ab dem Knoten: er besitzt die beiden Blätter ⇒ zwei Schritte.
    let counter = AtomicUsize::new(0);
    let mut emitted: usize = 0;
    let node_bytes = *lakearch_core::ContentId::of_datum(&node).as_bytes();
    let status = unsafe {
        lakearch_traverse(
            handle,
            node_bytes.as_ptr(),
            0, // Forward
            8, // max_depth
            1_000, // max_nodes
            counting_callback,
            &counter as *const AtomicUsize as *mut c_void,
            &mut emitted as *mut usize,
        )
    };
    assert_eq!(status, LakearchStatus::Ok);
    assert_eq!(emitted, 2, "der Knoten besitzt zwei Blätter ⇒ zwei Schritte");
    assert_eq!(counter.load(Ordering::Relaxed), 2);

    let close = unsafe { lakearch_close(handle) };
    assert_eq!(close, LakearchStatus::Ok);
}

#[test]
fn forced_panic_inside_ffi_is_caught_as_error_code() {
    // Ein Panic INNERHALB des Rust-Rumpfs einer `extern "C"`-Funktion ist
    // undefiniertes Verhalten, wenn er über die C-Grenze unwindet. `guard`
    // (catch_unwind) umschließt JEDEN FFI-Rumpf und wandelt den Unwind in einen
    // Code. `lakearch_force_panic_for_testing` spiegelt genau diesen Rumpf und
    // erzwingt einen Panic — er muss als LakearchStatus::Panic zurückkehren
    // (KEIN Abort, KEIN Unwind über die Grenze). Liefe der Prozess hier in einen
    // SIGABRT, schlüge der Test (und der Job) hart fehl.
    //
    // Den Default-Panic-Hook für die Dauer des erwarteten Panics stumm schalten,
    // damit die Test-Ausgabe keinen (irreführenden) Backtrace zeigt — der Panic
    // ist hier das erwartete Verhalten, kein Fehler.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let status = lakearch_force_panic_for_testing();
    let status2 = lakearch_force_panic_for_testing();
    std::panic::set_hook(prev_hook);
    assert_eq!(
        status2,
        LakearchStatus::Panic,
        "der Prozess lebt nach dem gefangenen Panic weiter (zweiter Aufruf identisch)"
    );
    assert_eq!(
        status,
        LakearchStatus::Panic,
        "ein Panic im FFI-Rumpf muss als LakearchStatus::Panic zurückkehren (kein Abort/UB)"
    );
}

#[test]
fn null_and_invalid_arguments_return_codes_not_panic() {
    // Null-Handle ⇒ InvalidHandle (kein Panic).
    let mut id = [0u8; LAKEARCH_CONTENT_ID_LEN];
    let status = unsafe { lakearch_append(ptr::null(), b"x".as_ptr(), 1, id.as_mut_ptr()) };
    assert_eq!(status, LakearchStatus::InvalidHandle);

    // close(null) ⇒ Ok (no-op).
    let status = unsafe { lakearch_close(ptr::null_mut()) };
    assert_eq!(status, LakearchStatus::Ok);

    // open mit null out_handle ⇒ NullArgument.
    let status = unsafe {
        lakearch_open(
            b"/tmp".as_ptr() as *const std::os::raw::c_char,
            4,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, LakearchStatus::NullArgument);
}
