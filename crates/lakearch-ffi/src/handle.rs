//! Das **opake Kernel-Handle** der C-ABI.
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§11 das Tor bleibt die
//! einzige Inhalts-Quelle; §8.4 ein Bestand = ein Kernel) und der Plan (Trust-
//! Modell: das Embedding bedient eine Vertrauenszone).
//!
//! Der Aufrufer sieht **nur** einen opaken `*mut KernelHandle`-Pointer (kein
//! Feld-Zugriff über die Grenze). Die Konstruktion/Freigabe läuft ausschließlich
//! über [`KernelHandle::into_raw`]/[`KernelHandle::drop_raw`] (RAII: genau ein
//! `close` gibt genau einen `open` frei). Diese Schicht ist
//! `#![deny(unsafe_op_in_unsafe_fn)]`.

#![deny(unsafe_op_in_unsafe_fn)]

use lakearch_core::{LakearchKernel, RedbEdgeIndex};

/// Der Kernel hinter dem opaken Handle (Standard-Engine redb).
type FfiKernel = LakearchKernel<RedbEdgeIndex>;

/// Das **opake Handle** auf einen geöffneten Kernel. Über die C-ABI erscheint nur
/// ein `*mut KernelHandle`; das Feld ist privat und außerhalb dieses Crates nicht
/// zugreifbar.
///
/// Ein Handle besitzt **einen** Bestand (= einen [`LakearchKernel`], §8.4) und
/// erlaubt — passend zum sync-threaded Kernel mit `RwLock` — gleichzeitige Leser
/// und einen serialisierten Schreiber. Lebenszeit ist RAII über
/// [`lakearch_open`](crate::lakearch_open)/[`lakearch_close`](crate::lakearch_close).
pub struct KernelHandle {
    kernel: FfiKernel,
}

impl KernelHandle {
    /// Verpackt einen geöffneten Kernel in ein Heap-Handle und gibt den **rohen**
    /// Pointer heraus (Eigentum geht an den C-Aufrufer über; Freigabe nur via
    /// [`KernelHandle::drop_raw`]).
    pub(crate) fn into_raw(kernel: FfiKernel) -> *mut KernelHandle {
        Box::into_raw(Box::new(KernelHandle { kernel }))
    }

    /// Leiht den Kernel hinter einem rohen Handle-Pointer (`&self`-Lesepfad). Gibt
    /// `None`, wenn `handle` `null` ist.
    ///
    /// # Safety
    /// `handle` muss `null` **oder** ein lebendes, von [`KernelHandle::into_raw`]
    /// erzeugtes und noch nicht freigegebenes Handle sein. Die geliehene Referenz
    /// darf das Handle nicht überleben.
    pub(crate) unsafe fn kernel_ref<'a>(handle: *const KernelHandle) -> Option<&'a FfiKernel> {
        if handle.is_null() {
            return None;
        }
        // SAFETY: laut Vertrag ein lebendes, gültig ausgerichtetes Handle; die
        // Lebenszeit `'a` ist an den FFI-Aufruf gebunden (der Aufrufer hält das
        // Handle für die Dauer des Aufrufs).
        let h = unsafe { &*handle };
        Some(&h.kernel)
    }

    /// Gibt ein rohes Handle frei (rekonstruiert den `Box` und droppt ihn — Log/
    /// Index werden sauber geschlossen).
    ///
    /// # Safety
    /// `handle` muss ein lebendes, von [`KernelHandle::into_raw`] erzeugtes und
    /// **noch nicht** freigegebenes Handle sein (nie `null`, nie doppelt).
    pub(crate) unsafe fn drop_raw(handle: *mut KernelHandle) {
        // SAFETY: laut Vertrag genau einmaliges Reclaim eines per `Box::into_raw`
        // erzeugten Pointers; der `Box`-Drop schließt den Kernel.
        let boxed = unsafe { Box::from_raw(handle) };
        drop(boxed);
    }
}
