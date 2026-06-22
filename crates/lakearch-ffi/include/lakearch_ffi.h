/*
 * lakearch_ffi.h — hand-geschriebener C-Header für lakearch-ffi.
 *
 * Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§1.4/§14.2 nur Kernel-
 * Primitive an der Grenze; §11 das Tor; §11.3 VANISH/sichtbarkeits-blind) und der
 * gehärtete Plan (Trust-Modell). Diese C-ABI ist für das IN-PROZESS-Embedding in
 * EINER Vertrauenszone gedacht: der Einbetter ist die vertrauenswürdige Schicht-
 * darüber. Mandantenfähig/reguliert => der Daemon (lakearchd), nicht diese FFI.
 *
 * ABI-Sicherheit: JEDE Funktion fängt einen Rust-Panic intern ab (catch_unwind)
 * und gibt LAKEARCH_PANIC zurück — ein Panic propagiert NIE über die C-Grenze.
 *
 * (Wird cbindgen verfügbar, kann dieser Header daraus generiert werden; bis dahin
 * ist er hand-gepflegt und mit den Rust-Signaturen in src/lib.rs abgeglichen.)
 */
#ifndef LAKEARCH_FFI_H
#define LAKEARCH_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Laenge einer ContentId in Bytes (§5.2). Teil des ABI-Vertrags. */
#define LAKEARCH_CONTENT_ID_LEN 32

/*
 * Fehlercodes (int32, C-ABI-stabil). LAKEARCH_OK = 0; alles andere ist ein
 * definierter, mechanischer (§1.4) und sichtbarkeits-blinder (§11.3) Fehlerzustand.
 * Werte sind eingefroren (append-only erweitern, nie umnummerieren).
 */
typedef enum LakearchStatus {
    LAKEARCH_OK = 0,
    LAKEARCH_PANIC = 1,                     /* gefangener Rust-Panic (statt UB)     */
    LAKEARCH_NULL_ARGUMENT = 2,             /* Null-Pointer/Argument-Verletzung     */
    LAKEARCH_INVALID_HANDLE = 3,            /* ungueltiges Handle / Pfad-Konversion */
    LAKEARCH_NOT_FOUND = 4,                 /* VANISH: verborgen ODER abwesend      */
    LAKEARCH_BUFFER_TOO_SMALL = 5,          /* Puffer zu klein; out_len = benoetigt */
    LAKEARCH_NOT_YET_IMPLEMENTED = 10,
    LAKEARCH_TRAVERSAL_BUDGET_EXCEEDED = 11,
    LAKEARCH_CANCELLED = 12,
    LAKEARCH_INCONSISTENT = 13,             /* fail-closed (§11)                    */
    LAKEARCH_IO = 14,
    LAKEARCH_CORRUPTION = 15,
    LAKEARCH_POISONED = 16,
    LAKEARCH_OTHER = 99
} LakearchStatus;

/* Opakes Handle auf einen geoeffneten Kernel (ein Bestand, §8.4). */
typedef struct KernelHandle KernelHandle;

/*
 * Ein Traversier-Schritt (§1.2): drei 32-Byte-Adressen + Tiefe. repr(C); das
 * Layout ist ABI-stabil.
 */
typedef struct LakearchStep {
    uint8_t from[LAKEARCH_CONTENT_ID_LEN];
    uint8_t edge_ctx[LAKEARCH_CONTENT_ID_LEN];
    uint8_t to[LAKEARCH_CONTENT_ID_LEN];
    uint32_t depth;
} LakearchStep;

/*
 * Streaming-Callback fuer die Traversierung. Wird je emittiertem Schritt
 * aufgerufen; gibt der Callback 0 zurueck, wird die Traversierung kooperativ
 * abgebrochen (=> LAKEARCH_CANCELLED). user_data wird unveraendert durchgereicht.
 */
typedef int32_t (*LakearchStepCallback)(const LakearchStep *step, void *user_data);

/*
 * Oeffnet einen Kernel auf dem Verzeichnis dir_utf8 (dir_len Bytes UTF-8, OHNE
 * NUL) und schreibt das Handle nach *out_handle. Der Aufrufer MUSS das Handle mit
 * lakearch_close() freigeben (RAII). Bei einem Fehler bleibt *out_handle NULL.
 */
LakearchStatus lakearch_open(const char *dir_utf8, size_t dir_len,
                             KernelHandle **out_handle);

/*
 * Schliesst ein Handle und gibt alle Ressourcen frei. NULL => no-op (Ok). Ein
 * doppeltes close desselben Handles ist VERBOTEN.
 */
LakearchStatus lakearch_close(KernelHandle *handle);

/*
 * Haengt len Bytes ab data als atomares Blatt-Daten an (§7.1; Dedup §5.3) und
 * schreibt die 32-Byte-ContentId nach out_content_id (LAKEARCH_CONTENT_ID_LEN
 * Bytes). Inhaltsgleiches dedupliziert => dieselbe ID, kein neuer Record.
 */
LakearchStatus lakearch_append(const KernelHandle *handle, const uint8_t *data,
                               size_t len, uint8_t *out_content_id);

/*
 * Liest das Daten content_id (32 Byte) DURCH DAS TOR (§11) und fuellt
 * out_buf/*out_len mit seinen kanonischen Bytes (§K4).
 *
 * Puffer-Protokoll: *out_len traegt beim Aufruf die Kapazitaet von out_buf; nach
 * Erfolg die geschriebene Laenge. Ist der Puffer zu klein => LAKEARCH_BUFFER_TOO_
 * SMALL und *out_len = benoetigte Laenge (erneut mit groesserem Puffer aufrufen).
 * Nicht sichtbar/nicht vorhanden => LAKEARCH_NOT_FOUND (VANISH, §11.3).
 */
LakearchStatus lakearch_get_by_content_id(const KernelHandle *handle,
                                          const uint8_t *content_id,
                                          uint8_t *out_buf, size_t *out_len);

/*
 * Beschraenkte, zyklensichere Traversierung (§1.2/§1.7 a) ab start (32 Byte), die
 * jeden Schritt ueber callback streamt. direction: 0=Forward, 1=Backward, 2=Both.
 * max_depth/max_nodes = Budget (§1.7 a). out_emitted (optional, darf NULL sein)
 * erhaelt die Zahl der emittierten Schritte. Die Schritte kommen in aufsteigender
 * ContentId-Adress-Order (§5.2/§1.4) — die Grenze ordnet NICHTS um (§14.2).
 */
LakearchStatus lakearch_traverse(const KernelHandle *handle, const uint8_t *start,
                                 uint32_t direction, uint32_t max_depth,
                                 uint64_t max_nodes, LakearchStepCallback callback,
                                 void *user_data, size_t *out_emitted);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LAKEARCH_FFI_H */
