# Decisions For Review — autonomer Nacht-Lauf

Protokoll der Entscheidungen, die während des autonomen Übernacht-Laufs getroffen
wurden. **Bitte morgens durchsehen.** Politik: Best-Default wählen + hier
markieren; nur bei wirklich unumkehrbaren Weichen anhalten und warten.

## Vom Nutzer vorab bestätigt (2026-06-22)
- **Kanonik (irreversibel):** RFC 8949 Kerndeterminismus, selbst erzwungen +
  Golden Vectors + zweiter unabhängiger Encoder als Gegenprobe in CI.
- **Checkpoints:** Branch `kernel-impl`, ein Commit pro grüner Phase (deutsche
  Messages, Repo-Stil), **kein Push**.
- **Gabelungen:** Best-Default + Eintrag hier; nur Unumkehrbares blockiert.
- **Qualität:** Fundament zuerst; jede committete Phase ist grün
  (`cargo build` + `cargo test` + `cargo clippy -D warnings`); adversarielle
  Review je Phase.
- **Sprache = Rust**, **Trust-Modell:** Embedding nur Einzel-Vertrauenszone,
  mandantenfähig ⇒ Daemon. **Performance:** erst messen (Benchmark-Gate Phase 1).

## Während des Laufs getroffen

### Phase 0.5 — Irreversibles eingefroren (Branch `kernel-impl`)

- **Kanonik-Encoder (irreversibel):** **hand-gerollt** in `serialize.rs` (RFC 8949
  Kerndeterminismus explizit erzwungen — Major-Type-Köpfe, kürzeste-Form-Längen,
  nur definite-length); **kein** Verlass auf den Default-Output einer CBOR-Crate
  (§K1). Gegenprobe: **zweiter, unabhängiger Encoder** auf Basis `minicbor 2.2.x`
  **nur als dev-dependency** in `tests/canonical_vectors.rs`, muss bytegleich sein
  (§K7). Golden Vectors GV-1..GV-6 (fixe Eingabe → fixe ContentId-Bytes) für immer
  in CI eingefroren (§K8).
- **Datum-Form (irreversibel, Identitätsmodell):** ein Daten ist **entweder** ein
  atomares Blatt (opake Bytes, dedupt auf Bytes allein, §5.3) **oder** ein
  besitzender Knoten (nicht-leere, aufsteigend **sortierte + deduplizierte** Menge
  der `ContentId`s besessener Kontexte, §K2.3). Gemischte/leere Klasse ist im Typ
  unkonstruierbar. **Kein** privilegiertes „Inhalts"-Feld neben den Kontexten
  (§4.3/§2.2). Besitz `A⊳K` ist **keine** adressierbare Entität und bekommt **keine**
  eigene ContentId. **Floats v1-weit verboten** (§K3.4); atomare Nutzlast stets opaker
  Byte-String.
- **DOMAIN_TAG_V1 (irreversibel):** exakt 16 Bytes `b"lakearch/cid/v1\n"`; steht
  **im BLAKE3-Preimage** vor dem CBOR, **nicht** im CBOR selbst.
  `ContentId = BLAKE3(DOMAIN_TAG_V1 || canonical_cbor(D))` — §5.2 (Adresse) und §5.3
  (Dedup) sind zwei Sichten auf **diesen einen** Hash. Künftiges `…/v2\n` ⇒ disjunkter,
  koexistierender ID-Raum.
- **AnchorId:** `u128`-Newtype, bestand-**lokaler** Handle (§9.1/§12.4), **kein**
  Inhalts-Hash — bewusst von `ContentId` getrennt.
- **Platzhalter-Konvention (§3.6):** eingefrorenes Marker-Atom `b"lakearch/unresolved/v1"`
  (22 Byte ASCII), Platzhalter = Knoten, der dieses Atom besitzt. Nur **Konvention**;
  Geschlossenheit erzwingt die schreibende Schicht, nicht der Kernel (§1.4/§7.2).
- **Tor-Typ-Skelett (§11):** `SealedRecord`/`VisibleDatum`/`Capability`/`GrantedScopes`
  außerhalb `gate.rs` **nicht konstruierbar** (private Felder + sealed trait); einzige
  `SealedRecord → VisibleDatum`-Funktion `open` verlangt eine `Capability` →
  „ohne Tor lesen" ist Compile-Fehler. `#![forbid(unsafe_code)]` auf `gate.rs`. **Nur Form**;
  Tor-Logik = Phase 2.
- **Kernel-API-Trait (§1):** Form eingefroren — die drei §1.3-Prädikate **getrennt**,
  `traverse`, Anker-Verben (`get_anchor_members`/`get_member_anchors`), Provenance
  (`find_dependents`/`traverse_provenance_backward`, nur rückwärts), Mutationen nur
  `append`/`set_active_marker`, opaker `SnapshotToken` an **jeder** Read-Signatur. Bodies
  sind Stubs (`KernelError::NotYetImplemented(phase)`).
- **ADR:** `docs/adr/0001-kernel-technology.md` (Sprache=Rust, Encoding, Trust-Modell,
  Engine-Benchmark-Gate) angelegt.

**Vertagte, nicht-blockierende Review-Punkte (für Phase 1):**
- **Segment/Record-Header + reservierte Felder** (`magic + format-version + checksum-algo-id`,
  activation-epoch, constituent-range, **shard-id**, index-validity-offset): in
  `semantics/canonical-encoding.md` spezifiziert, **noch nicht** in Rust-Typen gegossen —
  erst mit dem Append-Log in Phase 1 (kein Byte des Logs ist vor Phase 1 geschrieben).
- **`trybuild`-Compile-Fail-Test** für die Tor-Unumgehbarkeit: in `gate.rs` als
  auskommentierte Negativ-Fälle dokumentiert; maschinelle Einfrierung in Phase 2.
- **`loom`/`Miri`/`cargo-deny`-CI-Gates**: ab Phase 1 (es gibt in Phase 0.5 noch keinen
  lock-free/`unsafe`-Code).
- **GV-4-Längen-Notiz:** maßgeblich ist das Layout `A1 00 58 18`+24 = **28 Bytes**
  (in Spec §K8 GV-4 und im Test fixiert). Ein veralteter Kommentar in `serialize.rs`
  spricht noch von einem „27"-Tippfehler der Spec-Prosa; die Spec ist inzwischen korrekt
  (28) — Kommentar bei Gelegenheit aufräumen (nicht blockierend).

### Phase 1 — On-Disk-Format-Schicht (`format.rs`, Branch `kernel-impl`)

Reine **in-memory** Kodierung/Dekodierung des Segment-Log-Framings; **keine**
Datei-I/O (die kommt mit dem `pwrite`-Log-Writer/-Reader später in Phase 1).

- **Magic-Bytes:** Record-Frame = `b"LKR1"` (`4C 4B 52 31`), Batch-Footer =
  `b"LKF1"` (`4C 4B 46 31`). Bewusst **verschieden**, damit ein Footer beim
  Record-für-Record-Recovery-Scan nie als Record fehlgedeutet wird.
- **Prüfsumme (`checksum-algo-id = 1`):** **BLAKE3**, volle 32-Byte-Default-
  Ausgabe. Gewählt statt CRC, weil BLAKE3 schon Kern-Abhängigkeit (ContentId,
  §K5) ist, jeden Ein-Bit-Flip sicher erkennt und schnell ist. Die Prüfsumme ist
  **nur** Framing-Integrität — **kein** Teil des ContentId-Preimage.
- **Byte-Reihenfolge:** alle Mehrbyte-Integer **little-endian** (native x86-64/
  aarch64), einmal festgelegt und dokumentiert.
- **Record-Layout (fester 64-Byte-Header, `format-version = 1`):**
  `magic(4) | format_version(u16) | checksum_algo_id(u16) | seq(u64) |
  payload_length(u64) |` reservierte NULL-Felder `activation_epoch(u64) |
  marker_offset(u64) | constituent_range(u64) | shard_id(u32) |
  index_validity_offset(u64) | reserved_pad(u32)`, danach `payload` und
  `checksum(32)` über `Header ‖ Payload`. Gesamt = `64 + payload_len + 32`.
- **Batch-Footer-Layout (fester 64-Byte-Rumpf, `format-version = 1`):**
  `magic(4) | format_version(u16) | checksum_algo_id(u16) | record_count(u64) |
  first_seq(u64) | last_seq(u64) |` reservierte NULL-Felder
  `activation_epoch(u64) | shard_id_packed(u64) | index_validity_offset(u64) |
  reserved_pad(u64)`, danach `checksum(32)` über den Rumpf. Gesamt = `64 + 32`.
- **Reservierte Felder** (für spätere Phasen, damit das append-only-Format **nie**
  geändert werden muss, §K5.1): in v1 stets **NULL**; per Test (`reserved_*_fields_
  round_trip_as_zero`) abgesichert.
- **Striktheit (§Durability):** truncierter Header/Payload/Footer, falsches Magic,
  unbekannte `format-version`/`checksum-algo-id` und jede Prüfsummen-Verletzung ⇒
  definierter Fehler `KernelError::Inconsistent` — **nie** stilles Überspringen.
  seq-Lücken-Prüfung gehört in den Reader/Recovery (nächster Phase-1-Schritt),
  nicht in die reine Frame-Dekodierung.
- **`#![forbid(unsafe_code)]`** bleibt auf `format.rs` (nur Slice-/`Vec`-Arbeit);
  `unsafe` bleibt dem späteren log/mmap-Leaf-Modul vorbehalten.

**Index-Engine (Notiz, noch nicht implementiert):** **RocksDB heute bewusst
ausgeschlossen** — `libclang` fehlt in dieser Umgebung (RocksDB-bindgen braucht
es). Gewählt wird **redb** (pure-Rust); da das **Log die alleinige Wahrheit** ist
(§8.4) und die Sekundär-Indizes reine, neu-baubare Derivate sind, ist die Engine
**billig revidierbar** — das de-riskt redbs relative Jugend. Edge-Index hinter
einem Trait (owned `ContentId`s), redb als konkrete Impl; folgt nach der
Format-Schicht in Phase 1.

### Phase 1 — Append-Segment-Log (`log.rs`, Branch `kernel-impl`)

Die Datei-I/O-Schicht über dem Framing aus `format.rs`. Höchstrisiko-Modul;
rigoros + breit getestet (20 Log-Tests). **Grün:** `cargo build --all-targets`,
`cargo test` (89 Tests), `cargo clippy --all-targets -D warnings`.

- **Abhängigkeiten:** `memmap2 = "0.9"` (read-only mmap, dependency),
  `tempfile = "3"` (dev-dependency für Tests).
- **Schreibpfad `pwrite`:** Records werden per
  `std::os::unix::fs::FileExt::write_at`/`write_all_at` geschrieben — **nie**
  mmap-Stores fürs Log (§Durability). mmap ist ausschließlich **read-only**.
- **Group-Commit:** `append_record` puffert nur (in-memory `pending`-Vec);
  `commit` schreibt `Records ‖ Footer` ab dem committed offset, `fsync`t die
  Daten und veröffentlicht **erst danach** den neuen committed offset (Watermark
  `W`). `append_and_commit` ist der Ein-Record-Bequempfad.
- **Durability-on-Ack:** ein Record ist erst **nach** dem einschließenden
  Group-Commit-`fsync` geackt/sichtbar; vorher liegt er nur im Pending-Puffer und
  ist für Leser unsichtbar (Test `uncommitted_append_is_invisible_until_commit`,
  `uncommitted_tail_is_dropped_on_reopen`).
- **fsync-Fehler = fatal (errseq):** vergiftet das Log (`poisoned`-Flag,
  `KernelError::Poisoned`); **nie** Retry-als-Erfolg. Auch der Verzeichnis-`fsync`
  nach Segment-Erstellung ist fatal-bei-Fehler.
- **Lesepfad read-only mmap:** gemappt **nur bis `committed_offset`** (fester
  `MmapOptions::len`), nie über EOF / in den Schreibbereich (kein Torn-Read/
  SIGBUS). **Prüfsumme wird VOR Herausgabe der Bytes verifiziert** (`decode_record`).
  Test `mmap_reads_never_exceed_committed_offset` belegt den Map-Umfang.
- **monotone seq je physischem Record:** Dedup-Treffer (§5.3) liegen ÜBER diesem
  Modul (die schreibende Schicht entscheidet, ob überhaupt geschrieben wird) —
  `log.rs` vergibt seq strikt fortlaufend für jeden übergebenen Record und nimmt
  den Stand nach Reopen wieder auf.
- **Recovery (zwei getrennte Begriffe):** **strukturelles Vorrücken** über die
  Frame-Länge (Header-`payload_length`) erlaubt es, **über einen prüfsummen-
  defekten Record hinweg** weiterzuscannen, um einen *späteren* gültigen Footer zu
  finden; **Integritäts-Validierung** (Prüfsumme/seq-Kette/Footer-Felder) vermerkt
  den **ersten** Defekt. committed offset = Ende des letzten gültig
  abgeschlossenen Batches; **erster Defekt strikt VOR committed offset ⇒
  `KernelError::Corruption` (HALT, kein Auto-Truncate)**; Defekt am/nach committed
  offset ⇒ nur un-ackter Tail → trunkiert (`set_len` + `fsync`). Tests decken:
  torn mid-record, torn mid-footer, voller Record ohne Footer (verworfen),
  gekipptes Byte im ersten/nicht-ersten committeten Record (HALT), beschädigter
  committeter Footer vor dem letzten (HALT).
- **`unsafe`-Kapselung:** `log.rs` ist das **einzige** `unsafe`-Leaf-Modul (genau
  **ein** `MmapOptions::map`-Aufruf) mit `#![deny(unsafe_op_in_unsafe_fn)]` +
  SAFETY-Kommentar; `gate.rs`/`format.rs` bleiben `#![forbid(unsafe_code)]`.
- **Neue `KernelError`-Varianten:** `Io` (operativer I/O-Fehler), `Corruption`
  (beschädigte durable Daten → HALT), `Poisoned` (Log nach fatalem Fehler).
- **Bewusste Vereinfachungen (Phase 1, nicht-blockierend):**
  - **Ein Segment** (`000000000000.seg`); Roll-over/Mehr-Segment-LRU ist ein
    späterer Schritt. Der Dateiname ist sortierbar-gepolstert, damit das ohne
    Format-Bruch erweiterbar ist; Segment-Erstellung löst bereits den
    Directory-`fsync` aus.
    `LogMetrics.segment_count` ist in v1 stets 1.
  - **Externe Out-of-Band-Truncation/Korruption** eines gemappten Segments durch
    Dritte ist ein **Operator-Vertragsbruch** (§Sicherheit) und außerhalb der
    SIGBUS-Garantie; ein dedizierter `SIGBUS`-Handler ist ein späterer Härtungs-
    Schritt. Korruption **innerhalb** des durablen Präfixes (z. B. Bit-Rot)
    wird durch die Prüfsumme-vor-Herausgabe erkannt (`read_all`/`read_at` ⇒
    `Corruption`).
  - **Recovery liest das Segment via `pread` in einen `Vec`** (nicht mmap), weil
    der Tail torn/un-ackt sein darf; ein mmap des ganzen (evtl. torn) Files wäre
    SIGBUS-riskant. Bei sehr großen Historien werden hier in einer späteren Phase
    Checkpoints/segmentweises Streaming gebraucht (RTO-Bindung, vgl. Plan).
  - **Group-Commit ist noch nicht die volle MPSC-Pipeline:** `SegmentLog` ist der
    eine Append-Pfad (`&mut self`); die lock-free Producer-Queue + Loom-Tests
    folgen mit der `Kernel::append`-Verdrahtung.

### Phase 1 — Content-Store + Sekundär-Indizes (`store.rs`, `index.rs`, Branch `kernel-impl`)

Der Content-Store über dem Log (`store.rs`) und die abgeleiteten Kanten-Indizes
(`index.rs`, redb). **Grün:** `cargo build --all-targets`, `cargo test`
(97 lib + 12 Kanonik-Vektoren + 5 Store-Integration = 114 Tests),
`cargo clippy --all-targets -D warnings`.

- **Neue Abhängigkeit:** `redb = "2"` (löst auf **redb 2.6.3**, pure-Rust, baut mit
  Rust 1.96). **RocksDB heute bewusst ausgeschlossen** (libclang fehlt für
  RocksDB-bindgen); LMDB/heed nicht aufgenommen. Da das **Log die alleinige
  Wahrheit** ist (§8.4) und die Indizes reine, neu-baubare Derivate sind, ist die
  Engine **billig revidierbar** — das de-riskt redbs relative Jugend.
- **`strict_decode` (§K6) in `serialize.rs` ergänzt:** der Neu-Bau aus dem Log
  (und `get_by_content_id` als `Datum`) braucht die **strikte** Umkehr der
  Kanonisierung. `strict_decode(canonical_cbor(d)) == d` und Idempotenz
  (`re-encode == bytes`) sind getestet; jede nicht-kanonische Eingabe (nicht-
  kürzeste Länge §K3.1, indefinite-length §K3.2, Tag/Float/Simple §K3.4–§K3.6,
  fremder Schlüssel, gemischte/leere Klasse §K2.1, **unsortierte/doppelte** `owns`
  §K2.3, Rest-Bytes) ⇒ `KernelError::Inconsistent`. **Nie** stilles
  Re-Kanonisieren.

- **EdgeIndex-Trait-Form (eingefroren als Form, Logik bleibt mechanisch §1.3):**
  - `commit_edges(&mut self, edges: &[Edge], new_watermark: u64) -> Result<(),_>`
    — **eine** atomare Transaktion für Kanten **und** Watermark (§8.4); Watermark
    monoton nicht-fallend (Rückschritt ⇒ `Inconsistent`).
  - `contexts_of(owner) -> Vec<ContentId>` (Vorwärts, `owner→contexts`, §1.2/§3.2).
  - `referrers_of(target) -> Vec<ContentId>` (Rückwärts, `target→referrers`,
    §1.2/§10.3) — Grundlage der Invalidierung.
  - `watermark() -> u64` (§8.4-Watermark).
  - `scan_owners(start, end) -> Vec<(ContentId, Vec<ContentId>)>` (Präfix-/Range-
    Scan über die 32-Byte-Adress-Order, halb-offen `[start, end)`).
  - `wipe()` (alles löschen + Watermark→0, atomar; reines Derivat §8.4).
  Alle Rückgaben sind **owned** `ContentId`s (keine geliehenen redb-Guards lecken)
  und **aufsteigend** in 32-Byte-Order (deterministischer, föderationsstabiler
  Tiebreak; §5.2/§1.4, **kein** Wert-Sort). `Edge { owner, context }` ist nur ein
  Index-Eintrag, **keine** adressierbare Entität (§2.2/§K2.2).

- **redb-Schema/Tabellen-Layout (`RedbEdgeIndex`):**
  - `owner_contexts` : **Multimap** `[u8;32] → [u8;32]` (Vorwärts: owner→context).
  - `target_referrers` : **Multimap** `[u8;32] → [u8;32]` (Rückwärts: target→owner).
  - `watermark` : Tabelle `&str → u64`, **ein** Eintrag `"log_offset"` — im
    **selben Commit** wie die Kanten geschrieben (transaktionale Atomarität, §8.4).
  - Schlüssel/Werte sind die rohen 32 `ContentId`-Bytes (redb `[u8; 32]`-Key).
  - **Durability:** Index-Commits laufen mit `Durability::Immediate`. Bei Verlust/
    Vorauseilen ist der Index als reines Derivat neu baubar — nie die Wahrheit.

- **Content-Store (`ContentStore<I: EdgeIndex>`):**
  - `append_datum(&Datum)`: kanonisiert → `ContentId::of_datum` (§K5) → **Dedup**
    (in-memory `HashMap<ContentId, Offset>`): existiert die ID, **kein** Record,
    **keine** seq, Dedup-Zähler+1, vorhandene ID zurück (§5.3). Sonst:
    `append_and_commit` ans Log (**Log-fsync ZUERST**), Offset in die Dedup-Karte,
    **danach** `commit_edges` in den Index (**log-fsync → index-commit**, §8.4),
    Watermark = neuer committed Log-Offset.
  - `get_canonical_bytes` / `get_by_content_id`: Dedup-Karte → `read_at` (Prüfsumme
    verifiziert) → optional `strict_decode` zum `Datum`. Defensiv: zurückgelesene
    Form muss dieselbe ID tragen (sonst `Inconsistent`). **Noch kein Tor** in
    diesem Stand (Tor-Sichtbarkeit/VANISH ist Phase 2; der `SealedRecord`-Pfad
    folgt mit der `Kernel`-Trait-Verdrahtung).
  - **Reine Derivate, beim Öffnen rekonstruiert (§8.4):** Dedup-Karte stets
    vollständig aus dem Log; Index versöhnt (`W==T` sync, `W<T` Records ab Offset
    `W` nachspielen, `W>T` **voller Neu-Bau** — keine Suffix-Chirurgie).
    `rebuild_index_from_log()` = wipe + ganzen Log replayen.
  - **Metriken** (`StoreMetrics`): `append_count`, `dedup_hit_count`, `edge_count`.

- **Tests (alle grün):** owner/referrer-Kanten in beide Richtungen; Dedup
  (Log-Länge unverändert + Dedup-Zähler); **Wipe-&-Rebuild identisch**; Watermark
  monoton; Reopen konsistent (W==T); Lag-Replay (W<T, ohne Wipe); Index-Voraus
  (W>T ⇒ Neu-Bau); Blatt hat keine Kanten; `strict_decode` Round-Trip +
  Ablehnung nicht-kanonischer Eingaben; redb-Direkttests (beide Richtungen,
  Watermark, Wipe, Reopen, Range-Scan, Idempotenz).

**Vertagte, nicht-blockierende Punkte (Phase 1+):**
- **RocksDB/LMDB-Vergleichs-Benchmark vertagt:** das Engine-Benchmark-Gate
  (redb vs LMDB(heed) vs RocksDB: 100M–1Mrd Tiny-Edges, Write/Space-Amplification,
  p99-Referrer-Präfix-Scan, COW-Reader-File-Bloat) bleibt offen, bis libclang
  verfügbar ist bzw. der Bedarf gemessen wird. Die `EdgeIndex`-Abstraktion ist
  genau dafür da — die Engine ist hinter dem Trait austauschbar (§Storage-Engine).
- **`Kernel`-Trait-Verdrahtung** (`append`/`get_by_content_id` über das Tor mit
  `SealedRecord`/`Capability`/`SnapshotToken`): **erledigt** — siehe Abschnitt
  „Phase 1 — Kernel-Verdrahtung" unten. Die Tor-**Sichtbarkeitslogik** (VANISH,
  Bereichs-Filter) und die volle Snapshot-Epochen-Semantik bleiben Phase 2/5.
- **Index-Durability vs. einzige reale Barriere:** Index nutzt aktuell
  `Durability::Immediate` (zwei fsyncs pro Append). Der Plan sieht einen
  nicht-durablen/checkpointed Index mit **einer** realen Barriere vor; da der Index
  neu baubar ist, ist die Umstellung billig und für eine spätere Performance-Runde
  vorgesehen (vgl. Risiko „Doppelte Durability-Barriere/Skew").

### Phase 1 — Kernel-Verdrahtung (`kernel.rs`, Branch `kernel-impl`)

Die konkrete `Kernel`-Implementierung `LakearchKernel<I: EdgeIndex>` über dem
`ContentStore`. **Grün:** `cargo build --all-targets`, `cargo test`
(102 lib + 12 Kanonik + 5 Store-Integration + 3 Kernel-E2E = 122 Tests),
`cargo clippy --all-targets -D warnings`.

- **`LakearchKernel<I>`** besitzt den `ContentStore<I>` hinter einem
  `std::sync::RwLock` (der Store ist der eine Append-Pfad `&mut self`, der
  `Kernel`-Vertrag führt jedes Verb über `&self`): `append` nimmt den Schreib-Lock,
  Lesepfade den Lese-Lock. Ein **vergifteter Lock** ⇒ `KernelError::Poisoned`
  (fail-closed, §11). Die volle lock-freie MPSC-/Group-Commit-Pipeline ist eine
  spätere Phase. `LakearchKernel::open(dir)` ist die Standard-Konstruktion mit der
  redb-Engine (`dir/log` + `dir/index.redb`).
- **Verdrahtete Phase-1-Verben:** `append` (§7.1, Dedup §5.3, Index erst nach
  Log-`fsync` §8.4 — alles delegiert an `ContentStore::append_datum`) und
  `get_by_content_id` (§5.2-Fetch, liefert ein `SealedRecord` durchs Tor §11 via
  neuem `ContentStore::get_sealed`). **`pin_snapshot`/`authorize` minimal
  verdrahtet** (statt der Trait-Stubs), damit ein Ende-zu-Ende-Lesepfad existiert:
  `pin_snapshot` pinnt am aktuellen durablen Watermark `W` (committed Log-Offset);
  `authorize` stellt eine `Capability` aus, **ohne** schon Berechtigungen zu
  matchen (Tor-Logik = Phase 2). Alle übrigen Verben (Matching, Traversierung,
  Anker, Provenance, `set_active_marker`) bleiben die phasenrichtigen
  `NotYetImplemented`-Stubs des Trait-Defaults (Test
  `unwired_verbs_still_report_their_phase`).
- **`SealedRecord` trägt jetzt echte Bytes (statt Skelett-Spiegel):**
  `SealedRecord::seal(content_id, canonical_bytes)` (crate-intern) hält die
  durablen kanonischen CBOR-Bytes (§K4); `open` legt sie als
  `VisibleDatum::canonical_bytes()` frei — die **einzige** Stelle, an der die
  Roh-Sicht einen Leser erreicht, und **nur** gegen eine `Capability` (§11.5). Der
  frühere `revealed_content_id()`-Skelett-Getter ist durch `canonical_bytes()`
  ersetzt. Die Compile-Zeit-Unumgehbarkeit bleibt: kein Inhalts-Getter auf
  `SealedRecord`, `Capability`/`VisibleDatum` unfälschbar (privat + `Sealed`).
- **`GrantedScopes::from_scope_ids` jetzt `pub`** (war `pub(crate)`): `GrantedScopes`
  ist das **Eingabe-Subjekt** des Lesers, das die Schicht darüber dem Kernel vorlegt
  (§11.1) — daher öffentlich konstruierbar. Das bricht die Tor-Garantie **nicht**:
  das Tor (Phase 2) *validiert* die Scopes gegen die auditierten Berechtigungen,
  bevor es eine `Capability` ausstellt; `Capability`/`VisibleDatum` bleiben
  unfälschbar. (Korrigiert die Phase-0.5-Notiz „GrantedScopes außerhalb gate.rs
  nicht konstruierbar" — die Unfälschbarkeit liegt bei `Capability`/`VisibleDatum`,
  nicht beim bloßen Scopes-Eingabewert.)
- **Metriken (§Betrieb):** `KernelMetrics` über `LakearchKernel::stats()` fasst die
  Store- und Log-Zähler zu **einer** sichtbarkeits-blinden (§11.3) Lese-Sicht
  zusammen: `append_count`, `dedup_hit_count`, `edge_count`, `batch_count`,
  `fsync_count`, `segment_count`, `committed_bytes`. `append_count`/`dedup_hit_count`
  sind Prozess-Mechanik-Zähler (nicht persistiert; nach einem Reopen 0, die Daten
  selbst sind durabel).
- **Tests:** Ende-zu-Ende `append → get_by_content_id → open → strict_decode`
  (lib + öffentliche `tests/kernel_e2e.rs`); Dedup spiegelt sich in `stats`; Reopen
  von Platte liest zurück (committeter Watermark überlebt, Dedup-Karte aus dem Log
  rekonstruiert); unbekannte ID ⇒ `None` (VANISH-Vorform); nicht-verdrahtete Verben
  melden weiter ihre Phase.

### Phase 1 — Review-Härtung (blockierende Findings behoben, Branch `kernel-impl`)

Zwei blockierende Review-Findings adressiert; beide **warranted** ⇒ behoben (keine
Wegerklärung). **Grün:** `cargo build --all-targets`, `cargo test`
(105 lib + 12 Kanonik + 3 Kernel-E2E + 5 Store-Integration = 125 Tests),
`cargo clippy --all-targets -- -D warnings`.

- **Finding 1 (Durability) — Recovery verlor still geackte Daten bei Header-
  Korruption.** Der alte Recovery-Scan (`log.rs::scan_segment`) rückte über einen
  Record per `record_frame_len` vor, das die **unverifizierte** `payload_length`
  (Header-Bytes 16..24) las. Ein gekipptes Längen-Byte eines bereits geackten
  Records ließ den Vorlauf den nachfolgenden Batch-Footer **verschlucken**;
  `committed_offset` blieb bei 0 (Einzel-Batch) bzw. einem früheren Wert, der
  HALT-Guard `d < committed_offset` zündete nicht (`0 < 0` ist falsch), und
  `recover()` trunkierte die **geackten** Daten als vermeintlichen un-ackten Tail.
  Das verletzte den Durability-Vertrag (Plan „Durability/Recovery": Defekt VOR dem
  letzten Footer ⇒ **HALT**, nie auto-truncate; §7.1; §8.4).
  **Behebung (zwei Elemente):**
  1. **Defekter Header ist nicht vertrauenswürdig.** Schlägt `decode_record` die
     Prüfsumme eines Records fehl (ein gekipptes `payload_length` verfälscht die
     Prüfsumme über `Header ‖ Payload` immer), wird **nicht** über die im Header
     genannte Länge vorgerückt. Stattdessen sucht `next_frame_magic` **byteweise**
     das nächste Frame-Magic (`LKR1`/`LKF1`), sodass spätere gültige Footer
     weiterhin gefunden werden. `record_frame_len` ist entfernt.
  2. **Der Footer ist die Commit-Autorität.** Ein prüfsummen-**gültiger** Batch-
     Footer beweist, dass der mit ihm endende Byte-Bereich durable committet ist;
     `committed_offset` = Ende des **letzten** gültigen Footers (nicht aus
     unverifizierten Längen abgeleitet). HALT, sobald der erste Defekt **strikt
     vor** diesem committed offset liegt — einschließlich des Einzel-Batch-Falls,
     in dem der gekippte Record der allererste vor einem sonst gültigen Footer ist.
  **Neue Tests:** `recovery_halts_on_corrupt_payload_len_in_single_committed_batch`
  (Szenario A), `…_in_first_of_two_committed_batches` (B) und
  `…_on_shrunk_payload_len_in_committed_record` (C) — jeweils `Err(Corruption)`
  **und** Datei NICHT trunkiert. Alle bestehenden Torn-Tail-Regressionen
  (mid-record, mid-footer, voller Record ohne Footer, sauberer Multi-Batch, korrupte
  Nutzlast/Footer-Body) bleiben grün.

- **Finding 2 (Axiom-Treue §11) — ungegateter Byte-Zugriff verließ das Crate.**
  `ContentStore::get_canonical_bytes` und `…::get_by_content_id` waren `pub` und gaben
  Roh-CBOR-Bytes bzw. ein voll dekodiertes `Datum` **ohne** das Tor heraus; der
  öffentliche Integrationstest nutzte diesen Bypass. Das widersprach §11.2/§11.5
  („unumgehbares, manipulationssicheres Tor; jeder Lesevorgang passiert es") und der
  `gate.rs`-Zusage „ohne Tor lesen ist im Typsystem nicht darstellbar".
  **Behebung:** beide Methoden auf `pub(crate)` gesetzt; die `Datum`-Variante
  (nur noch von crate-internen Tests genutzt) zusätzlich `#[cfg(test)]`. Der
  **einzige** externe Lese-Pfad ist jetzt `ContentStore::get_sealed` (+ `gate::open`
  gegen eine `Capability`) bzw. der `Kernel`-Vertrag. Interne Aufrufer
  (`get_sealed`, Reconcile-/Rebuild-Pfade) laufen unter `pub(crate)` unverändert.
  `tests/store_index.rs::get_by_content_id_round_trips` ist auf den gegateten
  `LakearchKernel`-Pfad (`pin_snapshot → authorize → get_by_content_id → open`)
  umgestellt. Da `Capability` außerhalb von `gate.rs` nicht konstruierbar ist, kann
  externer Code die versiegelten Bytes nur durchs Tor öffnen — die Compile-Zeit-
  „kein-ungegateter-Byte-Zugriff"-Eigenschaft ist wiederhergestellt.

- **Index-Engine-Notiz (RocksDB heute ausgeschlossen, redb gewählt):** bleibt gültig
  (siehe oben „Index-Engine"-Notiz): `libclang` fehlt in dieser Umgebung
  (RocksDB-bindgen braucht es); **redb** ist pure-Rust. Weil das **Log die alleinige
  Wahrheit** ist (§8.4) und die Indizes reine, neu-baubare Derivate sind (hinter dem
  `EdgeIndex`-Trait, der owned `ContentId`s liefert), ist die Engine **billig
  revidierbar** — das de-riskt redbs relative Jugend. Das Vergleichs-Benchmark-Gate
  (redb vs LMDB/heed vs RocksDB) bleibt offen, bis libclang verfügbar bzw. der Bedarf
  gemessen ist.

### Phase 1 — Abschluss & Commit (Branch `kernel-impl`)

Phase 1 ist **fertig und grün** und wird als ein Commit eingefroren (Politik:
ein Commit pro grüner Phase). **Grün verifiziert** (`source $HOME/.cargo/env`,
in `/home/nanu/lakearch`):
- `cargo build --all-targets` — sauber.
- `cargo test` — **125 Tests** grün: 105 lib-Unit + 12 Kanonik-Vektoren
  (`tests/canonical_vectors.rs`) + 3 Kernel-E2E (`tests/kernel_e2e.rs`) + 5
  Store-Integration (`tests/store_index.rs`); 0 fehlgeschlagen, 0 ignoriert.
- `cargo clippy --all-targets -- -D warnings` — sauber (Exit 0).

Damit deckt Phase 1 ab: `pwrite`-Append-Log (alleinige Wahrheit, §8.4) +
read-only-mmap + Group-Commit + Recovery (HALT bei Korruption vor dem letzten
Footer, Tail-Truncate danach), die redb-Kanten-Indizes hinter dem
`EdgeIndex`-Trait (`owner→contexts` / `target→referrers`, §1.2/§10.3) als reine
neu-baubare Derivate (Wipe-&-Rebuild getestet, §8.4), der Content-Store mit
Wert-Dedup (§5.3), die gegatete `Kernel::append`/`get_by_content_id`-Verdrahtung
(§7.1/§5.2 durchs Tor §11) und die Betriebs-/Metrik-Basis (§Betrieb). Die
inhaltlichen Phase-1-Entscheidungen stehen in den Abschnitten oben
(`format.rs`, `log.rs`, `store.rs`/`index.rs`, `kernel.rs`, Review-Härtung).

**Vertagte, nicht-blockierende Punkte (für Phase 2+ / spätere Performance-Runde):**
- **RocksDB/LMDB-Vergleichs-Benchmark (Engine-Benchmark-Gate):** vertagt, bis
  `libclang` verfügbar ist (RocksDB-bindgen braucht es) bzw. der Bedarf gemessen
  wird. Messpunkte laut Plan: 100M–1Mrd Tiny-Edges nebenläufig ingesten,
  Write/Space-Amplification, p99-Referrer-Präfix-Scan, COW-Reader-File-Bloat;
  Kandidaten **redb vs LMDB(heed) vs RocksDB**. Die `EdgeIndex`-Abstraktion (owned
  `ContentId`s) ist genau dafür da — die Engine ist hinter dem Trait austauschbar,
  und da das Log die Wahrheit ist, ist der Wechsel billig (§Storage-Engine).
- **`dm-flakey`/CrashMonkey-Fault-Injection vertagt:** der Plan verlangt echte
  Fehler-Injektion (reordered/lost/partial I/O über Segment-, Footer-,
  Dir-Entry-, Index-Grenzen), nicht nur sauberen Prozess-Kill. Aktuell ist die
  Crash-Konsistenz durch **deterministische Recovery-Tests** abgedeckt (torn
  mid-record/mid-footer, voller Record ohne Footer, gekipptes Byte / verfälschte
  `payload_length` im committeten Präfix ⇒ HALT, kein Auto-Truncate). Die echte
  Block-Layer-Fault-Injection (Kernel-`dm-flakey`-Device) braucht Root/Geräte-Setup
  und wird in einer dedizierten Härtungs-Runde nachgezogen (vgl. Plan
  „Durability/Recovery", Verifikation Punkt 2).
- **`loom` für die künftige MPSC-/Group-Commit-Pipeline vertagt:** `SegmentLog`
  ist heute der **eine** Append-Pfad (`&mut self`), und `LakearchKernel` serialisiert
  Appends über einen `RwLock` — es gibt in Phase 1 noch **keinen** lock-freien
  MPSC-Producer-Pfad, also nichts, was `loom` modellieren könnte. Sobald die
  lock-freie Producer-Queue + Group-Commit-Pipeline gebaut wird (spätere Phase),
  kommen `loom`-Modelle (plus `Miri` für etwaigen zerocopy-Code) als CI-Gate dazu
  (vgl. Plan „Sicherheit, `unsafe` & Verifikations-Tooling").
- **Index-Durability vs. einzige reale Barriere:** der Index nutzt aktuell
  `Durability::Immediate` (zwei fsyncs pro Append). Der Plan sieht einen
  nicht-durablen/checkpointed Index mit **einer** realen Barriere vor; da der Index
  neu baubar ist, ist die Umstellung billig (spätere Performance-Runde, Risiko
  „Doppelte Durability-Barriere/Skew").

### Phase 2 — Mechanische Traversierung + Tor-Logik (Branch `kernel-impl`)

Die drei §1.3-Match-Prädikate, die beschränkte zyklensichere Traversierung
(`traverse.rs`) und die **Tor-Sichtbarkeitslogik** (§11: Filter-vor-Auflösen,
VANISH, fail-closed, sichtbarkeits-blind). **Grün:** `cargo build --all-targets`,
`cargo test` (127 lib + 12 Kanonik + 5 Kernel-E2E + 5 Store = 149 Tests),
`cargo clippy --all-targets -- -D warnings`.

> **⚠ SICHERHEITS-RELEVANTER POLICY-DEFAULT — bitte bestätigen.**
> **Ein Daten OHNE Bereichs-Zugehörigkeit gilt als UNBESCHRÄNKT (für alle
> sichtbar).** Bereiche (§11.1) sind damit **additive Restriktionen**: erst eine
> Bereichs-Zugehörigkeit beschränkt ein Daten; ohne sie ist es allgemein lesbar.
> Begründung: lakearch ist domänen-frei; die meisten Daten tragen anfangs keinen
> Bereich, und ein „fail-closed-by-default" (alles unsichtbar, bis ein Bereich
> gewährt) würde einen frisch befüllten Bestand **vollständig blind** machen und
> die Bereichs-Semantik gegen §11.1 invertieren (dort ist Zugehörigkeit eine
> *Hinzufügung*, kein Pflichtfeld). **Fail-closed gilt weiterhin für Korruption/
> Inkonsistenz** (Index-/Log-Fehler ⇒ DENY), **nicht** für „kein Bereich
> zugewiesen". Wer das Gegenteil will (jedes Daten muss explizit einem Bereich
> angehören, sonst unsichtbar), sagt Bescheid — die Umkehr ist eine **ein-Zeilen-
> Änderung** in `gate::is_visible` (das `areas.is_empty() ⇒ true` zu `⇒ false`),
> erfordert dann aber eine Bestands-weite Bereichs-Zuweisung.

- **Bereichs-Modell (§11.1), reine Konvention/Struktur:** ein **Bereich** ist ein
  gewöhnliches Daten; **Zugehörigkeit ist ein Kontext** — konkret ein eingefrorener
  Marker-`{ Marker, Bereich }`-Knoten (`Datum::area_membership`, Marker-Atom
  `lakearch/area-membership/v1`, 27 Byte, analog zur Platzhalter-Konvention §3.6).
  Besitzt ein Daten einen solchen Kontext, gehört es dem Bereich an; es darf
  **mehreren** Bereichen angehören (§11.1). Der Kernel **erkennt** die Struktur nur
  (reines Matching §1.3); die schreibende Schicht **baut** sie (§7.2). Rein
  konventionell — **kein** neues Speicher-/Match-Primitiv (§14.2), keine
  Modell-Erweiterung.
- **Bereichs-Zugehörigkeits-Index (`Daten → { Bereiche }`):** in-memory im
  `ContentStore`, **reines, neu-baubares Derivat** (§8.4) — beim Öffnen vollständig
  aus dem Log rekonstruiert (`rebuild_areas_from_log`), genau wie die Dedup-Karte.
  Bewusst **nicht** in die redb-`EdgeIndex`-Engine/das Schema gegossen (kleiner,
  schnell rekonstruierbar; hält die Engine-Abstraktion schmal). Falls die
  Bereichs-Mengen je sehr groß/zahlreich werden, ist die Verlagerung in einen
  persistenten Index eine billige spätere Änderung (Log = Wahrheit).
- **Tor-Durchsetzung (§11.3) zweiphasig:** das `SealedRecord` trägt jetzt die
  server-seitig bestimmten Bereiche des Daten; **`gate::open`** matcht
  *Bereiche ∩ gewährte Bereiche* (Phase A, match-only §1.3) **vor** der Freilegung
  der Bytes (Phase B). Nicht sichtbar ⇒ `None` (**VANISH**, ununterscheidbar von
  „existiert nicht"). Sowohl `get_by_content_id` **als auch** die Traversierung
  laufen durchs Tor — kein Read-Bypass.
- **Traversierung gegated:** in `traverse.rs` ist ein nicht-sichtbarer Nachbar ein
  **interner Front-Stopp** (weder Step noch Betreten) und verändert die
  Ergebnisform **nicht** (VANISH: getestet, dass 0/1/5 verborgene Nachbarn dem
  rechtlosen Leser dieselbe sichtbare Schritt-Zahl liefern — kein Nachbarzahl-
  Orakel). Deterministische Emission in aufsteigender `(to, edge_ctx, from)`-
  Adress-Order (§5.2/§1.4, **kein** Wert-Sort), Visited-Set-beschränkt
  (zyklensicher §1.6), `max_depth`/`max_nodes`-Budget (Knoten-Budget ⇒ definierter
  `TraversalBudgetExceeded`, nie unbeschränkter Speicher), kooperatives
  `CancelFlag` (⇒ `Cancelled`). `edge_type_filter` = strukturelles `ContentId`-
  Matching auf `edge_ctx` (§3.3), nie Wert.
- **Frozen-Form-`Kernel::traverse` ohne Capability:** die Trait-Signatur (Phase 0.5
  eingefroren) trägt **keine** Capability. Entscheidung: die Trait-Methode läuft
  daher mit **leersten gewährten Bereichen** (nur unbeschränkte Daten sichtbar,
  beschränkte VANISHen — fail-safe, kein Leck ohne Recht); der **volle gegatete**
  Einstieg mit vorgelegter `Capability` + `CancelFlag` ist die konkrete
  `LakearchKernel::traverse_with`. So bleibt die frozen Form unangetastet und der
  gegatete Pfad vollständig nutzbar. (Alternative — die Trait-Signatur um eine
  `Capability` erweitern — wurde **nicht** gewählt, um die Phase-0.5-Form nicht zu
  brechen; falls gewünscht, leicht nachziehbar.)
- **Die drei §1.3-Prädikate** (`content_equal`/`context_points_to`/
  `is_member_of_set`) sind **reines strukturelles Matching** und tragen in der
  frozen Form **keine** Capability (nur `SnapshotToken`). Sie geben **nur einen
  bool** über IDs zurück, die der Aufrufer bereits besitzt, und **materialisieren
  keinen Inhalt** — daher kein Tor-Bypass (der inhalts-freilegende Pfad
  `get_by_content_id`/`open` bleibt gegated). `content_equal` ist reine
  Adress-Gleichheit; `context_points_to`/`is_member_of_set` sind Mitgliedschaft im
  Vorwärts-Index (`contexts_of`).
- **Match-only / keine Zeit (§1.4/§11.5):** das Tor wertet **keine** Zeitfenster
  aus (das wäre Ordnung → §1.4). „Aktiv" ist strukturell-im-Snapshot; die volle
  §13-Aktiv-Marker-Logik (Hook reserviert) ist **Phase 5**, die bitemporalen Achsen
  **Phase 3**. Der `SnapshotToken` pinnt in Phase 2 die Watermark `W`; die volle
  Epochen-Semantik folgt in Phase 5.
- **Sichtbarkeits-blind (§11.3):** `KernelMetrics` sind labellose Aggregat-Zähler
  (keine pro-Bereich-Labels, keine IDs); `KernelError`-Texte nennen **keine**
  konkreten Daten/IDs/Bereiche (Negativ-Test `error_texts_are_visibility_blind`).
- **`#![forbid(unsafe_code)]`** auf `traverse.rs` (mechanische Traversierung muss
  beweisbar sicheres Rust sein), zusätzlich zu `gate.rs`/`model.rs`/`store.rs`/
  `kernel.rs`.

**Vertagte, nicht-blockierende Punkte (Phase 2+):**
- **OTel-Traces über eine Traversierung** (Plan „Betrieb, Phase 2"): die Histogramme
  (Tiefe/Fanout/Visited-Set-Größe) und Tor-Evaluierungs-/Denied-Zähler sind noch
  nicht instrumentiert — sie gehören in den Daemon-Rand (§8.4: Lesen erzeugt im
  Kernel nichts) und kommen mit Phase 7.
- **Visited-Set-Spill auf Platte** (Roaring/AnchorId) für riesige Traversierungen:
  aktuell ist die Besuchsmenge eine in-memory `HashSet`, hart durch `max_nodes`
  begrenzt (definierter Budget-Fehler statt Spill). Der Platten-Spill ist eine
  spätere Skalierungs-Option (Plan „Beschränkte Traversierung & Backpressure").
- **`trybuild`-Compile-Fail-Test** für die Tor-Unumgehbarkeit (in `gate.rs` als
  auskommentierte Negativ-Fälle dokumentiert): maschinelle Einfrierung weiterhin
  offen (Phase-0.5-Notiz), nicht-blockierend.

### Phase 2 — Tor-Härtung: Berechtigung, Entzug, Fail-closed-Metrik (Branch `kernel-impl`)

Ergänzungen zum Tor (§11), die den Tor-Auftrag vollständig erfüllen: das
**Berechtigungs-Modell** (§11.1), der **strukturelle Entzug** (§11.4), die
**Fail-closed-auf-Korruption**-Durchsetzung des sicherheits-tragenden Bereichs-
Index und ein **Fail-closed-Zähler**. **Grün:** `cargo build --all-targets`,
`cargo test` (139 lib + 12 Kanonik + 6 Kernel-E2E + 5 Store = 162 Tests),
`cargo clippy --all-targets -- -D warnings`.

- **Berechtigungs-Modell (§11.1), reine Konvention/Struktur (`model.rs`):** eine
  **Berechtigung** ist ein gewöhnlicher Knoten, der das eingefrorene
  `permission`-Marker-Atom (`lakearch/permission/v1`), einen **Subjekt-Rollen-
  Kontext** (`{ lakearch/perm-subject/v1, subject }`) und einen **Bereichs-Rollen-
  Kontext** (`{ lakearch/perm-area/v1, area }`) besitzt — analog zur
  Zugehörigkeits-Konvention `{ Marker, Bereich }`. Da die `owns`-Menge adress-
  sortiert ist (§K2.3), trägt die **Position** keine Bedeutung; die Rollen werden
  rein **strukturell** (§1.3) über ihre Rollen-Marker abgelesen
  (`Datum::permission_subject_area`). Weitere Kontexte (Recht/Zeit/Urheber, §11.1)
  dürfen hinzukommen, ohne die Ablesbarkeit zu stören; der Kernel **wertet sie
  nicht** (§1.4). Der Kernel **baut** keine Berechtigung — die schreibende Schicht
  tut das (§7.2); der Kernel **liest** sie nur (§11.2).
- **Entzug = strukturell-aktiv-im-Snapshot (§11.4/§11.5), kein Wall-Clock:** ein
  **Entzug** ist ein Knoten `{ lakearch/revocation/v1, permission_id }`, der auf die
  `ContentId` der entzogenen Berechtigung zeigt (append-only, §6.3 — nie gelöscht).
  „Aktiv" ist damit eine **strukturelle** Notion (§11.5): aktiv ist eine
  Berechtigung, die im Snapshot vorliegt **und** von keinem Entzugs-Kontext im
  Snapshot benannt wird — **kein** Zeitfenster-Vergleich (das wäre Ordnung →
  §1.4-Verstoß). Welche Berechtigung für einen *Zeitpunkt* gilt, ist eine Lese-
  Projektion der Schicht darüber (§6.4/§8.2). **Reihenfolge-unabhängig** (§Append-
  Order-Semantik): ein Entzug, der im Log **vor** seiner Berechtigung steht, filtert
  trotzdem (Test `revocation_before_permission_in_log_still_filters`); „neuester
  Offset gewinnt" gibt es **nicht**.
- **Berechtigungs-/Entzugs-Index + Subjekt-Auflösung (`store.rs`), reines Derivat
  (§8.4):** in-memory `permissions: ContentId → (Subjekt, Bereich)` und
  `revoked: { ContentId }`, beim Öffnen vollständig aus dem Log rekonstruiert
  (`rebuild_permissions_from_log`), genau wie die Bereichs-/Dedup-Karten.
  `granted_areas_for_subject(subject)` leitet die gewährten Bereiche **strukturell**
  ab (§1.3): alle Bereiche aktiver (nicht entzogener) Berechtigungen des Subjekts.
- **`LakearchKernel::authorize_subject(subject, snap)` (§11.1/§11.2):** der **volle**
  Tor-Einstieg — stellt eine `Capability` aus, deren gewährte Bereiche der Kernel
  aus den aktiven Berechtigungen ableitet (analog `traverse_with` ↔ `traverse`). Die
  **frozen-Form** `Kernel::authorize(scopes, snap)` bleibt unangetastet (sie nimmt
  die Scopes direkt entgegen, für In-Process-Einbetter); die Subjekt-Auflösung ist
  die konkrete Zusatz-Methode. So bleibt die Phase-0.5-Trait-Form unverändert.
- **Fail-closed auf korruptem Bereichs-Index (§11), mit Metrik:** der Bereichs-Index
  ist sicherheits-tragend (er bestimmt, was VANISHt). `areas_of_checked` prüft die
  **gecachte** Bereichs-Menge eines Daten gegen die aus dem **durablen** Inhalt neu
  abgeleitete Wahrheit (§8.4); bei Abweichung ⇒ `KernelError::Inconsistent` (DENY)
  **statt** einer unsicheren (leckenden) Sicht. Sowohl `get_sealed` als auch die
  Traversierung (`is_visible_node`) laufen über diesen geprüften Pfad. Ein stiller
  Index-Defekt, der ein beschränktes Daten fälschlich als „unbeschränkt" auswiese,
  ist damit ausgeschlossen. **Metrik:** neuer Zähler
  `StoreMetrics/KernelMetrics::fail_closed_count` (Atomic, auch auf `&self`-
  Lesepfaden erhöhbar) zählt **dass** ein Fail-closed auftrat — **sichtbarkeits-
  blind** (§11.3: kein Daten/keine ID/kein Bereich). Tests:
  `corrupt_scope_index_fails_closed_with_metric` (Store),
  `traversal_fails_closed_on_corrupt_scope_index` (Traversierung). **Fail-closed
  gilt für Korruption/Inkonsistenz, NICHT für „kein Bereich zugewiesen"** (letzteres
  bleibt der unten markierte Unrestricted-Default).
- **Neue Tests (Tor-Auftrag):** Filter-vor-Auflösen (nicht-sichtbarer Nachbar
  erscheint nie in gegateter Traversierung **noch** in `get_by_content_id`:
  `get_by_content_id_filters_before_resolve`, `non_visible_neighbor_vanishes_…`);
  Fail-closed bei korruptem Scope-Index (oben); VANISH-Ergebnisform-Invarianz
  (`hidden_neighbor_count_does_not_change_result_shape`); Entzug verbirgt künftige
  Reads (`revocation_hides_future_reads_over_public_api`,
  `authorize_subject_then_revoke_hides_future_reads`); Telemetrie/Fehler ohne
  nicht-sichtbare ID (`error_texts_are_visibility_blind`).

### Phase 2 — Review-Härtung II (drei blockierende Findings behoben, Branch `kernel-impl`)

Drei blockierende Review-Findings adressiert; **alle drei warranted ⇒ behoben**
(keine Wegerklärung). **Grün:** `cargo build --all-targets`, `cargo test`
(143 lib + 12 Kanonik + 6 Kernel-E2E + 5 Store = 166 Tests),
`cargo clippy --all-targets -- -D warnings`.

- **Finding 1 (Tor §11.3 — EXISTENZ-ORAKEL auf `get_by_content_id`, VANISH-Loch).**
  `Kernel::get_by_content_id` (`kernel.rs`) lieferte `Ok(Some(SealedRecord))`,
  **sobald** das Daten durabel vorhanden war — **unabhängig** von der Capability;
  die Sichtbarkeit prüfte erst `gate::open` **danach**. Ein rechtloser Leser konnte
  so allein aus der **Rückgabeform** „existiert-aber-verborgen" (`Some`) von
  „existiert nicht" (`None`) unterscheiden — genau das von §11.3 verbotene
  Existenz-Orakel über die berechenbaren Hash-Adressen, und ein Bruch des eigenen
  frozen-Form-Vertrags (`api.rs`: „`None` ⇒ nicht sichtbar **oder** nicht
  vorhanden — der Leser kann es nicht unterscheiden"). Die Traversierung war
  **nicht** betroffen (`is_visible_node` kollabiert abwesend/verborgen bereits zu
  `false`); nur der Einzel-Fetch verriet die Existenz.
  **Behebung:** `get_by_content_id` matcht die Sichtbarkeit jetzt **vor** der
  Rückgabe (`areas_of_checked` + `gate::is_visible` gegen die gewährten Bereiche,
  fail-closed §11) und liefert `Ok(None)`, wenn nicht sichtbar — verborgen ist
  damit an der **Verb-Grenze** ununterscheidbar von abwesend (wie `is_visible_node`
  in der Traversierung). Das abschließende `gate::open` setzt die Sichtbarkeit ein
  zweites Mal durch (Tor bleibt einzige Inhalts-Quelle). **Tests umgestellt**
  (verborgenes Daten ⇒ `is_none()` statt `Some`): `get_by_content_id_filters_before_
  resolve`, `authorize_subject_then_revoke_hides_future_reads` (lib),
  `gate_vanish_over_public_api`, `revocation_hides_future_reads_over_public_api`
  (e2e). **Neuer Regressions-Test** `get_by_content_id_is_not_an_existence_oracle`:
  verborgenes Daten und zufällige unbekannte Adresse liefern für den rechtlosen
  Leser GENAU dieselbe Rückgabeform.

- **Finding 2 (§1.3/§1.7 a — `edge_type_filter` unsortiert ⇒ falsches/nicht-
  deterministisches Matching).** Die Filter-Mitgliedschafts-Prüfung in
  `run_traversal` (`filter.binary_search(&edge_ctx)`) ist nur auf einem
  **sortierten** Slice korrekt. Der frozen-Form-`Kernel::traverse` sortierte+
  deduplizierte zwar, doch der volle Einstieg `LakearchKernel::traverse_with` reichte
  ein vom Aufrufer befülltes `TraversalParams` **ungeprüft** durch — und das
  `pub`-Feld `edge_type_filter` trägt keine erzwungene Invariante. Ein unsortierter
  Filter ergab unspezifizierte `binary_search`-Treffer: passende Kanten konnten still
  fallen (Unter-Inklusion) oder nicht-passende durchrutschen (Über-Inklusion) — Bruch
  des strukturellen Matchings **und** des Determinismus (zwei Reihenfolgen ⇒ zwei
  Ergebnisse).
  **Behebung (Invariante unbrechbar gemacht, mehrschichtig):** (a) neuer Konstruktor
  `TraversalParams::new(...)`, der den Filter aufsteigend sortiert + dedupliziert;
  (b) `traverse_with` normalisiert den Filter an der Verb-Grenze über diesen
  Konstruktor; (c) `run_traversal` normalisiert **zusätzlich defensiv** (borgt einen
  bereits sortierten Filter ohne Klon; baut sonst eine normalisierte Kopie) und führt
  ein `debug_assert!(is_sorted_deduped(..))`. **Neuer Regressions-Test**
  `unsorted_duplicated_filter_is_normalized_and_order_irrelevant`: ein unsortierter,
  duplizierter Filter behält alle passenden Kanten, und zwei verschiedene Filter-
  Reihenfolgen liefern identische Schritte.

- **Finding 3 (§1.7 a — Per-Level-Speicher nicht durch `max_nodes` beschränkt).**
  Das `max_nodes`-Budget bremste nur die **Besuchsmenge** (distinkte Knoten); der
  Budget-Check feuerte erst beim Einfügen eines neuen Front-Knotens. Ein **einzelner**
  Knoten sehr hohen Ausgangsgrades (ein Owner mit N Kontexten) materialisierte aber
  O(N) `Step`s in `level_steps` und in das eager gebaute `out`-`Vec`, **bevor** der
  knoten-basierte Check zünden konnte — Bruch der Modul-Zusage „nie unbeschränkter
  Speicher". Zudem wurde das `CancelFlag` nicht **innerhalb** der Nachbar-Expansion
  eines Knotens geprüft, sodass eine laufende hochgradige Expansion nicht kooperativ
  abbrechbar war.
  **Behebung:** ein aus `max_nodes` abgeleitetes **Schritt-/Kanten-Budget** (`step_
  budget = max_nodes`): jede **zugelassene** (gefilterte + sichtbare) Kante zählt
  dagegen, und der Lauf bricht mit `TraversalBudgetExceeded` ab, **bevor** ein
  weiterer `Step` gepuffert wird ⇒ Speicher O(`max_nodes`), auch unter adversariellem
  Fan-out. Zusätzlich ein `CancelFlag`-Check **innerhalb** der inneren Nachbar-
  Schleife. **Neue Regressions-Tests:** `high_out_degree_node_respects_step_budget`
  (Ausgangsgrad 50, `max_nodes=3` ⇒ definierter Abbruch, ≤ 3 Schritte materialisiert)
  und `cancel_interrupts_high_out_degree_expansion`.
  *Hinweis zur Semantik-Verschärfung:* das Schritt-Budget kann einen Lauf nun
  **früher** abbrechen als zuvor (sobald die gepufferten Schritte `max_nodes`
  erreichen), nicht erst beim N-ten distinkten Knoten. Das ist die beabsichtigte,
  speicher-sichere Schranke; bestehende Budget-/Knoten-Tests bleiben grün. Falls ein
  **getrenntes** Schritt-Budget (unabhängig von `max_nodes`) gewünscht ist, ist das
  eine billige additive Erweiterung der `TraversalParams` (nicht-blockierend).

### Phase 3 — Bitemporal + Platzhalter (Branch `kernel-impl`)

Zeit als Daten (§6), der Ersetzungs-Kontext (§6.3) und die volle Platzhalter-
Behandlung (§3.6). **Die spec-kritische Grenze: „Zeit speichern + indizieren,
NIE ordnen/vergleichen."** **Grün:** `cargo build --all-targets`, `cargo test`
(158 lib + 12 Kanonik + 10 Kernel-E2E + 5 Store = **185 Tests**),
`cargo clippy --all-targets -- -D warnings`.

- **Zeit IST Daten (§6.1), rein strukturelle Konvention (§1.3) — `model.rs`:**
  Zeitpunkte/Zeiträume sind **gewöhnliche** Daten; eine **Zeit-Aussage** ist ein
  **besonderer Kontext** `{ Achsen-Marker, opaker Zeit-Wert }` (analog zur
  Zugehörigkeit §11.1 und zum Ersetzungs-Kontext §6.3). Der **Zeit-Wert** ist ein
  **opakes** Daten (z. B. ein Blatt mit den Zeit-Bytes); der Kernel sieht ihn als
  Bytes (§1.4) und **parst/ordnet/vergleicht ihn nie**.
- **Zwei eingefrorene, VERSCHIEDENE Achsen-Marker (§6.2)** — analog zu allen
  bestehenden Marker-Atomen (Platzhalter §3.6, Bereichs-Zugehörigkeit §11.1,
  Berechtigung/Entzug §11.1/§11.4), **versioniert**, **niemals ändern** (verschöbe
  alle Aussagen): `lakearch/recording-time/v1` (Aufzeichnungszeit, 26 Byte ASCII) und
  `lakearch/validity-time/v1` (Gültigkeitszeit, 25 Byte ASCII). Bewusst distinkt ⇒
  die zwei Achsen sind strukturell unterscheidbar (verschiedene Kontext-`ContentId`s);
  ein Daten **darf beide** tragen, sie **dürfen auseinanderfallen** (§6.2). Methoden
  `Datum::recording_time(value)`/`validity_time(value)` (Aussage bauen) und
  `recording_time_value()`/`validity_time_value()` (strukturell ablesen, nur die
  Adresse — kein Parsen/Vergleichen).
- **Ersetzungs-Marker eingefroren (§6.3):** `lakearch/supersedes/v1` (22 Byte ASCII).
  Ein **Ersetzungs-Kontext** ist der Knoten `{ supersedes-Marker, älteres }`, der auf
  die `ContentId` des überholten ÄLTEREN zeigt; das **NEUERE** Daten **besitzt** diesen
  Kontext. Append-only — das Ältere wird **nie** geändert/gelöscht (§7.1).
  `Datum::supersedes(older)` / `supersedes_target()`.
- **HARTE GRENZE (§1.4/§6.4/§8.2) — im Code festgehalten:** der Kernel stellt
  **ausschließlich** bereit: Zeit **als Daten speichern**, Zeit-Aussage-Kontexte für
  **strukturellen LOOKUP** indizieren (Exakt-Match/Mitgliedschaft §1.3, **KEINE**
  geordnete Bereichs-Abfrage) und **strukturell traversieren**. Es gibt **kein** Verb,
  das eine Zeit entgegennimmt und „die aktive" zurückgibt; **keine** Funktion
  vergleicht zwei Zeit-Werte. „Eine Version ist eine **Leseregel**" (§6.4) der Schicht
  darüber (§8). Negativ-Test `no_kernel_verb_orders_or_selects_by_time` friert die
  Garantie ein.
- **Zwei weitere reine, neu-baubare in-memory Derivate (§8.4) — `store.rs`** (genau
  wie Bereichs-/Berechtigungs-/Entzugs-Index, beim Öffnen aus dem Log rekonstruiert
  und in `rebuild_index_from_log` mit-gewipt/-neu-gebaut):
  - **Zeit-Aussage-Mitgliedschafts-Index** `time_carriers: Zeit-Aussage-Kontext-ID →
    { Daten, die ihn tragen }` — beantwortet **nur** „welche Daten tragen GENAU diese
    Aussage?" (Mitgliedschaft §1.3), **nicht** „T zwischen A und B" (das wäre Ordnung →
    §1.4-Verstoß).
  - **Ersetzungs-Index in BEIDE Richtungen** `supersedes: neuer → { ältere }` und
    `superseded_by: älter → { neuere }` ⇒ die Ersetzungs-Relation ist vor- **und**
    rückwärts traversierbar (§1.2). Der Kernel **verknüpft und indiziert** nur — er
    **ordnet nicht** und entscheidet **nicht**, welches „aktuell" ist (§6.4/§8);
    „neuester Offset gewinnt" gibt es **nicht** (§Append-Order-Semantik;
    reihenfolge-unabhängig getestet).
  - **Designwahl:** bewusst **nicht** in die redb-`EdgeIndex`-Engine/das Schema
    gegossen (wie schon der Bereichs-/Berechtigungs-Index) — klein, schnell aus dem
    Log rekonstruierbar, hält die Engine-Abstraktion schmal. Verlagerung in einen
    persistenten Index ist eine billige spätere Änderung (Log = Wahrheit). Beachte:
    die Ersetzungs-/Zeit-**Kanten** existieren ohnehin als gewöhnliche redb-Kanten
    (`owner→contexts`/`target→referrers`), sodass die rohe Vor-/Rückwärts-Traversierung
    auch ohne diese Komfort-Indizes möglich ist; die in-memory Karten sind nur der
    direkte Mitgliedschafts-/Richtungs-Lookup.
- **Volle Platzhalter-Behandlung (§3.6) — `ContentStore::resolve_placeholder` /
  `LakearchKernel::resolve_placeholder`:** die strukturelle **Auflösung**. Trifft das
  echte Ziel ein, (1) wird es angehängt (Dedup §5.3), (2) ein Ersetzungs-Kontext
  `supersedes(placeholder)` gebaut + angehängt, (3) ein Auflösungs-Knoten
  `{ real, supersedes_ctx }` angehängt, der Platzhalter→real über den Ersetzungs-
  Kontext verknüpft (§6.3). **Append-only:** der Platzhalter wird **nie** geändert/
  gelöscht (§7.1) und bleibt unverändert über das Tor lesbar. Der auflösende Pfad ist
  vom Platzhalter aus über die bestehenden Kanten-Indizes erreichbar
  (`superseded_by` → Auflösungs-Knoten → vorwärts zum echten Daten). Der Kernel
  **validiert keine Geschlossenheit** (§1.4/§7.2) — er prüft **nicht**, ob `placeholder`
  ein Platzhalter ist; er stellt nur die **Primitive** (Platzhalter + Auflösung +
  Traversierung Platzhalter→Auflöser).
- **Gegatete Lese-Helfer (§11.3) — `kernel.rs`:** `time_carriers_visible`,
  `supersedes_visible`, `superseded_by_visible`, `placeholder_resolvers_visible`. Alle
  reichen **nur** für die Capability **sichtbare** `ContentId`s heraus (VANISH:
  nicht-sichtbares/nicht-vorhandenes Daten ununterscheidbar weg, §11.3) und
  **materialisieren keinen Inhalt** (den legt erst das Tor frei, §11.5). Gemeinsamer
  Pfad `ContentStore::visible_filter` (VANISH + fail-closed §11 bei korruptem
  Bereichs-Index). Keine Capability-tragende Trait-Form nötig — diese Phase-3-Verben
  sind **konkrete** `LakearchKernel`-Methoden (wie `traverse_with`/`authorize_subject`
  in Phase 2), die eingefrorene Phase-0.5-Trait-Form bleibt unangetastet.
- **`#![forbid(unsafe_code)]`** bleibt auf `model.rs`/`store.rs`/`kernel.rs`/
  `gate.rs`/`traverse.rs`; das `unsafe` lebt allein im `mmap`-Leaf `log.rs`.

**Neue Tests (Phase 3, alle grün):** Marker-Atome eingefroren + distinkt; beide
Achsen lesbar + Achsen-Kreuz (eine Aufzeichnungszeit ist keine Gültigkeitszeit);
ein Daten trägt beide Achsen divergent; Ersetzungs-Kontext verknüpft neuer→älter
strukturell; Zeit-Achsen als gewöhnliche Kanten; Zeit-Mitgliedschafts-Lookup liefert
Träger (keine Ordnung); Ersetzungs-Index beide Richtungen + Kette; Platzhalter
auflösbar + beidseitig traversierbar + append-only unverändert; **Wipe-&-Rebuild +
Reopen identisch** für Zeit-/Ersetzungs-Index (§8.4); gegatete Helfer mit VANISH
(geheimer Träger/überholendes Daten VANISHt); Negativ-Garantie „kein Verb ordnet/
wählt nach Zeit"; öffentliche E2E-Tests für Ersetzungs-Kette, Zeit-Lookup und
Platzhalter-Auflösung über die `pub`-API.

**Vertagte, nicht-blockierende Punkte (Phase 3+):**
- **§13-Aktiv-Marker / volle Snapshot-Epoche:** der `SnapshotToken` pinnt weiterhin
  nur die committete Watermark `W`; die volle „strukturell-aktiv-im-Snapshot"-Semantik
  (§13) bleibt **Phase 5**. Die Zeit-/Ersetzungs-Lookups sind davon unberührt (rein
  strukturell, snapshot-agnostisch in dieser Phase).
- **Anker / referenzielle Identität (§9):** Phase 4 — die Phase-3-Ersetzung (§6.3) ist
  davon getrennt (Fortschreibung §5.7 a vs. Repräsentantensystem §9).

---

## Phase 4 — Anker / Mitgliedschaft / gradierte Identität / Kuratierung (§9, §5.5)

**Leitsatz (HARTE GRENZE).** Der Kernel **HÄLT** die Strukturen der Identitäts-
Auflösung; er **löst sie nicht auf**. Es gibt **kein** Verb, das eine Identität
auflöst, einen „gewinnenden" Repräsentanten wählt/rankt, eine Konfidenz vergleicht/
schwellt oder destruktiv mergt (§9-Präambel/§1.4/§5.5). Bereitgestellt sind **nur**:
Anker bauen, (gradierte) Mitgliedschaft anhängen, gradierten Identitäts-Kontext
anhängen, Repräsentant⇆Anker- und Identitäts-Links traversieren, reversible
Kuratierung (verbergen/aufheben/ersetzen), Split per Ersetzung (§6.3-Wiederverwendung).
Die Grenze ist mit einem expliziten **Negativ-Test** eingefroren
(`kernel_never_resolves_ranks_or_thresholds_identity`).

**Eingefrorene Marker-Atome (`model.rs`, Blatt-Daten §2.1, distinkte Längen):**
`lakearch/anchor/v1` (Anker-Rolle §9.1) · `lakearch/membership/v1` (Mitgliedschaft
§9.3) · `lakearch/grade/v1` (Grad-Sub-Kontext §9.3) · fünf gradierte Stärke-Marker
§5.5 (`lakearch/ident-deckungsgleich/v1`, `…-ergaenzt/v1`, `…-widerspricht-in/v1`,
`…-verwandt-mit/v1`, `…-bekannt-verschieden/v1`) · drei Kuratierungs-Marker §9.5
(`lakearch/curation/hide/v1`, `…/unhide/v1`, `…/replace/v1`). Alle paarweise distinkt
(Negativ-Test friert es ein).

**Modell (`model.rs`) — Konstruktoren + strukturelle Reader auf `Datum`:**
- **Anker (§9.1):** `Datum::anchor(payload)` = Knoten `{ anchor_marker, …payload }` —
  ein **gewöhnliches inhaltsadressiertes Daten** (§2.1) mit eigener `ContentId`;
  `is_anchor()`. Der Anker wird **nie** aus einem Repräsentanten umgewandelt (§9.2).
- **Mitgliedschaft (§9.1/§9.3):** `Datum::membership(anchor, grade_value)` = Knoten
  `{ membership_marker, anchor, grade_ctx }`; der Repräsentant **besitzt** ihn und
  verweist damit auf den **Anker** (§9.2). Grad-Sub-Kontext
  `Datum::membership_grade(grade_value)` = `{ grade_marker, opaker Grad-Wert }`.
  Reader `membership_anchor(resolve)` / `membership_grade_context(resolve)` /
  `membership_grade_value()` — der Grad-**Wert** wird **nie** verglichen/geschwellt.
- **Gradierte Identität (§5.5/§3.4):** `IdentityStrength` (bewusst **kein** `Ord`/
  `PartialOrd` — eine Ordnung wäre §1.4-Verstoß). `Datum::graded_identity(a, b,
  strength, sub_contexts)` = `{ strength_marker, a, b, …reifizierte Sub-Kontexte }`;
  Sub-Kontexte tragen betroffene Attribute, **Konfidenz**, Urheber, Zeit (native
  Reifikation §3.4). Reader `identity_strength()` / `is_graded_identity()` /
  `graded_identity_contexts()` — der Kernel **hält** die Konfidenz, **vergleicht sie
  nie**.
- **Kuratierung (§9.5):** `curation_hide(target)` / `curation_unhide(target)` /
  `curation_replace(replaced, replacement)` + Reader. Verbergen ist ein **reversibler
  Lese-Filter** (Aufheben reversiert); Ersetzen ein reversibler Hinweis. **Nichts**
  gelöscht (§7.1); physisches Entfernen ist Compaction (§15/Phase 8).

**Indizes (`store.rs`) — reine, neu-baubare Derivate (§8.4), aus dem Log
rekonstruiert (`rebuild_identity_and_curation_from_log`), in `rebuild_index_from_log`
mit-gewipt/-neu-gebaut:**
- **Anker-Mitgliedschaft beide Richtungen** `anchor_to_reps` / `rep_to_anchors`
  (§9.1/§9.3; ein Repräsentant darf mehreren Ankern angehören).
- **AnchorId ⇆ Anker-ContentId-Karte** `anchor_id_of` / `anchor_cid_of` (§12.4) —
  der bestand-**lokale** Handle, **deterministisch** in Auftretens-Reihenfolge der
  Anker im Log vergeben (neu-baubar identisch, Reopen-stabil). Der Anker bleibt ein
  gewöhnliches inhaltsadressiertes Daten; der Handle ist **nie** seine alleinige
  Identität.
- **Gradierte-Identitäts-Links** `graded_identity_links: Daten → { Identitäts-Kontexte,
  die es erwähnen }` (§5.5; von beiden erwähnten Daten auffindbar).
- **Kuratierungs-Verbergen-Filter** `curation_hidden` — reversibel (Aufheben
  reversiert), **reihenfolge-unabhängig** (Aufheben dominiert via Dedup-Lookup der
  strukturell bestimmten Unhide-`ContentId`, analog Entzug §11.4). `visible_filter`
  lässt verborgene Daten **VANISHen** (§9.5/§11.3), ohne etwas zu löschen.
- **Designwahl** (wie schon Bereichs-/Zeit-/Ersetzungs-Index): bewusst **nicht** in
  das redb-Schema gegossen — klein, schnell aus dem Log rekonstruierbar; die
  zugrundeliegenden **Kanten** existieren ohnehin als gewöhnliche redb-Kanten.

**Gegatete Lese-Helfer (`kernel.rs`, §11.3):** `anchor_members_visible` /
`member_anchors_visible` / `graded_identity_links_visible` reichen **nur** sichtbare
`ContentId`s heraus (VANISH; auch **kuratorisch verborgene** VANISHen), Inhalt nur
über das Tor (§11.5), fail-closed (§11). `anchor_id_of` / `anchor_cid_of` lösen den
lokalen Handle auf (kein Inhalts-Read). Keine Capability-tragende Trait-Form nötig —
konkrete `LakearchKernel`-Methoden (wie Phase 2/3); die Phase-0.5-Trait-Form
(`get_anchor_members`/`get_member_anchors`) bleibt unangetastet.

**Neue Tests (Phase 4, alle grün):** Marker eingefroren + distinkt + dokumentierte
Länge; Anker = gewöhnlicher inhaltsadressierter Knoten; Mitgliedschaft verweist
strukturell Rep→Anker; gradierte Identität trägt Stärke + **gespeicherte, nie
verglichene** Konfidenz; Kuratierung hide/unhide/replace reversibel; **Negativ-Garantie**
„IdentityStrength hat keine Ordnung, der Kernel rankt nie". Store: Anker-Mitgliedschaft
beide Richtungen + lokaler Handle deterministisch; Wipe-&-Rebuild + Reopen identisch
(inkl. stabiler AnchorIds); gradierte Links neu-baubar; Verbergen→VANISH→Aufheben
reversibel + reihenfolge-unabhängig; **Split (§9.4)** re-verweist einen Repräsentanten
zu einem NEUEN Anker per Ersetzungs-Kontext (§6.3) — der **alte Anker (und alte
Repräsentant) werden NICHT mutiert/gelöscht** (append-only §7.1), beide Richtungen +
Ersetzungs-Relation neu-baubar (`split_re_references_representative_to_new_anchor_
without_mutating_old`). Kernel: gegatete Anker-Mitgliedschaft + VANISH;
gradierte Links halten Konfidenz ohne Vergleich; Verbergen ist reversibler Lese-Filter
(Daten nicht gelöscht); **HARTE-GRENZE-Negativ-Test** (kein Auflösen/Ranken/Schwellen).

### Phase 4 — Abschluss & Commit (Branch `kernel-impl`)

Phase 4 ist **fertig und grün** und wird als ein Commit eingefroren (Politik: ein
Commit pro grüner Phase). **Grün verifiziert** (`source $HOME/.cargo/env`, in
`/home/nanu/lakearch`):
- `cargo build --all-targets` — sauber.
- `cargo test` — **202 Tests** grün: 175 lib-Unit + 12 Kanonik-Vektoren
  (`tests/canonical_vectors.rs`) + 10 Kernel-E2E (`tests/kernel_e2e.rs`) + 5
  Store-Integration (`tests/store_index.rs`); 0 fehlgeschlagen, 0 ignoriert
  (+17 lib-Tests gegenüber Phase 3).
- `cargo clippy --all-targets -- -D warnings` — sauber (Exit 0).

Damit deckt Phase 4 die §9-/§5.5-Strukturen vollständig ab — **HALTEN, NIE
auflösen**: Anker/Repräsentant + gradierte Mitgliedschaft, gradierte referenzielle
Identität (Konfidenz gespeichert, nie verglichen), reversible Kuratierung
(VANISH ohne Löschen), Split per Ersetzung (§6.3), die vier neu-baubaren in-memory
Derivate (Anker-Mitgliedschaft beidseitig, AnchorId⇆Anker-Karte §12.4,
gradierte-Identitäts-Links, Verbergen-Filter) mit Wipe-&-Rebuild- und Reopen-
Gleichheit, und die gegateten VANISH-Helfer. Die **HARTE GRENZE** (kein
Auflösen/Ranken/Schwellen/destruktives Mergen) ist mit dem expliziten Negativ-Test
`kernel_never_resolves_ranks_or_thresholds_identity` und der bewusst ordnungslosen
`IdentityStrength` (kein `Ord`/`PartialOrd`) eingefroren. `#![forbid(unsafe_code)]`
bleibt auf `model.rs`/`store.rs`/`kernel.rs`/`gate.rs`/`traverse.rs`.

**Vertagte, nicht-blockierende Punkte (Phase 4+):**
- **§13-Aktiv-Marker / volle Snapshot-Epoche:** bleibt **Phase 5** — der
  `SnapshotToken` pinnt weiterhin nur die committete Watermark `W`; die Anker-/
  Identitäts-/Kuratierungs-Lookups sind davon unberührt (rein strukturell).
- **Persistenz der neuen Derivate:** wie schon Bereichs-/Zeit-/Ersetzungs-Index
  bewusst **nicht** in das redb-Schema gegossen (klein, schnell aus dem Log
  rekonstruierbar; die zugrundeliegenden Kanten existieren ohnehin als gewöhnliche
  redb-Kanten). Verlagerung in einen persistenten Index ist eine billige spätere
  Änderung (Log = Wahrheit, §8.4).

### Phase 5 — Atomarität / Aktiv-Marker-Sichtbarkeit (§13, Branch `kernel-impl`)

Die **eine Linearisierungsstelle** für Atomarität **ohne Transaktions-Maschinerie**
(§13.3): ein mehrere Daten berührender Umbau (Merge/Split §9, Berechtigungs-Änderung
§11) wird durch **einen** abschließenden ACTIVE-Schreibvorgang — den **Marker-Record**
— **gemeinsam** sichtbar; bis der Marker durabel ist, sind die Konstituenten
**bedingt/INAKTIV** und Traversierung/Reads **ignorieren** sie (§13.1/§13.2). Die
Mechanik ist **exakt** das adversariell verifizierte Plan-Design (Abschnitt
„Aktiv-Marker-Sichtbarkeit (§13) — eine Linearisierungsstelle"); **kein** zweiter,
frei laufender Epochenzähler. **Grün:** `cargo build --all-targets`, `cargo test`,
`cargo clippy --all-targets -- -D warnings`.

- **Marker-Record + bedingte Konstituenten (`log.rs`/`format.rs`), reservierte
  Felder aktiviert:** der Marker ist selbst ein **gewöhnlicher Record**; er trägt im
  reservierten `constituent_range`-Feld (Phase 0.5/1 reserviert) den **Anfangs-Offset
  des ersten Konstituenten** (`[first_constituent_offset, marker_offset)`, Audit). Jeder
  **bedingte** Konstituent referenziert im reservierten `marker_offset`-Feld den Offset
  seines **regierenden Markers**. Ein **unbedingter** Record (gewöhnlicher Einzel-Append)
  hat `marker_offset == 0` und **keinen** regierenden Marker. Die Header-Felder werden
  über `RecordHeader::with_marker_offset`/`with_constituent_range` gesetzt — **kein**
  Format-Bruch, das append-only-Framing bleibt unverändert (§K5.1).
- **EIN Commit-Watermark `W` (`SegmentLog::committed_offset`), keine zweite Größe:**
  `W` = Offset **nach** dem letzten durablen Batch-Footer = die **bestehende**
  Group-Commit-/fsync-Grenze aus Phase 1 (**nicht** „letzter Marker"). Es gibt
  **genau eine** Watermark. Sie wird **erst** veröffentlicht, **nachdem** der
  Group-Commit-`fsync` durch ist **und** die zugehörigen Sekundär-Index-Einträge
  durabel sind (Invariante **index-durable → publish-watermark**, geerbt aus dem
  Store-Append-Pfad `log-fsync → index-commit → Watermark`, §8.4). **Memory-Ordering:**
  der Append-Pfad ist der **eine** `&mut self`-Schreiber, über den `RwLock` in
  `LakearchKernel` serialisiert; die Lock-Release/Acquire-Paare liefern die
  Release/Acquire-Barriere des Plans (`committed_offset` ist daher ein einfaches `u64`,
  **kein** `AtomicU64`). Die lock-freie MPSC-Variante mit explizitem Release-Store/
  Acquire-Load ist eine spätere Phase (wie schon in Phase 1 vertagt) — die **Semantik**
  („ein W fixiert den Snapshot") ist hier bereits voll erfüllt.
- **Leser-Prädikat (`SegmentLog::visible`), reiner Offset-Vergleich (§1.4-sicher):**
  ein Record an `offset` mit `marker_offset` ist gegenüber `W` sichtbar ⇔
  `offset < W ∧ (marker_offset == 0 ∨ marker_offset < W)`. Striktes `<`, weil `W`
  end-exklusiv ist (ein Record ist durabel, sobald `W` über sein Frame-Ende vorgerückt
  ist). Index-Treffer werden **zusätzlich** über denselben offset-Vergleich gefiltert
  (`is_active`/`visible_filter`/`get_sealed`) — ein **über-frischer** Index ist harmlos
  (Treffer fällt am `offset < W`-Filter), ein **unter-frischer** ist per
  index-durable→publish-watermark-Invariante ausgeschlossen.
- **`activation_epoch` bleibt AUDIT-only, NICHT Sichtbarkeits-Autorität (§13):** das
  reservierte Epochenfeld `E` ist **ausschließlich** Metadaten/Audit. Der
  **Offset-Vergleich ist die ALLEINIGE Autorität**. Es wurde **kein** separater,
  frei laufender Epochenzähler eingeführt (adversariell verlangt).
- **Zweiphasiger Restructuring-Pfad (`store.rs`/`kernel.rs`):**
  `stage_restructuring(constituents)` schreibt die Konstituenten als **bedingte,
  noch inaktive** Records (jeder mit `marker_offset` = dem noch fehlenden
  Marker-Offset) als **eigenen** Group-Commit-Batch und gibt einen `StagedHandle`;
  während des Stagings gilt `W == marker_offset`, also `marker_offset < W` **falsch**
  ⇒ die genuin neuen Konstituenten sind inaktiv. `commit_restructuring(handle, marker)`
  schreibt den **unbedingten** Marker-Record (er endet den Batch, sein
  `constituent_range` zeigt auf den ersten Konstituenten), `fsync`t und veröffentlicht
  `W` über das Marker-Ende hinaus ⇒ **alle** Konstituenten flippen in **einem**
  Linearisierungspunkt **gemeinsam** sichtbar. `append_restructuring(constituents,
  marker)` ist der Ein-Aufruf-Bequempfad (stage + commit unmittelbar). Die
  eingefrorene Phase-0.5-Trait-Form `Kernel::set_active_marker(&[ContentId])` bleibt
  **unangetastet** (sie nimmt nur **schon vorhandene** IDs entgegen und kann die
  bedingten Konstituenten nicht **stagen**); der konkrete `LakearchKernel`-Einstieg
  verlangt die **Daten** selbst (analog `traverse_with` ↔ `traverse`).
- **Crash mid-Umbau bleibt INERT (§13.3, Recovery):** wird der Marker nie durabel,
  setzt die Recovery `W` auf den letzten voll-durablen Record (Footer-Autorität aus
  Phase 1); die gestageten Konstituenten referenzieren `marker_offset > W` und sind
  damit **für immer unsichtbar wie geschrieben** — der halb-vollzogene Umbau leckt
  durch **keinen** Lesepfad. `rebuild_dedup_from_log` rekonstruiert die
  `governing_marker`-Karte **reihenfolge-unabhängig** aus dem Log (ein **unbedingtes**
  Vorkommen einer `ContentId` gewinnt immer → bereits geackte Daten bleiben aktiv,
  §5.3/§7.1). Test `crash_before_marker_keeps_acked_datum_visible_only_new_
  constituent_lost`.
- **Orthogonal zum §11-Tor (§11.3), beide pre-resolution:** der §13-Aktiv-Filter
  und der §11-Scope-Filter sind **getrennte, strukturelle Vor-Auflösungs-Prädikate**,
  die **nebeneinander** laufen — ein Read wendet **beide** an (inaktiv ⇒ unsichtbar;
  nicht-sichtbarer Scope ⇒ VANISH). `get_sealed`, `visible_filter`,
  `is_visible_node` (Traversierung) und alle gegateten Helfer prüfen erst §13-Aktiv,
  dann §11-Scope, beide über **dasselbe** gepinnte `W` (kein In-Kernel-TOCTOU).
- **Gepinnter `SnapshotToken` durch ALLE Lesepfade durchgereicht:** `pin_snapshot`
  fixiert das **aktuelle** `W`; jedes Lese-Verb liest `let w = snapshot.watermark();`
  und reicht es hinab (`get_sealed(id, w)`, `visible_filter(.., w)`,
  `run_traversal(.., w)`) statt das **Live**-Watermark erneut zu lesen — ein Leser mit
  fixiertem Snapshot sieht einen nach dem Pin committeten Umbau **nicht**
  (Snapshot-Isolation, Test `pinned_snapshot_does_not_see_restructuring_committed_
  after_pin`). Damit ist die `api.rs`-Zusage „dasselbe S, kein In-Kernel-TOCTOU"
  in der Implementierung **wahr**.
- **`#![forbid(unsafe_code)]`** bleibt auf `store.rs`/`kernel.rs`/`gate.rs`/
  `traverse.rs`/`model.rs`; das `unsafe` lebt allein im `mmap`-Leaf `log.rs`
  (genau ein `MmapOptions::map`, `#[deny(unsafe_op_in_unsafe_fn)]` + SAFETY-Kommentar).

**Vertagte, nicht-blockierende Punkte (Phase 5+):**
- **Lock-freie MPSC-/Group-Commit-Pipeline + `loom`:** wie in Phase 1 vertagt — der
  Append ist heute der **eine** `&mut self`-Pfad über den `RwLock`; sobald die
  lock-freie Producer-Queue gebaut wird, wird `committed_offset` ein `AtomicU64`
  mit explizitem Release-Store/Acquire-Load und `loom`-Modellen (die Plan-Formulierung
  „ein Release-Store / ein Acquire-Load" wörtlich). Die §13-**Semantik** ändert sich
  dadurch **nicht** (Offset-Vergleich bleibt die alleinige Autorität).
- **Cross-Shard-Umbau:** das `shard_id`-Feld bleibt reserviert/NULL (Phase 0.5);
  der Marker referenziert Konstituenten-Offsets **innerhalb eines Bestands/Shards**.
  Cross-Shard-Atomarität (oder ihr Verbot) fällt mit dem Sharding-Design nach dem
  Benchmark-Gate (Plan „Scale-out reservieren").

### Phase 5 — Review-Härtung (drei blockierende Findings behoben, Branch `kernel-impl`)

Drei blockierende Phase-5-Review-Findings adressiert; **alle drei warranted ⇒ behoben**
(keine Wegerklärung). **Grün:** `cargo build --all-targets`, `cargo test` (232 Tests:
204 lib + 12 Kanonik + 11 Kernel-E2E + 5 Store), `cargo clippy --all-targets -- -D
warnings`.

- **Finding 1 (Atomarität §7.1/§5.3/§13) — ein geacktes UNBEDINGTES Daten konnte durch
  einen späteren Umbau rückwirkend konditioniert (und bei Crash für immer unsichtbar)
  werden.** Pfad: `append(X)` (unbedingt, aktiv, kein regierender Marker) →
  `stage_restructuring(&[X, Y])` schrieb einen zweiten X-Record und stempelte X über
  `governing_marker.entry(X).or_insert(marker_offset)` einen regierenden Marker auf;
  während des Stagings ist `w == marker_offset`, also `marker_offset < w` **falsch** ⇒
  X galt als **inaktiv** ⇒ VANISHt aus `get_*`/Traversierung. Beim Reopen reproduzierte
  `rebuild_dedup_from_log` das (bedingtes Duplikat setzt einen Marker) ⇒ X für immer
  unsichtbar, wenn der Marker nie committet (Crash mid-Umbau). Verstieß gegen §7.1
  (geackter Append nie verloren) und §5.3 (Wert-Identität: inhaltsgleich = dasselbe,
  bereits sichtbare Daten).
  **Behebung (zwei koordinierte Stellen, beide Vorkommen der Regel „unbedingt
  gewinnt"):**
  1. `ContentStore::stage_restructuring`: vor dem Einfügen `let pre_existing =
     self.dedup.contains_key(id)`; **nur** wenn `!pre_existing`, wird
     `governing_marker.insert` gesetzt. Ein bereits (unbedingt) vorhandenes Daten bleibt
     unbedingt/aktiv — ein Umbau konditioniert es nicht.
  2. `ContentStore::rebuild_dedup_from_log`: eine `ContentId` mit **irgendeinem**
     unbedingten Vorkommen (`marker_offset == 0`) wird unbedingt/aktiv geführt
     **unabhängig** von Reihenfolge/bedingten Duplikaten — ein unbedingtes Vorkommen
     `governing_marker.remove(id)` (und ein gemerktes `seen_unconditional`-Set
     verhindert ein nachträgliches Aufstempeln). Reihenfolge-unabhängig (§Append-Order).
  **Neue Regressions-Tests:** `staging_value_identical_constituent_does_not_retro_
  condition_acked_datum` (X aktiv vor UND nach dem Marker, kein Marker aufgestempelt;
  nur das genuin neue Y bis zum Marker inaktiv) und
  `crash_before_marker_keeps_acked_datum_visible_only_new_constituent_lost` (Reopen nach
  Crash: X sichtbar, nur Y für immer inaktiv §13.3).

- **Finding 2 + 3 (Phase-5-Leser-Invariante §13.2/§8.4 — „ein W fixiert den Snapshot")
  — der gepinnte `SnapshotToken` wurde von KEINEM Lesepfad genutzt; sie lasen das
  LIVE-Watermark.** `pin_snapshot` reichte zwar das gepinnte `W` im `SnapshotToken`
  heraus, doch `get_by_content_id`/`traverse`/`traverse_with`/alle `*_visible`-Helfer
  verwarfen den Token (`let _ = snapshot;`) und die Store-/Traversier-Ebene leitete `W`
  aus dem **Live** `store.current_watermark()` ab. Folge: ein Leser mit fixiertem
  Snapshot, der zwei Reads um einen Marker-Commit klammert, sah die Konstituenten
  inaktiv-dann-aktiv — der Umbau war aus Sicht eines festen Snapshots **nicht** atomar
  (falsche Stabilität); zugleich war die im `api.rs`-Vertrag behauptete „kein In-Kernel-
  TOCTOU, dasselbe S"-Eigenschaft in der Implementierung **unwahr**. (Der §13-Sicherheits-
  Boden hielt — ein un-committeter Marker bedeutet `live W <= marker_offset` ⇒ inaktiv;
  aber die *spezifizierte* gepinnte-W-Leser-Semantik fehlte.)
  **Behebung (reiner Offset-Vergleich, §1.4-sicher, keine zweite Epoche):** das gepinnte
  `W` wird durch alle Lesepfade **durchgereicht**, statt das Live-Watermark erneut zu
  lesen:
  - `ContentStore::get_sealed(id, w)` und `ContentStore::visible_filter(candidates,
    granted, w)` nehmen `w` als Parameter (kein internes `self.current_watermark()` mehr).
  - `traverse::run_traversal(store, cap, params, cancel, w)` erhält `w` vom Aufrufer (kein
    internes `store.current_watermark()` mehr).
  - In `kernel.rs` liest jedes Verb `let w = snapshot.watermark();` und reicht es hinab:
    `get_by_content_id`, `traverse` (frozen-Form), `traverse_with` **und** alle acht
    gegateten Helfer. Letztere tragen jetzt einen `snapshot: SnapshotToken`-Parameter
    (analog zu `get_by_content_id`/`traverse_with`), sodass Tor (§11) und §13-Filter über
    **dasselbe** S laufen.
  - `SnapshotToken::watermark()` und `::at_watermark()` verlieren ihr stale
    `#[allow(dead_code)]` (jetzt von den Lesepfaden bzw. `pin_snapshot` genutzt).
  **Neuer Regressions-Test:** `pinned_snapshot_does_not_see_restructuring_committed_
  after_pin` (Token VOR dem Umbau gepinnt → `append_restructuring` (stage+commit)
  NACH dem Pin → mit dem ALTEN Token VANISHen die Konstituenten weiterhin über
  `get_by_content_id`, den gegateten Anker-Helfer UND die Traversierung; erst ein FRISCH
  gepinnter Snapshot sieht den committeten Umbau — Snapshot-Isolation).
  **Test-Anpassung (kein Maskieren mehr):** zwei bestehende Tests
  (`kernel_never_resolves_ranks_or_thresholds_identity`,
  `trait_traverse_runs_over_unrestricted_data`) pinnten ihren Snapshot **vor** den
  Appends, die sie dann lasen, und verließen sich damit auf das (zuvor fälschlich gelesene)
  Live-Watermark. Sie pinnen den Snapshot jetzt **nach** den Appends (korrekte Snapshot-
  Isolation) — die Lese-Erwartungen bleiben unverändert.
  Keine zweite/freilaufende Epoche eingeführt; `activation_epoch` bleibt reines
  Audit-Feld (Offset-Vergleich ist die alleinige Sichtbarkeits-Autorität, §13).

### Phase 5 — Abschluss & Commit (Branch `kernel-impl`)

Phase 5 ist **fertig und grün** und wird als ein Commit eingefroren (Politik: ein
Commit pro grüner Phase). **Grün verifiziert** (`source $HOME/.cargo/env`, in
`/home/nanu/lakearch`):
- `cargo build --all-targets` — sauber (Exit 0).
- `cargo test` — **232 Tests** grün: 204 lib-Unit + 12 Kanonik-Vektoren
  (`tests/canonical_vectors.rs`) + 11 Kernel-E2E (`tests/kernel_e2e.rs`) + 5
  Store-Integration (`tests/store_index.rs`); 0 fehlgeschlagen, 0 ignoriert
  (+30 Tests gegenüber Phase 4: +29 lib, +1 E2E).
- `cargo clippy --all-targets -- -D warnings` — sauber (Exit 0).

Damit deckt Phase 5 die §13-Atomarität vollständig ab — **eine Linearisierungs-
stelle, ohne Transaktions-Maschinerie**: Marker-Record + bedingte Konstituenten
über die reservierten `constituent_range`/`marker_offset`-Felder, **das eine**
Commit-Watermark `W` (= bestehende `committed_offset`-Group-Commit-Grenze), das
reine Offset-Vergleichs-Leser-Prädikat (`offset < W ∧ (unbedingt ∨ marker_offset
< W)`), die index-durable→publish-watermark-Invariante, der zweiphasige
`stage`/`commit`-Pfad (+ Ein-Aufruf-`append_restructuring`), die Crash-Inertheit
(nie-committeter Marker ⇒ Konstituenten für immer inaktiv), die Orthogonalität
zum §11-Tor (beide pre-resolution) und der durch **alle** Lesepfade durchgereichte
gepinnte `SnapshotToken` (Snapshot-Isolation, kein In-Kernel-TOCTOU). **Kein**
zweiter Epochenzähler — `activation_epoch` bleibt Audit-only. Drei blockierende
Review-Findings sind behoben (siehe Abschnitt „Phase 5 — Review-Härtung").
`#![forbid(unsafe_code)]` bleibt auf `store.rs`/`kernel.rs`/`gate.rs`/`traverse.rs`/
`model.rs`; das `unsafe` lebt allein im `mmap`-Leaf `log.rs`.

### Phase 6 — Materialisierung & Invalidierung (§10) — Entscheidungen

**Spec-kritische Grenze (§1.5/§10.3): der Kernel FINDET Abhängige, BERECHNET aber
NIE neu.** Dies ist die zentrale, einzuhaltende Trennlinie der Phase. Alle Verben
sind reine **Finde-/Lese-Pfade**; es gibt **kein** Verb, das ein Ergebnis ableitet,
neu berechnet, als stale markiert oder auto-invalidiert. „Als-stale-markieren" und
„neu-berechnen" sind ein **weiterer Append / eine Ersetzung der Schicht darüber**
(§7.1/§6.3) — außerhalb des Kernels. Der Negativ-Test
`find_dependents_only_finds_and_never_recomputes_or_marks_stale` friert dies ein:
`find_dependents` ist `&self` (kein `&mut`), liefert nur `ContentId`s, und ein
wiederholter Aufruf nach einem erneuten Lauf liefert **identisch** dieselben
Abhängigen (kein Seiteneffekt, keine erzeugten Daten).

1. **Herkunft als Kontext, gespiegelt aus den bestehenden Markern (§10.2).** Ein
   **eingefrorenes** Herkunft-Marker-Atom `lakearch/origin/v1` (18 Bytes ASCII,
   `niemals ändern`) und ein **Herkunfts-Kontext** `{ origin_marker, input }` —
   exakt dieselbe Marker+Ziel-Konvention wie Zugehörigkeit (§11.1), Ersetzung
   (§6.3), Zeit (§6.2) und Mitgliedschaft (§9.3). Bewusst **distinkt** von allen
   bestehenden Markern (paarweise-Distinktheits-Test); gleiche Byte-LÄNGE wie der
   Anker-Marker, aber andere Bytes ⇒ andere `ContentId`. Ein berechnetes Ergebnis
   **besitzt** je Eingabe einen Herkunfts-Kontext; **mehrere Herkunfts-Links** für
   mehrere Eingaben sind nativ (§10.2). `Datum::computed_result(payload, inputs)`
   bindet das **fertige** Ergebnis (`payload` = das von der Schicht darüber
   Gerechnete, §1.5) nur strukturell an seine Eingaben — der Konstruktor rechnet
   nichts.

2. **Invalidierung = Rückwärts-Traversierung über die schon vorhandenen Indizes
   (§10.3/§8.4).** Statt eines neuen Spezial-Index werden — analog zum Ersetzungs-
   Index der Phase 3 — **zwei** reine, neu-baubare in-memory Derivate gehalten:
   `origin_of` (Ergebnis→Eingaben, *origin*) und `derived_from` (Eingabe→Ergebnisse,
   *derived-from* = die **Invalidierungs-Rückwärts-Kante**). Beide werden in
   `index_edges_for` aus dem Herkunfts-Kontext beidseitig befüllt und in
   `rebuild_index_from_log` mit-gewipt; Wipe-&-Rebuild **und** Reopen liefern den
   identischen Index (§8.4, Test
   `origin_index_both_directions_materialize_and_survive_rebuild`). Die
   `target→referrers`-Kante allein hätte zwar das Ergebnis von der Eingabe aus
   erreichbar gemacht, aber gemischt mit allen anderen Verweisern; der dünne,
   typ-getaggte `derived_from`-Index liefert die Abhängigen **direkt** und
   sichtbarkeits-blind — eine bewusste, billige Derivat-Entscheidung (§Indexierung,
   §15).

3. **Eine mechanische `provenance_walk` für beide Richtungen (§1.7 a).** Sowohl
   `find_dependents` (transitiv, *derived-from*, alle Stufen) als auch
   `traverse_provenance_backward` (*origin*, `max_depth`/`max_nodes`-beschränkt)
   laufen über **eine** private BFS: **deterministisch** (aufsteigende
   `(from,edge_ctx,to,depth)`-Adress-Order, §5.2/§1.4), **Visited-Set-zyklensicher**
   (§1.6 — ein Knoten wird nie zweimal expandiert), **budget-beschränkt**
   (`max_nodes==0` ⇒ `TraversalBudgetExceeded`, nie unbeschränkter Speicher),
   **gegatet** (VANISH/fail-closed §11.3) und **§13-aktiv** unter dem am
   `SnapshotToken` gepinnten `W`. Tests `provenance_is_cycle_safe_and_budget_bounded`
   (selbst bei einem Herkunfts-Zyklus terminiert der Lauf) und der Reopen-/Rebuild-
   Test decken dies ab.

4. **Frozen-Form ohne Capability ⇒ fail-safe leere Bereiche.** Wie bei der Phase-2-
   `traverse` tragen die Trait-Verben `find_dependents`/`traverse_provenance_backward`
   keine Capability; sie laufen daher mit **leersten** gewährten Bereichen (nur
   unbeschränkte Daten sichtbar, bereichs-beschränkte VANISHen). Die voll-gegateten
   Einstiege mit vorgelegter Capability sind die Helfer `dependents_visible` /
   `origin_inputs_visible` (je **eine** Stufe) — analog zur Helfer/Trait-Aufteilung
   der Vorphasen.

5. **Materialisierung ersetzt append-only (§10.1/§6.3).** `materialize(result,
   replaces)` hängt das fertige Ergebnis an (§7.1, Dedup §5.3); ist `replaces =
   Some(older)`, baut es den Phase-3-**Ersetzungs-Kontext** `supersedes(older)` und
   einen **Verknüpfungs-Knoten** `{ result_id, supersedes_ctx }`, der das neuere
   Ergebnis über den Ersetzungs-Kontext auf das ältere zeigen lässt — beide
   Richtungen über die bestehenden `supersedes`/`superseded_by`-Indizes traversierbar
   (§1.2). Das **ältere** Ergebnis wird **nie** mutiert/gelöscht (Test
   `newer_materialized_result_supersedes_older_without_mutating_it`). Der Kernel
   **validiert nicht** (§1.4/§7.2): er prüft **nicht**, ob `older` durabel vorliegt
   oder ob `result` überhaupt eine Herkunft trägt — das ist Sache der schreibenden
   Schicht.

### Phase 6 — Abschluss & Commit (Branch `kernel-impl`)

Phase 6 ist **fertig und grün** und wird als ein Commit eingefroren (Politik: ein
Commit pro grüner Phase). **Grün verifiziert** (`source $HOME/.cargo/env`, in
`/home/nanu/lakearch`):
- `cargo build --all-targets` — sauber (Exit 0).
- `cargo test` — **242 Tests** grün: 214 lib-Unit + 12 Kanonik-Vektoren
  (`tests/canonical_vectors.rs`) + 11 Kernel-E2E (`tests/kernel_e2e.rs`) + 5
  Store-Integration (`tests/store_index.rs`); 0 fehlgeschlagen, 0 ignoriert
  (+10 Tests gegenüber Phase 5, alle im lib-Unit-Block: model §10, store §10,
  kernel §10).
- `cargo clippy --all-targets -- -D warnings` — sauber (Exit 0, nach erzwungenem
  Neu-Lauf verifiziert).

`#![forbid(unsafe_code)]` bleibt auf `store.rs`/`kernel.rs`/`gate.rs`/`traverse.rs`/
`model.rs`; das `unsafe` lebt allein im `mmap`-Leaf `log.rs`. Kein neues Verb
berechnet/invalidiert — die spec-kritische Grenze (§1.5/§10.3) ist eingehalten und
durch einen Negativ-Test eingefroren.

### Phase 7 (Teil) — Daemon `lakearchd` + Transport-Entscheidung (Branch `kernel-impl`)

Der Daemon-Rand (`crates/lakearchd`): **ein** Bestand (= **ein** `LakearchKernel`)
hinter **einer** Schreib-Pipeline mit **vielen** nebenläufigen Lesern, die
Kernel-Primitive über das Netz, das **Tor** (§11) auf **jeder** Anfrage. **Grün:**
`cargo build --all-targets`, `cargo test` (Workspace: 242 lakearch-core + 5
lakearchd-Unit + 2 lakearchd-Integration), `cargo clippy --all-targets -- -D warnings`.

#### Transport-Entscheidung: gRPC/tonic (GEWÄHLT) — kein Fallback nötig

- **Gewählt: echtes gRPC über `tonic` 0.14** (+ `tonic-prost` 0.14 / `prost` 0.14),
  exakt wie im Plan vorgesehen (Topologie-Tabelle: „gRPC (tonic) + Arrow Flight
  (Bulk)"). Der Plan markiert Wire-Protokoll/Transport ausdrücklich als **billig
  revidierbare** Rand-Entscheidung (§14.2) — der Kernel ist davon unberührt.
- **`protoc`-Trick (umgesetzt):** in dieser Umgebung ist **kein** System-`protoc`
  installiert. `crates/lakearchd/build.rs` setzt daher `PROTOC` auf das von der
  **Build-Dependency `protoc-bin-vendored` 3** mitgelieferte, vorgebaute Binär
  (`libprotoc 31.1`), bevor `tonic-prost-build` die `.proto` kompiliert — so braucht
  weder der Build noch der CI ein System-`protoc`. Verifiziert: der ganze
  tonic/prost/hyper/axum/tower-Stack baut grün mit Rust 1.96.
  - *Hinweis:* `std::env::set_var` ist unter Rust 1.96 `unsafe`; build.rs ruft es in
    einem `unsafe`-Block (single-threaded vor jeder Nebenläufigkeit) — der
    dokumentierte Weg, prost/tonic ein protoc vorzugeben.
- **Der pure-Rust-Fallback (tokio-TCP + längen-präfigierte postcard/serde-Frames)
  war NICHT nötig** und wurde **nicht** gebaut: der gRPC-Stack baute ohne Reibung
  grün. Bliebe er je hängen (Versions-Friktion in einer anderen Umgebung), ist der
  Fallback die dokumentierte Rückfallebene; da Transport-Serialisierung eine
  Rand-Entscheidung ist (§14.2), ist der Wechsel billig.

#### Bewusst vertagt (nicht-blockierend)

- **Arrow Flight (Bulk-Streaming) VERTAGT** (Plan Phase 7: „Arrow Flight Bulk").
  Heute **nicht** gebaut, um den schweren `arrow`-Stack nicht hereinzuziehen. Die
  Unary-RPCs decken alle Primitive ab; Bulk-/Stream-Reads (großvolumige
  Traversier-/Scan-Ausgaben) kommen als eigener `arrow-flight`-Dienst am selben
  Rand dazu, **ohne** Kernel-Änderung (§14.2: reine Rand-Entscheidung). Der
  bidirektionale Explore-Stream + server-seitiges bounded Multi-Hop (gegen N+1) ist
  ebenfalls eine spätere Rand-Ergänzung.
- **C-ABI / PyO3-Binding (Plan Phase 7) VERTAGT** — separates `lakearch-ffi`-Crate,
  hier nicht im Auftrag.
- **TLS / mTLS am Rand VERTAGT:** der Server bindet heute Klartext-gRPC (für den
  In-Process-/lokalen Betrieb). Produktiv gehört mTLS + Subjekt-Authentifizierung an
  den Rand (der Daemon ist die Sicherheits-Grenze); das Subjekt kommt heute als
  Anfrage-Feld (`Subject.subject_id`), perspektivisch aus dem authentifizierten
  Verbindungs-Kontext (TLS-Identität / Token).
- **Read-Audit am Rand VERTAGT** (Plan/Trust-Modell: „Read-Audit lebt im Daemon, nicht
  im Kernel"; §8.4 Lesen erzeugt im Kernel nichts). Heute nur `tracing` am Rand; der
  strukturierte Audit-Datensatz (Subjekt, Scope, Snapshot, Grant-ID,
  Ergebnis-Kardinalität) ist eine eigene Rand-Ergänzung.

#### Topologie & Gate-Durchsetzung (umgesetzt)

- **Ein Bestand, eine Schreib-Pipeline (`bestand.rs`):** `Bestand::open` öffnet
  **einen** `LakearchKernel<RedbEdgeIndex>` und startet **einen** dedizierten
  Writer-Thread. Alle `append`s (§7.1, die EINZIGE Mutation) laufen über **einen**
  bounded `tokio::mpsc`-Kanal (Backpressure) **seriell** durch diesen Thread (eine
  Append-Reihenfolge). Lesevorgänge laufen **nebenläufig** über `spawn_blocking`
  direkt am `&self`-Kernel (der Kernel-`RwLock` erlaubt viele gleichzeitige Leser;
  MVCC-Snapshot über das Watermark, §8.4/§13). **Async am Rand, sync im Kern** — der
  Kernel bleibt unverändert sync/threaded; kein `async` im Kernel.
- **Gate auf JEDER Anfrage (`service.rs`, §11):** jede lesende RPC trägt ein
  `Subject`. Der Daemon pinnt einen Snapshot und stellt — strukturell aus den
  aktiven (nicht entzogenen) Berechtigungen im Snapshot (§11.2/§11.4) — über
  `LakearchKernel::authorize_subject` eine `Capability` aus. **Ein leeres Subjekt ⇒
  keine gewährten Bereiche** (nur unbeschränkte Daten sichtbar — fail-safe, kein
  Leck ohne Recht). VANISH (§11.3: verborgen ununterscheidbar von „nicht
  vorhanden") und fail-closed (§11: Inkonsistenz/Korruption/Vergiftung ⇒
  `Status::internal`, nie ein leckendes Teilergebnis) sind die des Kernels — der Rand
  reicht nur durch. `get_by_content_id` legt Inhalt **nur** über `gate::open` gegen
  dieselbe Capability frei (§11.5).
- **Exponierte Primitive (NUR diese, §1.4/§14.2):** `append`, `get_by_content_id`,
  die DREI §1.3-Prädikate getrennt (`content_equal`/`context_points_to`/
  `is_member_of_set`), die beschränkte `traverse` (Tiefe/Knoten-Budget §1.7 a,
  strukturelles `edge_type_filter` §3.3) und `find_dependents` (§10.3). **KEIN**
  Sortieren/Aggregieren/Ranken/Rechnen am Rand: Traversier-Schritte kommen in der vom
  Kernel emittierten aufsteigenden `ContentId`-Adress-Order (§5.2/§1.4) — der Rand
  ordnet **nichts** um.
- **Datum-Wire-Form:** `oneof { leaf-bytes | node(context_ids: [bytes;32]…) }`; die
  kanonische Kodierung/Identität (§K5) bestimmt der Kernel — der Rand reicht die Form
  nur durch und lehnt Formfehler (ID ≠ 32 Byte, leerer Knoten §K2.1) als
  `InvalidArgument` ab, sodass der Kernel nie eine ungültige Eingabe sieht.

#### Review-Härtung: §1.3-(ii/iii)-Prädikate am Daemon GEGATET (umgesetzt)

- **`context_points_to`/`is_member_of_set` tragen am Rand ein `Subject` und laufen
  durchs Tor (§11.2/§11.3).** Begründung: beide Prädikate verraten einen
  strukturellen **Besitz-/Zugehörigkeits-Fakt** über (potentiell) bereichs-
  beschränkte **oder** noch **inaktive** (§13) Daten — ein ungegateter Roh-Index-
  Match wäre ein **Struktur-Orakel** über verborgene Daten (§11.3-Verstoß). Der
  Daemon leitet daher — wie bei `get_by_content_id`/`traverse` — aus dem Subjekt die
  gewährten Bereiche ab (`authorize_subject`) und ruft die **neuen gegateten
  Kernel-Einstiege** `LakearchKernel::context_points_to_visible` /
  `is_member_of_set_visible`: beide Operanden werden am gepinnten Watermark gegen die
  Sichtbarkeit geprüft (`visible_filter` bündelt is_active §13 + Kuratierung §9.5 +
  §11-Bereich + fail-closed §11); ist **ein** Operand nicht sichtbar/inaktiv ⇒
  `value = false` (**VANISH**) — der Roh-Index wird für verborgene Operanden **nie**
  konsultiert. `content_equal` (§1.3 i) ist reine **Adress-Gleichheit** (kein Inhalt,
  kein Bereich) und trägt bewusst **kein** Subjekt.
- **`crates/lakearch-core` bleibt verhaltens-unverändert:** die Erweiterung ist rein
  **additiv** — zwei neue `pub`-Methoden (`context_points_to_visible`/
  `is_member_of_set_visible`) neben den **unangetasteten** frozen-Form-Trait-Methoden
  `Kernel::context_points_to`/`is_member_of_set` (Phase-0.5-Form unberührt; alle 214
  Kern-lib-Tests weiterhin grün). Dies verfeinert die Phase-2-Notiz „die Prädikate
  tragen keine Capability": das gilt für die **frozen-Form**; der **gegatete
  Daemon-Pfad** legt die Capability über die `*_visible`-Methoden vor.

#### Tests (`crates/lakearchd/tests/grpc_e2e.rs`, in-process, ephemerer Port :0)

- **`append_get_traverse_and_concurrent_read`:** `append` → `get_by_content_id`
  (Round-Trip durchs Tor) → kleine `traverse` (Nachbarn x,y) → `context_points_to`
  → `find_dependents` (leer für Nicht-Herkunft) → **nebenläufig** 64 Appends
  (Client A) parallel zu 64 Reads (Client B); jeder Read sieht das durable Datum
  (MVCC, keine Leser-Blockade während laufender Writes).
- **`gate_vanishes_restricted_datum_without_granting_scope`:** ein dem Bereich
  angehörendes (beschränktes) Datum **VANISHt** ohne gewährten Bereich (kein
  Subjekt **und** unberechtigtes Subjekt ⇒ `present = false`); nach Anhängen der
  Berechtigung (Subjekt → Bereich) sieht das **berechtigte** Subjekt es (§11.2);
  ein unbeschränktes Datum bleibt für alle sichtbar (Policy-Default §11.3).
- **5 Unit-Tests** (`service.rs`): Wire→Kernel-Konvertierungen (ID-Länge, leaf/node,
  leerer Knoten), Richtungs-Default Forward, sichtbarkeits-blinde/fail-closed
  Fehler-Abbildung.

`crates/lakearch-core` ist **verhaltens-unverändert** (keine Bearbeitung; 242
Kern-Tests weiterhin grün). Workspace-Member `crates/lakearchd` ergänzt.

### Phase 7 — C-ABI / In-Prozess-FFI (`crates/lakearch-ffi`, Branch `kernel-impl`)

Die **C-ABI** für das **IN-PROZESS-Embedding** in EINER Vertrauenszone (§Trust-
Modell): ein neuer Workspace-Member `crates/lakearch-ffi`, der die Kernel-
Primitive über `extern "C"`-Funktionen + opake Handle-Pointer als **cdylib +
staticlib** (+ rlib für den Rust-Integrationstest) exponiert. **Grün:**
`cargo build --all-targets`, `cargo test` (253 Tests: 214 Kern-lib + 12 Kanonik +
11 kernel_e2e + 5 store + **4 FFI c_abi** + 5 lakearchd-lib + 2 grpc_e2e),
`cargo clippy --all-targets -- -D warnings`.

#### Trust-Modell-Verortung (warum FFI ≠ Daemon)

- **Embedding bedient NUR eine Vertrauenszone.** Der Einbetter ist die
  vertrauenswürdige Schicht-darüber (Read-Audit, Berechtigungs-Ausstellung,
  Auflösung/Rechnung). **Mandantenfähig/reguliert ⇒ der Daemon** (`lakearchd`),
  nicht diese FFI. Konkret: die Lese-Verben (`get_by_content_id`, `traverse`) laufen
  mit **leeren** gewährten Bereichen (`authorize(GrantedScopes::from_scope_ids([]))`) — nur
  unbeschränkte Daten sind ohne explizites Recht sichtbar, bereichs-beschränkte
  Daten VANISHen (fail-safe §11.3). Das Tor (§11) wird dennoch auf **jedem** Read
  durchgesetzt (kein Byte-Bypass; Inhalt nur über `gate::open`).
- **Exponierte Primitive (NUR diese, §1.4/§14.2):** `lakearch_open`/`lakearch_close`
  (RAII-Handle), `lakearch_append` (§7.1), `lakearch_get_by_content_id` (§5.2 durchs
  Tor §11), `lakearch_traverse` (§1.2/§1.7 a, Streaming-Callback). **KEIN** Sortieren/
  Aggregieren/Ranken/Rechnen an der Grenze — die Schritte kommen in der vom Kernel
  emittierten aufsteigenden `ContentId`-Adress-Order (§5.2/§1.4).

#### ABI-Sicherheit: kein Panic über die C-Grenze (UB-Schutz)

- **`std::panic::catch_unwind` umschließt JEDEN FFI-Rumpf** (`guard(...)`). Ein über
  die C-ABI **unwindender** Rust-Panic ist UB; `guard` fängt ihn und liefert
  `LakearchStatus::Panic` (Code 1). **Kein** `unwrap`/`expect`/`panic!` in den
  FFI-Pfaden — Fehler sind ausschließlich Rückgabe-Codes (`LakearchStatus`,
  sichtbarkeits-blind §11.3, mechanisch §1.4). `KernelError` → genau ein Code.
- **WICHTIGE Nuance (Callback-Panic):** ein Panic, der durch eine **fremde**
  `extern "C"`-Callback-Funktion (z. B. der Traversier-Callback des C-Aufrufers)
  unwindet, **abortet bereits am Callback-Rand** (Rust-Verhalten für
  `extern "C"`-Funktionen, die der Aufrufer bereitstellt) — er erreicht unser
  `catch_unwind` nicht. Der Vertrag ist daher: **der C-Aufrufer darf keinen
  Rust-Panic durch seinen Callback lassen.** `guard` schützt den **eigenen**
  Rust-Rumpf, der die UB-relevante Stelle für diese Bibliothek ist. Der Panic-Test
  (`forced_panic_inside_ffi_is_caught_as_error_code`) erzwingt deshalb einen Panic im
  **eigenen** Rumpf über das `#[doc(hidden)]`-Test-Symbol
  `lakearch_force_panic_for_testing` (spiegelt exakt den `guard`-Rumpf) und prüft
  Code 1 statt SIGABRT.
- **`#![deny(unsafe_op_in_unsafe_fn)]`** auf `lib.rs`/`handle.rs`: jedes Pointer-
  Deref / `slice::from_raw_parts` trägt einen expliziten `unsafe`-Block mit
  SAFETY-Begründung. Null-/Form-Fehler ⇒ definierte Codes (`NullArgument`,
  `InvalidHandle`), nie Deref eines Null-Pointers.

#### Puffer-/Streaming-Protokoll (zero-surprise C-Konventionen)

- **`get_by_content_id`:** `*out_len` trägt beim Aufruf die Puffer-**Kapazität**,
  nach Erfolg die geschriebene Länge; zu klein ⇒ `BufferTooSmall` + benötigte Länge
  in `*out_len` (kein Datenverlust; Längen-Abfrage via `out_buf = null, *out_len = 0`).
- **`traverse`:** **Streaming** über `LakearchStepCallback` (je Schritt aufgerufen;
  Rückgabe `0` ⇒ kooperativer Abbruch ⇒ `Cancelled`). `out_emitted` (optional)
  meldet die Schrittzahl. Gewählt statt eines vorab dimensionierten Schritt-Puffers,
  weil die Schrittzahl a priori unbekannt ist und der Callback echte Backpressure/
  Deadline erlaubt — die Traversierung bleibt server-seitig beschränkt
  (`max_depth`/`max_nodes`, §1.7 a). **Kein `edge_type_filter`** in v1 dieser FFI
  (das Verb bietet die volle Filter-Signatur am Kernel/Daemon); nicht-blockierend,
  später additiv ergänzbar ohne ABI-Bruch (neue Funktion/Parameter).

#### C-Header

- **Hand-geschrieben:** `crates/lakearch-ffi/include/lakearch_ffi.h` (mit den
  Rust-Signaturen in `src/lib.rs` abgeglichen). **`cbindgen` ist in dieser Umgebung
  NICHT installiert** — der Header wird daher hand-gepflegt; sobald `cbindgen`
  verfügbar ist, kann er daraus generiert werden (nicht-blockierend).

#### PyO3 — VERTAGT (libpython-Embed-Dev fehlt; Default-Build bleibt grün)

- **Geprüft:** `python3` (3.14.4) ist vorhanden und `libpython3.14.so.1` liegt unter
  `/usr/lib/x86_64-linux-gnu/`, **aber** es gibt **kein** `pkg-config python3`/
  `python3-embed` und **keine** `python3-dev`-Header für das **Embedding-Linken**
  (PyO3 braucht die Entwickler-Header/Embed-Konfiguration). Daher wird **PyO3 NICHT
  in den Default-Build aufgenommen** (sonst bräche der Workspace-Grün-Zustand).
- **Vertagt — intendierte Python-Story (wenn `python3-dev`/Embed verfügbar):** ein
  separates `pyo3`-Feature/Crate, das die opaken Handles als Python-Klasse mit
  **RAII-Guards** (`__enter__/__exit__` bzw. `__del__` ⇒ `lakearch_close`) kapselt
  und Bytes als **`PyBytes`-Kopien** über die Grenze reicht (kein geliehenes
  Rust-Slice in Python-Hand). Bis dahin ist die C-ABI (`cdylib`) über `ctypes`/
  `cffi` direkt nutzbar.

`crates/lakearch-core` und `crates/lakearchd` sind **verhaltens-unverändert** (keine
Bearbeitung). Workspace-Member `crates/lakearch-ffi` ergänzt.
