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
