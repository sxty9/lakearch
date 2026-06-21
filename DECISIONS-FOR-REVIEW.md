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
