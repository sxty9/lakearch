# ADR 0001 — Kernel-Technologie: Sprache, Kanonik, Storage, Trust-Modell

- **Status:** Akzeptiert (eingefroren, soweit als irreversibel markiert)
- **Datum:** 2026-06-22
- **Branch:** `kernel-impl`
- **Kontext-Dokumente:** Gesetzbuch `semantics/lakearch.md`; gehärteter Plan
  `~/.claude/plans/lakearch-geht-in-die-indexed-sphinx.md`; bestätigte
  Entscheidungen `DECISIONS-FOR-REVIEW.md`; Kanonik-Spec
  `semantics/canonical-encoding.md`.

> **Reversibilitäts-Leitsatz.** Nur **zwei** der hier getroffenen Entscheidungen
> sind wirklich **irreversibel** und verdienen die meiste Sorgfalt:
> **(1) die kanonische Kodierung/Hash** (noch mehr als die Sprache — ein stiller
> Encoder-Wechsel re-hasht das gesamte Universum und bricht Dedup §5.3 +
> Föderation §12.3) und **(2) die Sprache**. Alles Übrige (Index-Engine,
> Wire-Protokoll, Transport-Serialisierung) ist **billig revidierbar**, weil das
> Append-Log die alleinige Wahrheit ist; es wird hier bewusst **nicht** über-
> verteidigt.

---

## Entscheidung 1 — Sprache = **Rust**  ·  Reversibilität: **IRREVERSIBEL**

### Begründung (Reihenfolge nach adversarieller Neugewichtung)

Die ursprüngliche Begründung „GC-Tail-Latenz" wurde in der adversariellen
Multi-Agent-Validierung **zurückgestuft** (moderne Go-/ZGC-Collectoren 2026 haben
das weitgehend entschärft). Maßgeblich, in dieser Reihenfolge:

1. **Sauberes In-Process-Embedding mit Zero-Copy** für den First-Class-Python-KI-
   Client (KI ist First-Class-Client für Schreiben **und** Lese-Traversierung).
   Go (cgo/Runtime-in-Process) und JVM (JNI/Footprint) scheitern hier hart.
2. **Compile-Time-Data-Race-Sicherheit** auf dem MVCC-Leser-+-Single-Writer-Pfad
   (`Send`/`Sync`). C++/Zig erreichen das nur per TSan/Disziplin.
3. **Cache-Layout-Kontrolle** für das Pointer-Chasing der Traversierung
   (§1.2/§1.7a).
4. **(zurückgestuft)** GC-Tail-Latenz — kein tragender Grund mehr.

**Zyklen-Einwand aufgelöst (§1.6):** Der Graph ist immutable, inhaltsadressierte
Blobs im Log + **Kanten als Index-Einträge**, traversiert über besessene IDs mit
Visited-Set — **nie** ein lebender `Rc<RefCell>`-Objektgraph. Der Borrow-Checker
steht der Zyklen-Erlaubnis des Modells damit nicht im Weg.

### Flip-Bedingungen (explizit festgehalten)

- **Reine Daemon-Topologie** (Embedding fällt aus dem Scope) → **Go** tragfähig.
- **Zig 1.0 + kleines Expertenteam** → **Zig** konkurrenzfähig.
- **Beide Bedingungen treten nach Nutzerentscheidung 1 (s. u.) nicht ein:**
  Embedding bleibt im Scope, daher bleibt es bei Rust.

---

## Entscheidung 2 — Kanonik = **RFC 8949 Core Deterministic Encoding (selbst erzwungen)**  ·  Reversibilität: **IRREVERSIBEL (die irreversibelste)**

- **Profil:** RFC 8949 §4.2.1 Core Deterministic Encoding, **explizit erzwungen**:
  kürzeste-Form-Integer/Längen, **nur** definite-length, bytewise-sortierte
  Map-Schlüssel ohne Duplikate, **Floats in v1 verboten**, keine Tags, keine
  indefinite-length. Vollständig und eingefroren in
  `semantics/canonical-encoding.md`.
- **Identität:** **EIN** BLAKE3-Hash mit drei Sichten — Speicher-Identität (§5.2,
  adressiert), Wert-Identität (§5.3, dedupliziert), Föderations-Band (§12.3).
  **Nicht** zwei verschiedene Hashes. Ein Daten ist **vollständig** durch seine
  kanonische Form definiert; diese **schließt die ContentId-Referenzen der
  besessenen Kontexte ein** (§4.3). Es gibt **kein** privilegiertes „Inhalts"-Feld
  (§2.2/§4.3); die lose Formel „Hash über den Daten-*Inhalt*" ist **verworfen**.
- **Domain-Separation + Version:** `ContentId = BLAKE3(DOMAIN_TAG_V1 ||
  canonical_cbor(D))`. Das Versions-Tag im Preimage garantiert, dass jede künftige
  Encoding-/Hash-Änderung einen **neuen, koexistierenden** ID-Raum (`v2`) erzeugt
  statt stiller Kollisionen.
- **Beweis statt Vertrauen:** **nicht** auf den Default-Output einer CBOR-Crate
  verlassen; **Golden Vectors** (fixe Eingabe → fixe ContentId-Bytes) in CI für
  immer + ein **zweiter unabhängiger Encoder**, der bytegleich übereinstimmt
  (DECISIONS-FOR-REVIEW.md, Nutzer-Bestätigung 2026-06-22).
- **Begründung der Irreversibilität:** Ein still geänderter Encoder re-hasht das
  gesamte gespeicherte Universum und bricht Dedup + Föderation **rückwirkend und
  lautlos**. Deshalb höchste Sorgfalt und Einfrieren **vor** jedem Append-Code.

---

## Entscheidung 3 — Storage = **Log-als-Wahrheit + neu-baubarer Index**  ·  Reversibilität: Log-Format teilw. fix; **Engine billig revidierbar**

- **Invariante:** Ein eigenes Append-Segment-**Log ist die alleinige
  Durability-Wahrheit** (§7.1). **Alle** Sekundär-Indizes sind reine, löschbare,
  jederzeit **neu-baubare** Projektionen über das Log (§8.4) und werden **nie**
  gesichert.
- **Engine per Benchmark, nicht per Reinheit (Nutzerentscheidung 2):** Die
  konkrete eingebettete KV-Engine für die Indizes (`owner→contexts`,
  `target→referrers`) wird **erst gemessen, dann festgelegt** — ein
  **Benchmark-Gate in Phase 1** (100M–1Mrd winzige Kanten nebenläufig; Write/Space-
  Amplification; p99-Präfix-Scan; Langläufer-Reader-File-Bloat) entscheidet
  zwischen z. B. **redb / LMDB(heed) / RocksDB**. Das dominante Muster
  (Tiny-Edge-Massen-Ingest + Präfix-Scans, §10.3) **begünstigt einen LSM** — daher
  RocksDB **nicht** per Reinheit verwerfen.
- **Warum billig revidierbar:** Weil das Log die Wahrheit ist, ist die Engine
  **austauschbar** (Index wegwerfen, neu bauen). Abstraktion auf **semantischer**
  Ebene (Edge-Index-Interface, das owned `ContentId`s liefert), nicht auf der
  Engine-API.
- **Format-Aspekte, die früh fixiert werden (Phase 0.5/1, weil format-bindend):**
  Segment/Record-Header (`magic + format-version + checksum-algo-id`), reservierte
  Felder (activation-epoch, constituent-range, **shard-id**, index-validity-offset),
  Compaction/DSGVO-Strategie (Crypto-Shredding; Index referenziert **stabile
  logische ID**, nie rohe Byte-Offsets). Frame/Footer sind **nicht** Teil des
  BLAKE3-Preimage.

---

## Entscheidung 4 — Trust-Modell = **Embedding nur Einzel-Vertrauenszone; Daemon für Multi-Tenant**  ·  Reversibilität: revidierbar (Topologie)

- **Nutzerentscheidung 1:** Embedding ist **nur in einer Vertrauenszone** erlaubt
  — der Einbetter **ist** selbst die vertrauenswürdige „Schicht darüber". Im
  Embedded-Fall läuft das Tor (§11) im Adressraum des Einbetters und ist gegen ihn
  **per Konstruktion keine Sicherheitsgrenze**.
- **Mandantenfähige / regulierte / gegenseitig-misstrauische Workloads MÜSSEN den
  Daemon (`lakearchd`) nutzen.** Nur dort ist das Tor eine echte Grenze und führt
  Read-Audit (Subjekt, Scope, Snapshot, Grant-ID, Ergebnis-Kardinalität).
  Read-Audit lebt im **Daemon**, nicht im Kernel (§8.4: Lesen erzeugt nichts).
- **Wirkung:** löst das Risiko „Embedded-Trust-Downgrade" durch **explizite
  Abgrenzung** statt teurem In-Process-Sandboxing. Diese Entscheidung hält
  zugleich die Sprach-Flip-Bedingung „reine Daemon-Topologie" geschlossen (s. E1).
- **Tor-Eigenschaften (gelten unabhängig vom Modus, Compile-erzwungen):** Store/
  Index liefern nur opake `SealedRecord`; die einzige `SealedRecord → VisibleDatum`
  lebt in `gate.rs` und verlangt ein nicht-konstruierbares `Capability`-Token →
  „Tor vergessen" ist ein **Compile-Fehler**. Zweiphasig (Filter-vor-Auflösen
  §11.3), **match-only** (§1.3, keine Zeitfenster-Auswertung — das wäre Ordnung,
  §1.4), **fail-closed**, **VANISH** (verborgen ununterscheidbar von „existiert
  nicht").

---

## Kernel-Boundary (gilt für alle obigen Entscheidungen)

Der Kernel macht **ausschließlich**: append (§7.1), mechanische zyklensichere
Traversierung (§1.2/§1.7a), strukturelles Matching (§1.3), das Zugriffs-Tor
(§11), Inhaltsadressierung + Dedup (§5.2/§5.3), Föderation über Hash (§12.3),
Invalidierung = Rückwärts-Traversierung (§10.3), Atomarität über Aktiv-Marker
(§13). **Nicht** im Kernel: Rechnen, Werten, Sortieren, Aggregieren, Konfidenz,
Identitäts-*Entscheidung*, Eingabe-Validierung, „Platz finden", Lese-Auflösung
(§1.4/§1.5/§7.2/§8). Jede Verb-Benennung in der API ist so gewählt, dass sie
**kein** verbotenes Verhalten einlädt (Plan, „Kernel-API-Vertrag").

---

## Reversibilitäts-Übersicht

| Entscheidung | Wahl | Reversibilität |
|---|---|---|
| Sprache | Rust | **irreversibel** (Flip nur bei reiner Daemon-Topologie / Zig 1.0 — beide ausgeschlossen) |
| Kanonik/Hash | RFC 8949 deterministisch + BLAKE3 + Domain-Tag-v1 | **irreversibel — die irreversibelste**; Evolution nur als koexistierender v2-Raum |
| Storage-Modell | Log = Wahrheit, Index = neu-baubares Derivat | Modell fix; **konkrete Engine billig revidierbar (Phase-1-Benchmark)** |
| Trust-Modell | Embedding = Einzel-Vertrauenszone; Daemon = Multi-Tenant | revidierbar (Topologie-Entscheidung) |
| Wire-Protokoll / Transport | gRPC (tonic) + Arrow Flight + In-Process-Binding | **billig revidierbar** (Phase 7) |

---

## Folgen

- `semantics/canonical-encoding.md` ist das eingefrorene Begleit-Artefakt zu
  Entscheidung 2 und MUSS vor jedem Append-Code stehen (erfüllt).
- Die Index-Engine-Wahl bleibt **offen bis zum Phase-1-Benchmark-Gate**; bis dahin
  programmiert der Core gegen ein semantisches Edge-Index-Interface.
- Embedding-Konsumenten sind vertraglich auf Einzel-Vertrauenszonen beschränkt;
  Multi-Tenant-Deployments laufen über `lakearchd`.
