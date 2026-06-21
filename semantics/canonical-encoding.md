# lakearch — Kanonische Kodierung & Inhalts-Identität (v1)

> **Eingefroren. Append-only-für-immer.** Dieses Dokument legt die kanonische
> Serialisierung eines Daten und die Berechnung seiner `ContentId` **endgültig**
> fest. Jede Abweichung von diesen Regeln erzeugt einen *anderen* Hash und bricht
> damit Wert-Identität/Dedup (§5.3) und Föderation (§12.3) — **rückwirkend für das
> gesamte Universum schon geschriebener Daten**. Änderungen sind deshalb verboten;
> die einzige erlaubte Evolution ist ein **neuer, koexistierender ID-Raum** (`v2`,
> siehe §K9).

**Status:** v1 (FROZEN). **Maßgeblich übergeordnet:** `semantics/lakearch.md`
(das Gesetzbuch). Dieses Dokument ist eine Umsetzungs-Entscheidung im Sinne von
§15 (ID-Schema, Serialisierung) und darf dem Gesetzbuch nie widersprechen.

**Verbindlichkeit der Begriffe.** „MUSS" / „DARF NICHT" / „DARF" sind normativ.
Eine Implementierung, die hier „MUSS" verletzt, ist **falsch**, nicht „eine
Variante".

---

## K1 — Warum diese Spec überhaupt eingefroren wird

Die `ContentId` ist zugleich **Adresse** (§5.2 Speicher-Identität) **und**
**Dedup-Schlüssel** (§5.3 Wert-Identität) **und** das **Föderations-Band**
(§12.3: inhaltsgleich ⇒ bestand-übergreifend identisch). Es ist **ein** BLAKE3-
Hash mit drei Sichten, **nicht** drei Hashes (Gesetzbuch §5.2/§5.3; Plan
„Identitäts- & Hashing-Modell").

Daraus folgt: Die Abbildung *Daten → Bytes → Hash* muss **bit-deterministisch**
sein und für alle Zeit gleich bleiben. Ein still geänderter Encoder „re-hasht das
Universum" und bricht Dedup und Föderation lautlos. Deshalb wird die Kodierung
**vor** jedem Append-Code als erstklassiges, getestetes Artefakt eingefroren
(Plan, Phase 0.5; ADR 0001 stuft Encoding als *die* irreversibelste Entscheidung
ein).

Wir verlassen uns **nicht** auf den Default-Output einer CBOR-Bibliothek
(`ciborium`/`serde_cbor` o. ä.). Die Regeln aus §K3 werden **explizit erzwungen**
und durch Golden Vectors (§K8) plus einen **zweiten, unabhängigen Encoder** in CI
bytegleich gegengeprüft (DECISIONS-FOR-REVIEW.md, Nutzer-Bestätigung 2026-06-22).

---

## K2 — Das abstrakte Daten-Modell (was kodiert wird)

Es gibt genau **eine** Entität: das **Daten** (Gesetzbuch §2.1). Struktur
entsteht **allein durch Kontexte** (§4.3); es gibt **keine zweite Entitätsklasse**
(§2.2) und **kein** privilegiertes „Inhalts"-Feld neben den Kontexten.

Ein Daten `D` hat für die Zwecke der Kanonik genau **zwei** mögliche Bestandteile:

1. **Atomare Nutzlast** (`payload`) — **nur** vorhanden, wenn `D` ein
   **primitives Blatt** ist (es besitzt keine Kontexte). Die atomare Nutzlast ist
   ein opaker Byte-String; lakearch interpretiert ihn nicht (§1.4: lakearch wertet
   nicht).
2. **Besessene Kontexte** (`owns`) — die **Menge** der `ContentId`s der Kontexte,
   die `D` besitzt (`D ⊳ K`, §3.1/§3.2). Ein Kontext `K` ist selbst ein
   gewöhnliches Daten (§3.1); referenziert wird er hier **ausschließlich über
   seine `ContentId`** — niemals eingebettet, niemals als eigenes Edge-Objekt.

### K2.1 — Genau drei Wohlgeformtheits-Klassen

| Klasse | `payload` | `owns` | Bedeutung |
|---|---|---|---|
| **Blatt (atomar)** | vorhanden | leer | primitives Daten; dedupliziert auf seinen atomaren Bytes allein (§5.3 „ein primitives Daten existiert genau einmal"). |
| **Knoten (besitzend)** | DARF NICHT vorhanden sein | nicht leer | Daten, dessen Identität **vollständig** aus der kanonisch sortierten, deduplizierten Menge seiner besessenen Kontext-IDs entsteht (§4.3). |
| *(verboten)* | vorhanden | nicht leer | **Wohlgeformtheits-Fehler.** Es gibt kein privilegiertes Inhalts-Feld *neben* Kontexten (§2.2/§4.3). Ein Daten ist **entweder** atomares Blatt **oder** besitzt Kontexte, nie beides. |
| *(verboten)* | fehlt | leer | **Wohlgeformtheits-Fehler.** Das „leere Nichts" ist kein Daten. Ein Blatt mit *leerer* Nutzlast (`payload = []`) ist hingegen wohlgeformt und von „kein payload" verschieden (siehe §K3.5). |

> **Anmerkung zur Schichtgrenze (§1.4/§7.2).** Der **Kernel validiert nicht**.
> Die Erzwingung der Wohlgeformtheit (insb. das Verbot der gemischten Klasse) ist
> die Aufgabe der **schreibenden Schicht**. Diese Spec *definiert* nur, was eine
> kanonische Form ist; sie verlangt nicht, dass der Kernel Eingaben prüft. Der
> Kanonisierer selbst arbeitet rein mechanisch über bereits-wohlgeformten
> abstrakten Daten.

### K2.2 — Ownership ist KEINE adressierbare Entität

`D ⊳ K` ist **kein** eigenständiges, hashbares Faktum (Gesetzbuch §3.1: ein
Kontext ist die **Rolle** eines besessenen Daten `K`, kein Edge-Objekt; §2.2:
keine zweite Entitätsklasse). Die *Kante* existiert physisch ausschließlich als
abgeleiteter Index-Eintrag (`owner→contexts` / `target→referrers`, in späteren
Phasen gebaut) und bekommt **keine eigene `ContentId`**. Der früher erwogene
Vorschlag „Kante als separat adressierbares Faktum mit eigener ContentId" ist in
der Review **verworfen** (Plan; Aufgaben-Vorgabe). In der kanonischen Form eines
besitzenden Daten erscheint Besitz **nur** als das Vorkommen der Kontext-`ContentId`
in der `owns`-Menge.

### K2.3 — `owns` ist eine MENGE (sortiert, dedupliziert)

Die besessenen Kontexte bilden eine **Menge**, keine Liste:

- **Dedupliziert:** kommt dieselbe Kontext-`ContentId` mehrfach im Eingabe-
  Multiset vor, erscheint sie in der kanonischen Form **genau einmal**. (Ein
  Daten „besitzt einen Kontext" oder „besitzt ihn nicht" — Vielfachheit hat keine
  Bedeutung; sie zu kodieren würde inhaltsgleiche Daten künstlich spalten und
  §5.3 verletzen.)
- **Kanonisch sortiert:** die verbleibenden `ContentId`s werden **aufsteigend in
  lexikographischer Byte-Reihenfolge ihrer 32 Roh-Hash-Bytes** angeordnet. Diese
  Ordnung ist **rein strukturell/adressbasiert** (§5.2 „adressiert, urteilt
  nicht") und ausdrücklich **kein** Wert-Sort im Sinne von §1.4 — sie ordnet
  Adressen, nicht Werte, und ist föderationsstabil (dieselbe Tiebreak-Ordnung wie
  in der Traversierung, Plan/lib.rs).

> **Begründung (§12.3-Erhalt).** Zwei Daten mit identischen atomaren Bytes, aber
> **unterschiedlich** besessenen Kontexten, sind **verschiedene** Daten mit
> verschiedenen `ContentId`s — sonst bräche die Föderation (inhaltsgleich ⇒
> identisch). Umgekehrt müssen zwei Daten, die *dieselbe* Kontext-Menge besitzen,
> *unabhängig von der Einfüge-Reihenfolge* dieselbe `ContentId` erhalten — daher
> die feste Sortierung und Deduplizierung.

---

## K3 — Das kanonische CBOR-Profil (RFC 8949 §4.2.1 Core Deterministic Encoding)

Die kanonische Byte-Form `canonical_cbor(D)` ist CBOR (RFC 8949) unter dem
**Core-Deterministic-Encoding**-Profil (RFC 8949 §4.2.1), zusätzlich verschärft
durch die folgenden, **explizit erzwungenen** Regeln. „Default-Output einer
CBOR-Crate" gilt **nicht** als Beleg für Konformität (§K1).

### K3.1 — Kürzeste-Form-Integer (RFC 8949 §4.2.1)

Jeder Integer (Major Type 0 unsigned / Major Type 1 negative) und **jeder
Längen-/Count-Präfix** (von Byte-Strings, Text-Strings, Arrays, Maps) MUSS in der
**kürzest möglichen** Additional-Info-Form kodiert werden:

- `0..=23` → direkt im Additional-Info-Nibble (1 Byte gesamt).
- `24..=255` → `ai = 24`, 1 Folgebyte (`uint8`).
- `256..=65535` → `ai = 25`, 2 Folgebytes (`uint16`).
- `65536..=4294967295` → `ai = 26`, 4 Folgebytes (`uint32`).
- `4294967296..=18446744073709551615` → `ai = 27`, 8 Folgebytes (`uint64`).

Eine längere-als-nötige Kodierung (z. B. `25 00 17` für die Zahl 23) ist
**verboten** und MUSS, falls beim Dekodieren angetroffen, als **nicht-kanonisch
abgelehnt** werden (Strict-Decode, §K6).

### K3.2 — Nur definite-length (KEINE indefinite-length)

Indefinite-length-Kodierung (Additional Info `31`, der „break"-Code `0xFF`) ist in
der kanonischen Form **verboten** — für Byte-Strings, Text-Strings, Arrays und
Maps gleichermaßen. Jeder Container trägt seine **definite** Länge als
kürzeste-Form-Count (§K3.1). Ein angetroffener indefinite-length-Marker beim
Dekodieren ist **nicht-kanonisch** (§K6).

### K3.3 — Map-Schlüssel: bytewise sortiert, keine Duplikate

Maps (Major Type 5) MÜSSEN ihre Einträge **aufsteigend nach der bytewise-
lexikographischen Reihenfolge der vollständig kodierten Schlüssel** anordnen (RFC
8949 §4.2.1: „sorted lowest to highest … by the bytewise lexicographic order of
their deterministic encodings"). **Doppelte Schlüssel sind verboten** (sowohl beim
Kodieren als auch beim strikten Dekodieren).

> In v1 wird die Map-Struktur ausschließlich für die **feste** Top-Level-Hülle
> eines Daten verwendet (§K4). Die Schlüssel sind kleine Integer-Konstanten; ihre
> Sortierung ist damit deterministisch und trivial prüfbar.

### K3.4 — Floats: in v1 VERBOTEN (Modell-weit)

Gleitkommazahlen (Major Type 7, `ai = 25/26/27` — half/single/double) sind im
v1-Daten-Modell **vollständig verboten**. Begründung: kanonische Float-Behandlung
(kürzeste verlustfreie Form, NaN-Normalisierung, Behandlung der negativen Null
`-0.0` vs `+0.0`) ist eine Quelle subtiler, föderations-brechender Nicht-
Determinismen. Statt sie zu kanonisieren, schließen wir sie aus.

- Ein Float im Eingabe-Modell ist ein **Wohlgeformtheits-Fehler** (von der
  schreibenden Schicht zu verhindern).
- Ein Float-Major-Type-7-Item (`ai ∈ {25,26,27}`) beim strikten Dekodieren ist
  **nicht-kanonisch** und MUSS abgelehnt werden (§K6).
- Wer eine reelle/rationale Größe speichern will, kodiert sie als atomares Blatt
  (opaker Byte-String, z. B. ein Dezimal-/Verhältnis-Text) — ihre Interpretation
  liegt in der Schicht über lakearch (§1.4/§1.5).
- *(v2-Vorbehalt, §K9: ein künftiger ID-Raum darf Floats mit explizit
  spezifizierter Kanonisierung einführen; v1 tut es nicht.)*

### K3.5 — Major-Type-7 simple values

Erlaubt sind in v1 **keine** simple values außer denen, die §K4 für die feste
Hülle braucht (in v1: **keine** — die Hülle nutzt nur Maps, Arrays, unsigned
Integer und Byte-Strings). Insbesondere sind `false`/`true`/`null`/`undefined`
(`ai = 20/21/22/23`) **nicht** Teil des kanonischen Daten-Kodierungs-Alphabets von
v1; ein Bool/Null wird, falls eine Domäne es braucht, als atomares Blatt kodiert.
Ein leeres Blatt ist `payload = []` (ein Byte-String der Länge 0, `0x40`) und ist
**verschieden** von „kein payload" (= ein besitzender Knoten, §K2.1).

### K3.6 — Tags (Major Type 6)

CBOR-Tags werden in der kanonischen Daten-Form v1 **nicht** verwendet. Es gibt
**keine** Tag-Wrapper um payload oder Kontext-IDs. (Die Domain-Separation
geschieht außerhalb des CBOR, im BLAKE3-Preimage, §K5 — nicht über einen
CBOR-Tag.) Ein angetroffener Tag beim strikten Dekodieren ist **nicht-kanonisch**.

### K3.7 — Text-Strings (Major Type 3)

In v1 enthält die **feste Hülle** keine Text-Strings; atomare Nutzlast wird als
**Byte-String** (Major Type 2) kodiert, nicht als Text-String. Damit entfällt die
Frage der Unicode-Normalisierung (NFC) für die Kernform: lakearch sieht Nutzlast
als **opake Bytes** (§1.4). Bringt eine Domäne Text ein, normalisiert die
**schreibende Schicht** ihn (z. B. NFC) **vor** der Übergabe an lakearch und legt
das Resultat als Byte-String ab; lakearch kanonisiert Text nicht selbst, weil das
eine Wertung wäre. *(Diese Festlegung ist Teil des v1-Vertrags: identische
„Texte" mit verschiedener Normalisierung sind in v1 verschiedene Blätter, solange
die Schicht darüber sie nicht angleicht.)*

---

## K4 — Präziser Byte-Layout von `canonical_cbor(D)`

Die kanonische Form eines Daten ist eine **CBOR-Map mit fester, kleiner
Integer-Schlüssel-Menge**. Genau **eine** der beiden inhaltlichen Schlüssel
(payload **oder** owns) ist je vorhanden (§K2.1).

### K4.1 — Feste Schlüssel (v1)

| Schlüssel (uint) | Name | Wert-Typ | Vorhanden bei |
|---|---|---|---|
| `0` | `payload` | CBOR Byte-String (Major Type 2) | **Blatt** |
| `1` | `owns` | CBOR Array (Major Type 4) von 32-Byte-Byte-Strings | **Knoten** |

Die Schlüssel sind die kleinsten Integer; ihre kürzeste-Form-Kodierung ist
`0x00` bzw. `0x01`. Da nur **einer** der beiden je in einer konkreten Map
vorkommt, ist die Map stets ein-elementig und die Sortierung (§K3.3) trivial
erfüllt. (Die feste Integer-Schlüssel-Wahl reserviert höhere Schlüssel für eine
mögliche — aber dann **v2**! — Erweiterung; in v1 sind nur `0` und `1` definiert,
jeder andere Schlüssel ist **nicht-kanonisch**.)

### K4.2 — Blatt (atomar)

```
Daten D (Blatt, payload = P  ∈  Bytes):

  canonical_cbor(D) =
      A1                      # Map, 1 Eintrag (Major 5, count 1, kürzeste Form)
        00                    #   Schlüssel 0  (payload)
        <bstr(P)>             #   Byte-String P, definite-length, kürzeste-Form-Count
```

`<bstr(P)>` = `0x40 + len`-Kopf in kürzester Form (§K3.1) gefolgt von den
`len` Roh-Bytes von `P`. Beispiel: leeres Blatt `P = []` →
`canonical_cbor = A1 00 40`.

### K4.3 — Knoten (besitzend)

Sei `owns(D) = { c_1, …, c_n }` die **deduplizierte** Menge der besessenen
Kontext-`ContentId`s (§K2.3), und seien `c_(1) ≤ c_(2) ≤ … ≤ c_(n)` dieselben
`ContentId`s **aufsteigend in 32-Byte-lexikographischer Reihenfolge** (§K2.3).
Dann:

```
Daten D (Knoten, n ≥ 1 besessene Kontexte):

  canonical_cbor(D) =
      A1                      # Map, 1 Eintrag
        01                    #   Schlüssel 1  (owns)
        <array, count = n>    #   Array (Major 4), count n in kürzester Form (§K3.1)
          58 20 <c_(1)>       #     bstr(32) : 0x58 0x20 gefolgt von 32 Bytes
          58 20 <c_(2)>
          ...
          58 20 <c_(n)>
```

Jede `ContentId` ist exakt 32 Bytes; ihr Byte-String-Kopf ist daher **immer**
`0x58 0x20` (Major 2, `ai = 24`, Länge-Byte `0x20 = 32` — die kürzeste Form für
die Länge 32, da `32 > 23`). Die `c_(i)` erscheinen **in genau einer**
Reihenfolge (aufsteigend) und **ohne Duplikate**; jede andere Anordnung oder ein
Duplikat ist **nicht-kanonisch**.

### K4.4 — Verbotene und Grenzfälle (Zusammenfassung)

- Map mit **beiden** Schlüsseln `0` und `1` → nicht-kanonisch (gemischte Klasse,
  §K2.1).
- Map mit **null** Einträgen (`A0`) → nicht-kanonisch (leeres Nichts, §K2.1).
- `owns`-Array mit `n = 0` → nicht-kanonisch (ein Knoten ohne Kontexte ist
  entweder ein Blatt mit `payload`, oder es ist gar kein Daten).
- `owns`-Array nicht aufsteigend / mit Duplikat → nicht-kanonisch (§K2.3).
- Irgendein Element des `owns`-Arrays ≠ 32-Byte-Byte-String → nicht-kanonisch.
- Irgendein Längen-/Count-Präfix nicht in kürzester Form → nicht-kanonisch (§K3.1).
- Irgendein indefinite-length-Item, Tag, Float, oder simple-value → nicht-kanonisch
  (§K3.2/§K3.4/§K3.5/§K3.6).

---

## K5 — `ContentId`: Domain-Tag, Hash-Version & Preimage

```
ContentId(D) = BLAKE3( DOMAIN_TAG_V1 || canonical_cbor(D) )
```

- **BLAKE3**, 32-Byte-Ausgabe (default output length), als Roh-`[u8; 32]`. Keine
  Hex-Hülle, kein Multihash-Präfix *innerhalb* des Hash-Werts — die `ContentId`
  **ist** genau diese 32 Bytes (vgl. `crates/lakearch-core/src/lib.rs`,
  `ContentId([u8; 32])`).
- **`DOMAIN_TAG_V1`** ist ein **fester Byte-Präfix**, der in den BLAKE3-Preimage
  eingeht und die **Hash-Algorithmus-/Encoding-Version 1** kodiert. Er steht
  **vor** dem kanonischen CBOR und ist **nicht** Teil von `canonical_cbor(D)`
  selbst (die Domain-Separation lebt im Preimage, nicht im CBOR; vgl. §K3.6).

### K5.1 — Exakte Bytes von `DOMAIN_TAG_V1`

`DOMAIN_TAG_V1` = die **ASCII-Bytes** des folgenden Strings, **ohne**
abschließendes NUL und **ohne** Trennzeichen danach:

```
ASCII:  l  a  k  e  a  r  c  h  /  c  i  d  /  v  1  \n
Hex:    6c 61 6b 65 61 72 63 68 2f 63 69 64 2f 76 31 0a
Länge:  16 Bytes
```

- Der menschenlesbare String `lakearch/cid/v1` macht den Zweck im Hex-Dump
  selbst-dokumentierend.
- Das abschließende `0x0a` (`\n`, **ein** Byte) dient als unzweideutiger
  Trenner zwischen dem festen Tag und dem variablen CBOR — so kann **kein**
  CBOR-Inhalt jemals den Tag „verlängern" oder mit ihm verschmelzen (Längen-
  Extension-Sicherheit; BLAKE3 ist zwar selbst extension-resistent, der Trenner
  macht die Konstruktion zusätzlich audit-klar).
- Die in den Tag eingebettete Versionskomponente `v1` ist die **maßgebliche**
  Versionsmarke des ID-Raums. (Ein paralleler `format-version`-Header im Segment-
  Log ist davon **getrennt** und betrifft das *Speicherframing*, nicht den
  *Hash-Preimage*; vgl. Plan „Durability/Recovery": Frame/Footer sind **nicht**
  Teil des Preimage.)

### K5.2 — Was das Versions-Tag garantiert

Weil `DOMAIN_TAG_V1` im Preimage steht, erzeugt **jede** künftige Änderung an
diesem Dokument (Encoding-Profil, Layout, Hash-Funktion) zwingend ein neues Tag
(`DOMAIN_TAG_V2`, …) und damit einen **disjunkten, koexistierenden** ID-Raum.
Ein altes Daten und seine v2-Re-Kodierung haben **verschiedene** `ContentId`s und
kollidieren **nie** still (§K9). Das ist die Einlösung von „Hash-Algorithmus-
Version + Domain-Separation-Tag in den BLAKE3-Preimage" (Plan).

### K5.3 — Zwei Sichten, ein Hash

Die so berechnete `ContentId` ist gleichzeitig **Speicher-Identität** (§5.2:
adressiert) und **Wert-Identität** (§5.3: dedupliziert) und das **Föderations-
Band** (§12.3). Es wird **nie** ein zweiter, separater Hash über „nur den Inhalt"
gebildet — die These „Hash über den Daten-*Inhalt*" ist als §4.3/§2.2-verletzend
**verworfen** (Plan). Ein primitives Blatt dedupliziert auf seinen atomaren Bytes
allein; ein besitzender Knoten dedupliziert auf seiner sortiert-deduplizierten
Kontext-Menge (§K2 — über `canonical_cbor`, nicht über einen Sonderpfad).

---

## K6 — Strict-Decode (Kanonizitäts-Prüfung)

Ein Dekodierer im Kernel-Vertrauenskern MUSS **strikt** sein: Er akzeptiert nur
Bytes, die **bit-identisch** dem entsprechen, was der Kanonisierer für dasselbe
abstrakte Daten ausgegeben hätte. Konkret prüft Strict-Decode jede Regel aus §K3
und §K4 und **lehnt** jede nicht-kanonische Eingabe **ab** (definierter Fehler,
**kein** stilles Re-Kanonisieren). Eine bequeme Invariante zum Testen:

```
strict_decode(canonical_cbor(D)) = D          (Round-Trip)
canonical_cbor(strict_decode(bytes)) = bytes  (Idempotenz / „re-encode = identity")
```

Schlägt die zweite Gleichung für irgendwelche Bytes fehl, waren die Bytes
**nicht-kanonisch** und MÜSSEN abgelehnt worden sein. (Dieser „encode∘decode =
identity"-Test ist ein billiger, scharfer Fuzz-Fang gegen Encoder-Drift.)

---

## K7 — Zweiter, unabhängiger Encoder (Gegenprobe)

Die Konformität wird **nicht** allein durch den Produktiv-Encoder bezeugt. Ein
**zweiter, unabhängig geschriebener** Encoder (anderer Code-Pfad, idealerweise
nach diesem Dokument von Hand, ohne die CBOR-Crate des Produktiv-Pfads) MUSS für
dieselbe Eingabe **bytegleichen** Output liefern. Differenzen sind ein **CI-Fehler**
(DECISIONS-FOR-REVIEW.md; Plan). Dieser Doppel-Encoder ist die operative
Absicherung gegen „der Default einer Crate ist zufällig deterministisch — bis zur
nächsten Minor-Version".

---

## K8 — Golden Vectors (in CI für immer geprüft)

Die folgenden festen Eingaben definieren festen Output. Die **`canonical_cbor`-
Bytes sind hier bereits vollständig festgelegt** (sie folgen zwingend aus §K4 und
sind von Hand verifizierbar). Die **`ContentId`-Hex-Werte** sind als `TODO`
markiert: der **Core-Schritt** (Phase 0.5/1) berechnet sie **einmal**, trägt sie
hier **und** in einen Golden-Vector-Test (`tests/`) ein und friert sie damit ein.
Ab dann ist jede Abweichung ein CI-Fehler.

> **Berechnungsregel für die TODOs:** `ContentId = BLAKE3(DOMAIN_TAG_V1 ||
> canonical_cbor)` mit `DOMAIN_TAG_V1 = 6c 61 6b 65 61 72 63 68 2f 63 69 64 2f 76
> 31 0a` (§K5.1). Hex in **Kleinbuchstaben**, 64 Hex-Ziffern.

> **Eingefroren (2026-06-22).** Die folgenden `ContentId`-Hex-Werte sind vom
> Core-Schritt berechnet, hier eingetragen und in
> `crates/lakearch-core/tests/canonical_vectors.rs` assertiert. Ab jetzt ist
> jede Abweichung ein CI-Fehler (§K9).

### GV-1 — leeres Blatt (`payload = []`)

- abstrakt: Blatt, `payload = []`
- `canonical_cbor` (3 Bytes): `A1 00 40`
- `BLAKE3`-Preimage (19 Bytes) = `DOMAIN_TAG_V1` (16) ‖ `canonical_cbor` (3):
  `6c 61 6b 65 61 72 63 68 2f 63 69 64 2f 76 31 0a   a1 00 40`
- **`ContentId`** = `e05fc4bc77e675f131dd618eb2181f1be23dc4ddc6bcdc4c1a342e1312484921`

### GV-2 — Blatt mit Nutzlast `0x01 0x02 0x03`

- abstrakt: Blatt, `payload = 01 02 03`
- `canonical_cbor` (6 Bytes): `A1 00 43 01 02 03`
  (`43` = bstr-Kopf für Länge 3, kürzeste Form)
- **`ContentId`** = `2615273e765a89ac9dd6ebc5a2b6470832c3bf29173faea3c45a2f91b015e4f5`

### GV-3 — Blatt mit Nutzlast „a" (`0x61`)

- abstrakt: Blatt, `payload = 61`
- `canonical_cbor` (4 Bytes): `A1 00 41 61`
- **`ContentId`** = `07ba90197aa18f77e57afa5b11591ce17f6177686aead272aaee02b8d60a5c9d`
- *(Dient als Quell-`ContentId` für GV-5/GV-6 unten; nenne ihn `CID_a`.)*

### GV-4 — Blatt mit langer Nutzlast (Länge 24, kürzeste-Form-Grenze)

- abstrakt: Blatt, `payload =` 24 Bytes `00 01 02 … 17`
- `canonical_cbor` (28 Bytes): `A1 00 58 18` gefolgt von `00 01 … 17`
  (`58 18` = bstr-Kopf für Länge 24 = `0x18`; **kürzeste** Form, da `24 > 23`;
  4 Kopf-Bytes + 24 Nutzlast = **28** Bytes)
- **`ContentId`** = `f3a86f813e3185d1d6e0c9f638e778164e4ed8083e335f959ce2f70942376922`
- *(Prüft die Additional-Info-`24`-Grenze aus §K3.1.)*

### GV-5 — Knoten mit **einem** besessenen Kontext (`CID_a` aus GV-3)

- abstrakt: Knoten, `owns = { CID_a }` (32 Bytes)
- `canonical_cbor` (37 Bytes): `A1 01 81 58 20` gefolgt von den 32 Bytes von
  `CID_a` (`81` = Array count 1; `58 20` = bstr(32))
- **`ContentId`** = `062d53bd4352003017079e8b9a5938fb3e7e294566efd89773addc4dbc9fa7ee`

### GV-6 — Knoten mit **zwei** Kontexten — Sortier- & Dedup-Beleg

- abstrakt: Knoten, Eingabe-Multiset `owns = { CID_b, CID_a, CID_b }`
  wobei `CID_a` = GV-3 und `CID_b` = `ContentId` von GV-2 (Blatt `01 02 03`)
- erwartete kanonische Menge: dedupliziert zu `{ CID_a, CID_b }`, dann
  **aufsteigend** nach 32-Byte-Order sortiert → `[ CID_a, CID_b ]`
  (denn `07… < 26…`)
- `canonical_cbor` (71 Bytes): `A1 01 82` gefolgt von `58 20 <CID_a>`
  und `58 20 <CID_b>` (`82` = Array count 2; 3 Kopf + 2×34 = **71** Bytes)
- **`ContentId`** = `6d909d128f2a3a31f642589578c94f96f5ee1a3a706273a8f7ff1ccac618b134`
- *(Dieser Vektor ist der zentrale Beweis für §K2.3: Eingabe-Reihenfolge und
  Duplikat dürfen das Resultat **nicht** ändern. Der Test prüft dieselbe `ContentId`
  auch für die Eingabe-Permutationen `{ CID_a, CID_b }` und `{ CID_b, CID_a }`
  sowie für ein dupliziertes Multiset.)*

---

## K9 — Append-only-für-immer & der Weg zu v2

1. **Dieses Dokument ist eingefroren.** Keine Regel in §K2–§K8 darf für v1
   geändert werden. Das gilt insbesondere für: `DOMAIN_TAG_V1`-Bytes, das
   CBOR-Profil, den Byte-Layout, die Sortier-/Dedup-Regel und die Float-/Tag-/
   indefinite-Verbote.
2. **Lesen für immer, schreiben nur aktuell.** Eine Implementierung MUSS in der
   Lage bleiben, v1-`ContentId`s für immer zu *reproduzieren* und v1-Daten zu
   *lesen* (§7.1: append-only, nie gelöscht). (Das Speicher-Format trägt dafür
   einen separaten `format-version`-Header; vgl. Plan/§K5.1.)
3. **Evolution = neuer ID-Raum, niemals Mutation.** Wird je ein anderes Encoding
   oder eine andere Hash-Funktion gebraucht, geschieht das als **v2** mit einem
   **anderen Domain-Tag** (`lakearch/cid/v2\n` o. ä.) und damit einem **disjunkten,
   koexistierenden** Adress-/Dedup-Raum. v1- und v2-`ContentId`s desselben
   abstrakten Daten sind verschieden und kollidieren nie still (§K5.2). Eine
   Migration ist dann ein **Append** neuer v2-Daten neben den v1-Daten, verbunden
   über gradierte Identitäts-Kontexte (§5.5/§5.7b) — **kein** destruktives
   Re-Hashing (§5.4/§7.1).

---

## K10 — Querverweise

- Gesetzbuch: §1.4 (kein Rechnen/Werten), §2.1/§2.2 (eine Entität), §3.1/§3.2
  (Kontext = Rolle, gerichtet), §4.3 (Struktur allein durch Kontexte), §5.2/§5.3
  (eine Identität, zwei Sichten), §5.4/§5.5/§5.7 (referenzielle Identität,
  gradiert, Pfade), §7.1 (append-only), §12.3/§12.4 (Föderation über Hash; Anker
  bestand-lokal), §15 (Serialisierung/ID-Schema bewusst offen).
- Plan: `~/.claude/plans/lakearch-geht-in-die-indexed-sphinx.md`, Abschnitte
  „Identitäts- & Hashing-Modell" und „Roadmap/Phase 0.5".
- ADR: `docs/adr/0001-kernel-technology.md` (stuft Encoding als irreversibelste
  Entscheidung ein).
- Code: `crates/lakearch-core/src/lib.rs` (`ContentId`/`AnchorId`-Newtypes);
  künftig `crates/lakearch-core/src/serialize.rs` (Kanonisierer + Strict-Decode)
  und `crates/lakearch-core/tests/` (Golden Vectors §K8).
