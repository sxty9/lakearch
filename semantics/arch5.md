# lakearch — Architektur-Entwurf v5

Semantisches Datenmodell der lakearch — ausschließlich Architektur, **nicht** technologische Umsetzung.

**arch5.md ersetzt arch4.md.** Die Kopf-Verfeinerung dieser Version ist ein **scharf gezogener Geltungsbereich** (§1): lakearch **speichert, traversiert und matcht strukturell — es rechnet, validiert und sortiert nicht.** Damit lösen sich mehrere zuvor vermutete „konzeptionelle Lücken" auf — sie waren der Versuch, von lakearch *Berechnung* zu erwarten, die eine Schicht darüber gehört. Außerdem neu: **Föderation & Topologien** (§15) und **Atomarität in Append-only** (§16). Der Identitäts-/Materialisierungs-Teil aus arch4 bleibt, aber konsistent an §1 ausgerichtet (lakearch stellt *Strukturen + Traversierung* bereit; das *Auflösen/Berechnen* läuft darüber).

---

## 1. Geltungsbereich & Nicht-Ziele

lakearch ist ein **Substrat für Speicherung und Traversierung von Daten**, kein Rechenwerk.

**lakearch leistet:**
- **Speichern** von Daten und ihren Kontexten (append-only, content-adressiert).
- **Traversieren** entlang von Kontext-Kanten (vorwärts wie rückwärts).
- **Strukturelles Matching:** Gleichheit auf Adress-/Inhaltsebene (Content-Hash), „zeigt Kontext K auf Daten D?", Mengen-Zugehörigkeit (ist D in einer per Kontext gegebenen Menge?).
- **Identität *repräsentieren* & *föderieren*** (gradierte Identitäts-Kontexte, Content-Hash über Stores hinweg).

**lakearch leistet bewusst NICHT:**
- **Rechnen** (Arithmetik, Ordnung, Aggregation) — z. B. Datums-Differenzen, Vergessenskurven, Mittelwerte.
- **Werten/Urteilen** — z. B. eine Konfidenz *erzeugen*, eine Klasse *entscheiden*, Eingaben *validieren*.
- **Sortieren** — Reihenfolge wird als Daten *gespeichert* (Positions-Kontext), das *Ordnen* macht die Schicht darüber.

Alles „Rechen-/Urteils-artige" lebt in einer **Schicht über lakearch** (App / Runner / Domänen-Profil): sie liest per Traversierung, rechnet, und schreibt ihr Ergebnis **als Daten** zurück. Beispiel: Die Vergessenskurve ist eine Rechen-Schicht, die Versuchs-Daten traversiert, Mastery berechnet und einen Checkpoint (§13) als Daten ablegt.

**Konsequenz:** Frühere „Lücken" wie Werte-Arithmetik, Projektions-Algebra, Constraints und Sortierung sind **per Design außerhalb von lakearch** und damit keine Modell-Löcher.

## 2. Grundprinzip: Eine Entität

Die lakearch kennt nur **eine** fundamentale Entität: **„Daten"**. Alles ist eine Instanz von Daten. Keine zweite Entitätsklasse, kein Schema, keine Metadaten-, Versions- oder Zeit-Objekte. Jede Ausnahme wird konsequent vermieden.

## 3. Kontext

**„Kontext"** ist keine eigene Entität, sondern eine *Rolle*, die eine Daten-Instanz einnimmt, wenn sie von einer anderen besessen wird. A besitzt Kontext K (selbst ein Daten); ein Verweis A→B = A besitzt einen Kontext, der auf B verweist. Besitz ist **gerichtet** (asymmetrisch). **Reifikation ist kostenlos**: ein Kontext kann über einen Kontext aussagen.

## 4. Vollskalierbarkeit & Typ

Struktur wird über **„Typ"** erschlossen. Typ ist ein besonderer Kontext, also nur Daten — **kein Meta-Typ-Regress**. Jede Domäne ist abbildbar, **ohne das Modell zu erweitern** (eine Domäne *erweitert lakearch nicht*, sie *drückt sich darin aus* → §9).

## 5. Identität

Identität ist **keine intrinsische Eigenschaft, sondern eine Aussage über Daten — selbst ein Kontext.**

- **5.1 Drei Ebenen:** physische ID (**Content-Hash**, reine Adressierung; store-unabhängig → Grundlage der Föderation §15) · Wert-Identität (Auto-Dedup bitgleicher Inhalte) · referenzielle Identität (über Kontexte, nie destruktiv).
- **5.2 Gradierbar:** Familie von Identitäts-Kontexten — `deckungsgleich`, `ergänzt`, `widerspricht_in`, `verwandt_mit`, `bekanntermaßen_verschieden` — jede selbst ein Daten mit Kontexten (Attribute, Konfidenz, Resolver, Zeit). *lakearch repräsentiert diese Grade; erzeugt werden sie von der Schicht darüber (§1).*
- **5.3 Quellsystem-Wissen als Kontext** am Quellsystem-Daten (stabile Schlüssel, Abweichungen, **Vertrauensgrade**). Resolver (in der Schicht darüber) lesen es zur Laufzeit → datengetrieben, auditierbar.
- **5.4 Drei Aufnahme-Pfade:** Trivial (Update), Korrelation (probabilistisch, immer eigenständig + gradierte Identität), Konflikt (explizit unklar, Auflösung auf der Leseseite).

## 6. Zeit und Versionierung

Zeit ist Daten. **Zwei Achsen:** Aufzeichnungszeit (`aufgezeichnet_am`) vs. Gültigkeitszeit (`gilt_von`/`gilt_bis`). **Append-only**: `ersetzt` markiert Überholtes ohne Löschen. **Versionierung = Speicher vs. Lesen**: historische Rekonstruktion ist eine *Projektion* unter Zeitfilter (eine Lese-/Rechen-Operation darüber), kein gespeichertes Objekt.

## 7. Konsequenzen für die Leseseite

Mehrdeutigkeit wird **beim Lesen ehrlich behandelt, nicht beim Schreiben verborgen**. Die Lese-/Rechen-Schicht entscheidet Konfidenz-Schwelle, Quellgewichtung, Zeitpunkt/Achse.

## 8. Abgrenzung zu RDF

Geteilt: eine Sorte Ding, Beziehungen selbst davon. Anders: Besitz statt Tripel-Symmetrie, native Reifikation, native gradierte Identität (Repräsentation), native Bitemporalität, keine Literal/Resource-Unterscheidung. Näher an Datomic/XTDB.

## 9. Schichtenarchitektur: Kernel, Profil, App

- **lakearch = Kernel** (Speicher + Traversierung, §1). Domänen-rein, wiederverwendbar.
- **Profil = abgeleitetes Domänenmodell *als Daten*** (kein Code-Subtyp): Vokabular, Konventionen, Config. „erbt von lakearch" = vollständig in lakearchs Primitiven ausgedrückt.
- **App / Rechen-Schicht:** alles Berechnen/Urteilen (§1), liest per Traversierung, schreibt Ergebnisse als Daten zurück.

## 10. Governance-Regel

> **Vokabular → Profil. Primitiv → Kernel. Berechnung → Schicht darüber.**
> Neuer Typ/Relation/Identitäts-Grad/Projektion → Profil. Neues **Speicher-/Traversier-Primitiv** → Kernel (domänen-agnostisch). Rechnen/Werten/Sortieren → niemals Kernel.

## 11. Methodik: Kernel zuerst, Domäne als Schleifstein

Der Kernel wird zuerst verfeinert und rein gehalten, aber am echten Druck eines vertikalen Dünnschnitts (studiq) geschärft. §12–§16 sind das Ergebnis dieses Schleifens.

---

## 12. Identitäts-Auflösung: Strukturen & Traversierung  *(lakearch-Anteil)*

Das *Auflösen* ist ein Prozess der Schicht darüber (§1). lakearch stellt die **Daten-Strukturen + Traversierung** bereit, auf denen er arbeitet:

- **12.1 Repräsentantensystem (Anker):** Hat etwas mehrere Repräsentanten, existiert ein **distinkter Klassen-Knoten** (eigenes Daten). Repräsentanten verweisen per `ist-repräsentant-von → Klasse`; anderes (z. B. Karten) hängt **am Anker**. Ein Element wird nie in die Klasse mutiert (append-only). Der Anker ist zugleich Bezugspunkt für Materialisierung (§13).
- **12.2 Graduierte, revidierbare Mitgliedschaft:** `ist-repräsentant-von` ist graduiert, kein harter Merge. **Splits** entstehen durch neue Kontexte, die alte überholen (`ersetzt`) — die Klasse teilt sich, betroffene Repräsentanten werden re-verlinkt. *(Die Schwellen/Clustering-Entscheidung trifft die Schicht darüber; lakearch speichert nur Ergebnis + Traversierpfad. Hinweis: Konfidenz ist nicht transitiv → die Rechen-Schicht nutzt Cut-Clustering, keine transitive Hülle.)*
- **12.3 Resolver-Autorität:** Bei Konflikt entscheidet **Quellvertrauen** (gelesen aus §5.3). Der Mensch ist eine einzelne, hoch-vertraute Quelle: selten, aber autoritativ; seine Korrektur haftet. lakearch *speichert* die konkurrierenden Aussagen mit ihren Resolver-/Vertrauens-Kontexten; das *Ordnen nach Vertrauen* macht die Schicht darüber.
- **12.4 Kuratierung unter Append-only:** Aufräumen = **reversible Kontexte hinzufügen** (`verbergen`, `ersetzt`, `ist-repräsentant-von`), Leseseite filtert sie weg — **nie löschen**. Physisches Entfernen = Compaction (§17). Runner (orchestriert via DevLab, App-Ebene) sind idempotent, konvergent, reversibel, auditierbar.

## 13. Materialisierung von Projektionen  *(lakearch-Anteil)*

Materialisierte Ergebnisse (z. B. „Checkpoints") dürfen **als Daten im Store liegen**:
- Ein materialisiertes Daten wird per `ersetzt` von einem neueren abgelöst → append-only-konform, Historie bleibt.
- **Was drinsteht und ob voll oder inkrementell erzeugt** — Sache der Rechen-Schicht (§1). Der *volle* Stand darf hinterlegt werden (keine Delta-Pflicht).
- **Lineage = Daten-Bindung über Kontext:** ein materialisiertes Daten trägt `abgeleitet-aus → <Eingaben>`. **Invalidierung = Rückwärts-Traversierung** dieser Kanten (lakearchs Kerngeschäft): ändert sich eine Eingabe (auch rückwirkend, §6), findet man die betroffenen Materialisierungen entlang der Lineage. *Das Neuberechnen selbst macht die Schicht darüber.*

## 14. Zugriff & Durchsetzung

Zugriff **beschreiben** (Daten) vs. **durchsetzen** (Kernel).
- **14.1 Beschreiben:** Scope-Label `gehört-zu-scope → <Bereich>` (mehrere möglich → geteilte Objekte); Grant als Daten (`subjekt`, `scope`, `recht`, Zeit, `resolver`) → auditierbar & bitemporal.
- **14.2 Durchsetzen (Reference Monitor / Row-Level Security):** jeder Lesevorgang durch **ein unumgehbares Tor**: (1) Sichtbarkeits-Bedingung aus den Grants bilden — reines **strukturelles Matching** (`Scope ∈ gewährte Scopes`), also lakearch-Kerngeschäft; (2) **vor** der Auflösung anwenden (Predicate Pushdown). **Filter-before-resolve** verhindert, dass private Repräsentanten eines geteilten Ankers (§12.1) in eine erlaubte Projektion lecken. Entzug = neuer Grant per `ersetzt`; künftige Reads filtern, Gesehenes bleibt. Kernel, weil ein Reference Monitor *immer aufgerufen, manipulationssicher, minimal* sein muss.

## 15. Föderation & Topologien

„Ein gemeinsamer Graph" **und** „getrennte Graphen, die sich verbinden" sind **beide möglich** — dieselben Primitive, zwei Topologien:

- **Intra-Store (ein Graph):** Scopes + Tor (§14) partitionieren logisch. „Teilen" = ein Scope-Grant. Geteilte Objekte = ein Daten mit mehreren Scopes.
- **Cross-Store (Föderation):** **Content-Hash** (§5.1) identifiziert wert-gleiche Daten **store-unabhängig** (dieselbe Datei → derselbe Hash überall → automatischer Abgleich beim Zusammenführen). Referenzielle Identität wird über den **Korrelations-Pfad** (§5.4) verlinkt — „Store B in Store A aufnehmen" *ist* genau dieser Pfad.

**Festlegung:** Wert-Daten nutzen Content-Hash-IDs (store-unabhängig). **Anker-IDs (§12.1) sind store-lokal** und werden beim Merge über gradierte Identität versöhnt — konsistent mit „Identität ist nie globale Wahrheit, sondern kontextuell" (§5). Es braucht **keinen neuen Mechanismus**.

## 16. Atomarität in Append-only

Mehr-Daten-Umbauten (Merge/Split §12, Grant-Wechsel §14) werden **atomar sichtbar** durch ein **einziges aktivierendes Schluss-Schreiben**:
- Schreibe alle Teile (Klassen-Knoten, Umlinkungen) zuerst; sie gelten als **inaktiv**, bis ein abschließender **Aktiv-Marker** (Kontext) gesetzt wird.
- Leser/Traversierung ignorieren Strukturen ohne Aktiv-Marker.
- Ein halb-gebauter Umbau ist damit **unsichtbar, bis er vollständig ist** — Atomarität nahezu kostenlos, ohne Transaktions-Maschinerie. (Echte Hochlast-Nebenläufigkeit kann später verschärft werden, siehe §17.)

---

## 17. Offene Punkte (verbleibend — operativ/Implementierung)

Die konzeptionellen Risse sind gelöst bzw. (durch §1) als außerhalb des Geltungsbereichs erkannt. Offen bleibt:
- **Compaction:** wann darf verborgener/überholter Zustand *physisch* entfernt werden; Spannung mit Hard-Delete-Anforderungen (DSGVO) vs. Append-only.
- **ID-Schema** (Content-Hash/UUID/hybrid), **Serialisierungsformat**, **Abfrage-/Traversier-Sprache** — Implementierung.
- **Indexierung/Performance** von Scope-Filter (Predicate Pushdown), Anker-Auflösung, Lineage-Rückwärts-Traversierung.
- **Hochlast-Nebenläufigkeit** über das Aktiv-Marker-Muster (§16) hinaus — erst relevant bei echter paralleler Multi-User-Last.

## 18. Zusammenfassung in einem Satz

lakearch ist ein append-only Substrat aus genau einer Entität — Daten, die andere Daten als Kontext besitzen —, das **speichert, traversiert und strukturell matcht** (Typ, Identität und Zeit sind besondere Kontexte; Identität ist gradiert, bitemporal und über Content-Hash föderierbar; Materialisierung, Identitäts-Strukturen und ein unumgehbares Zugriffs-Tor sind native Strukturen, Atomarität entsteht durch einen Aktiv-Marker) — während **Rechnen, Werten und Sortieren bewusst in einer Schicht darüber liegen**, die per Traversierung liest und Ergebnisse als Daten zurückschreibt.
