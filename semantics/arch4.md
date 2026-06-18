# lakearch — Architektur-Entwurf v4

Semantisches Datenmodell der lakearch — ausschließlich Architektur, **nicht** technologische Umsetzung.

**arch4.md ersetzt arch3.md.** Es übernimmt den Kern (§1–§10) unverändert in der Substanz und löst die fünf konzeptionellen „Risse", die die erste abgeleitete Domäne (studiq) am Modell sichtbar gemacht hatte (in arch3 §11.2 nur benannt). Diese fünf fallen auf **drei Kernel-Bauaufgaben** zusammen:

1. **Identitäts-Auflösung als Prozess** (§11) — vereint die alten Risse R1 (Anker), R3 (Vorrang) und R5 (Kuratierung).
2. **Materialisierung von Projektionen** (§12) — alter Riss R2 (Checkpoints).
3. **Zugriff & Durchsetzung** (§13) — alter Riss R4 (Reference Monitor).

Durch alle drei zieht sich die Governance-Regel (§9): **Mechanik → Kernel, Politik → Profil.** Die Politik-Werte (Schwellen, Vertrauensränge, Kadenzen) liegen im Profil (für studiq: `studiqarch`).

---

## 1. Grundprinzip: Eine Entität

Die lakearch kennt nur **eine** fundamentale Entität: **„Daten"**. Alles ist eine Instanz von Daten. Keine zweite Entitätsklasse, kein Schema, keine Metadaten-Schicht, keine Versions- oder Zeit-Objekte. Diese radikale Reduktion ist das Kernprinzip; jede Ausnahme wird konsequent vermieden.

## 2. Kontext

**„Kontext"** ist keine eigene Entität, sondern eine *Rolle*, die eine Daten-Instanz einnimmt, wenn sie von einer anderen besessen wird. A besitzt Kontext K (selbst ein Daten); ein Verweis A→B wird ausgedrückt, indem A einen Kontext besitzt, der auf B verweist. Besitz ist **gerichtet** (asymmetrisch, anders als das symmetrische RDF-Tripel). **Reifikation ist kostenlos**: ein Kontext kann über einen Kontext aussagen.

## 3. Vollskalierbarkeit & Typ

Daten haben keine feste Struktur; sie wird über **„Typ"** erschlossen. Typ ist ein besonderer Kontext, also nur Daten — **kein Meta-Typ-Regress**. Jede Domäne ist abbildbar, **ohne das Modell zu erweitern** (Dreh- und Angelpunkt für §8: eine Domäne *erweitert lakearch nicht*, sie *drückt sich darin aus*).

## 4. Identität

Identität ist **keine intrinsische Eigenschaft, sondern eine Aussage über Daten — selbst ein Kontext.**

- **4.1 Drei Ebenen:** physische ID (Content-Hash, reine Adressierung) · Wert-Identität (Auto-Dedup bitgleicher Inhalte) · referenzielle Identität (über Kontexte, nie destruktiv).
- **4.2 Gradierbar:** eine Familie von Identitäts-Kontexten — `deckungsgleich`, `ergänzt`, `widerspricht_in`, `verwandt_mit`, `bekanntermaßen_verschieden` — jede selbst ein Daten mit Kontexten (betroffene Attribute, Konfidenz, Resolver, Zeit).
- **4.3 Quellsystem-Wissen als Kontext** am Quellsystem-Daten (stabile Schlüssel, Abweichungen, **Vertrauensgrade**). Resolver lesen es zur Laufzeit → datengetrieben, auditierbar. *(§11.3 baut hierauf auf.)*
- **4.4 Drei Aufnahme-Pfade:** Trivial (Update), Korrelation (probabilistisch, immer eigenständig + gradierte Identität), Konflikt (explizit unklar, Auflösung auf der Leseseite).

## 5. Zeit und Versionierung

Zeit ist Daten; Zeit-Aussagen sind besondere Kontexte. **Zwei Achsen:** Aufzeichnungszeit (`aufgezeichnet_am`) vs. Gültigkeitszeit (`gilt_von`/`gilt_bis`), dürfen auseinanderfallen. **Append-only**: Änderungen fließen als neue Daten ein, `ersetzt` markiert Überholtes ohne Löschen. **Versionierung = Speicher vs. Lesen**: historische Rekonstruktion ist eine *Projektion* unter Zeitfilter, kein gespeichertes Objekt.

## 6. Konsequenzen für die Leseseite

Komplexität verschiebt sich in die Abfrage: jede Abfrage entscheidet implizit Konfidenz-Schwelle, Quellgewichtung, Zeitpunkt/Achse. Mehrdeutigkeit wird **beim Lesen ehrlich behandelt, nicht beim Schreiben verborgen**.

## 7. Abgrenzung zu RDF

Geteilt: eine Sorte Ding, Beziehungen sind selbst davon. Anders: Besitz statt Tripel-Symmetrie, native Reifikation, native gradierte Identität, native Bitemporalität, keine Literal/Resource-Unterscheidung. Näher an Datomic/XTDB.

## 8. Schichtenarchitektur: Kernel, Profil, App

- **lakearch = Kernel/Engine:** implementiert §1–§7 + §11–§13. Domänen-rein, einmal gebaut, wiederverwendbar.
- **Profil = abgeleitetes Domänenmodell *als Daten*** (kein Code-Subtyp, erweitert das Modell nicht): Vokabular (Typ-/Relations-Daten), Konventionen, Config (Schwellen, Projektionen), ggf. registrierte Erweiterungen an Kernel-Erweiterungspunkten. „erbt von lakearch" = *vollständig in lakearchs Primitiven ausgedrückt, auf lakearchs Engine lauffähig*.
- **App** (z. B. studiq): liest/schreibt über den Kernel mit ihrem Profil; ihre „einfache" Sicht ist eine materialisierte Lese-Projektion (Komplexität im Store, Simplizität in der Sicht).

## 9. Governance-Regel

> **Vokabular → Profil. Primitiv → Kernel.**
> Neuer Typ / Relation / Identitäts-Grad / Projektion → Profil (Daten/Config). Neues **Primitiv** (Engine muss es nativ verstehen) → Kernel-Änderung, **domänen-agnostisch** gerechtfertigt, kommt allen Profilen zugute.

Beispiel-Diskriminierung: *bitemporales Lesen = Kernel, Vergessenskurve = Profil; Such-Index = Kernel, Match-Schwelle = Profil.* Der Kernel stellt **Erweiterungspunkte** (registrierbare Resolver-/Projektions-Strategien); Profile bestücken sie.

## 10. Methodik: Kernel zuerst, Domäne als Schleifstein

Der Kernel wird zuerst verfeinert und rein gehalten — aber am echten Druck eines vertikalen Dünnschnitts geschärft (studiq ist Schleifstein, nicht Form). An jeder Reibungsstelle entscheidet §9. Die §11–§13 sind genau das Ergebnis dieses Schleifens an studiq.

---

## 11. Identitäts-Auflösung als Prozess  *(löst R1 + R3 + R5)*

Referenzielle Identität (§4.2) ist kein einmaliges Urteil, sondern ein **fortlaufender, quellen-vertrauens-gewichteter, reversibler, materialisierter Prozess**. Drei Aspekte:

### 11.1 Repräsentantensystem (Anker)  *— war R1*

„Das Ding" ist sonst nur ein Lese-Cluster aus Identitäts-Kontexten — Apps brauchen aber stabile Griffe. Daher:

- Hat etwas mehrere Repräsentanten, prägt der Kernel einen **eigenen, distinkten Klassen-Knoten** (Repräsentantensystem) — ein Daten mit eigener ID. **Ein Element wird nie in die Klasse mutiert** (Append-only).
- Repräsentanten verweisen per `ist-repräsentant-von → Klasse`. Anderes (z. B. Karten in studiq) hängt **am Klassen-Knoten**, nicht an einem Repräsentanten → stabiler Anker bei Merge/Split.
- Der Klassen-Knoten ist zugleich **Cache-Anker** für §12 (Projektionen referenzieren ihn).

### 11.2 Graduierte, revidierbare Mitgliedschaft — *Nicht-Transitivität & Split*

Konfidenz-basierte Identität ist **nicht transitiv** (A~B 0.96, B~C 0.96 ⇏ A~C). Naive transitive Hülle über einer Schwelle lässt den Graphen **verklumpen**. Daher:

- Mitgliedschaft (`ist-repräsentant-von`) ist **graduiert und revidierbar**, kein harter Merge.
- Zusammenführung erfolgt über eine **Clustering-Policy mit Cut-Schwelle** (Profil-Config), **nicht** über transitive Closure.
- Klassen können sich **wieder teilen** (`split`): widerspricht eine höher-vertraute Quelle (§11.3), spaltet der Prozess den Klassen-Knoten und re-verlinkt betroffene Repräsentanten; Anhänge am Anker werden nach Policy re-zugeordnet.

**Kernel:** Anker-/Mitgliedschafts-/Split-Mechanik. **Profil:** Schwellen, Clustering- und Split-Kriterien.

### 11.3 Resolver-Autorität: quellen-vertrauens-getriebener Vorrang  *— war R3*

Bei widersprüchlichen Aussagen (Mensch vs. Maschine, Maschine vs. neuere Maschine) entscheidet **nicht** „Mensch immer" oder „neuste immer", sondern das **Vertrauen der Quelle** — gelesen aus den Quellsystem-Kontexten (§4.3, datengetrieben).

- Jede Aussage trägt Resolver + Quelle; bei Konflikt ordnet die Engine nach **Vertrauensrang**.
- Der **Mensch ist eine einzelne, hoch-vertraute Quelle**: greift selten ein, aber autoritativ — eine menschliche Korrektur **haftet** und wird von späteren Maschinen-Läufen nicht überschrieben. (Kein „Mensch nie korrigierbar"; das Tool bleibt korrigierbar, ohne den Lernenden zum Hausmeister zu machen.)

**Kernel:** Vorrang-Mechanik (Konflikte nach Quellvertrauen ordnen). **Profil:** die konkreten Vertrauensränge.

### 11.4 Kuratierung unter Append-only  *— war R5*

Aufräumen heißt **nie löschen**, sondern **reversible Kontexte hinzufügen** (`verbergen`, `ersetzt`, `ist-repräsentant-von`); die Leseseite filtert sie weg. *Physisches* Entfernen ist **Compaction** — eine separate, seltene, gesondert gesicherte Operation (§14).

- Kuratierung ist nichts anderes als §11.1–§11.3 **im Batch**: Hintergrund-Resolver, die Dubletten zu Klassen zusammenlegen und Müll verbergen, gesteuert durch Quellvertrauen.
- Anforderungen an solche Runner: **idempotent** (Re-Run dupliziert keine Kontexte), **konvergent** (kein Oszillieren merge↔split), **reversibel**, **auditierbar** (Resolver/Konfidenz/Zeit nativ).
- Die **Orchestrierung** der Runner ist App-/Infrastruktur-Sache (für studiq: DevLab), nicht Kernel oder Profil.

## 12. Materialisierung von Projektionen  *(löst R2)*

„Alles beim Lesen berechnen" ist für hochfrequente, große Projektionen zu teuer. Daher dürfen **materialisierte Projektionen selbst als Daten im Store liegen**:

- Eine materialisierte Projektion (z. B. ein „Checkpoint") ist ein Daten, das per `ersetzt` von einem neueren abgelöst wird → **append-only-konform**, volle Historie bleibt.
- **Lesen** = jüngster gültiger Checkpoint **+ inkrementelles Replay** der Deltas seither (nicht die ganze Historie).
- Gespeichert wird der **Zustand/Parameter**, aus dem sich der Live-Wert billig berechnen lässt — **nicht** ein bereits abgeleiteter Skalar (sonst sofort veraltet bei zeit-kontinuierlichen Funktionen).
- **Granularität pro Anker** (§11.1), nicht global.
- **Invalidierung** ist der harte Teil: ein Checkpoint trägt einen **Abhängigkeits-/Gültigkeitsmarker**. Rückwirkende Schreibvorgänge (Bitemporalität, §5) **und** Merge/Split von Ankern (§11.2) markieren abhängige Checkpoints als stale → Neuberechnung der Betroffenen.

**Kernel:** Snapshot-als-`ersetzt`-Daten, inkrementelles Replay, Invalidierungs-/Abhängigkeitsmechanik. **Profil:** *was* materialisiert wird, *Kadenz*, Granularität, der konkrete Replay-Operator.

## 13. Zugriff & Durchsetzung  *(löst R4)*

Zwei getrennte Maschinen: Zugriff **beschreiben** (Daten) vs. Zugriff **durchsetzen** (Engine).

### 13.1 Beschreiben (Daten)
- **Scope-Label** an Daten: `gehört-zu-scope → <Bereich>` (ein Daten kann zu mehreren Scopes gehören → geteilte Objekte).
- **Grant** als Daten: `typ:zugriff` mit `subjekt`, `scope`, `recht`, plus Zeit-Kontexte und `resolver`. Grants sind damit auditierbar und **bitemporal** (Zugriff galt von–bis).

### 13.2 Durchsetzen (Kernel — Reference Monitor / Row-Level Security)
Jeder Lesevorgang läuft durch **ein unumgehbares Tor** in der Engine:
1. **Sichtbarkeits-Bedingung** aus den Grants des Anfragenden bestimmen: `Daten sichtbar ⟺ einer seiner Scopes ∈ gewährte Scopes`.
2. Diese Bedingung **vor die Auflösung schieben** (Predicate Pushdown): Auflösung/Projektion/Identität laufen nur über die bereits-erlaubte Menge.

**Filter-before-resolve ist nicht optional.** Bei geteilten Klassen-Knoten (§11.1) mit Repräsentanten aus privaten Scopes würde „resolve-then-filter" privates Material in eine erlaubte Projektion einfließen lassen, bevor gefiltert wird → **Leak**. Daher werden Identitäts-Kanten ins Nicht-Sichtbare **gekappt, bevor** aufgelöst wird. Beispiel: Lisa (Scope `statistik`) fragt „Regression" → der private `bwl`-Repräsentant wird vor der Cluster-Auflösung entfernt; sie sieht das Konzept nur durch Statistik-Quellen gestützt.

- **Entzug** = neuer Grant-Kontext, der den alten per `ersetzt` überholt; künftige Reads filtern ihn weg, schon Gesehenes bleibt (Append-only).
- **Warum Kernel:** ein Reference Monitor muss *immer aufgerufen*, *manipulationssicher* und *minimal/prüfbar* sein — ein Profil (nur Daten + Config) kann kein unumgehbares Tor erzwingen.

**Kernel:** Tor, Predicate Pushdown, filter-before-resolve, Scope-Auswertung. **Profil:** Vokabular (Rollen, Recht-Arten, Scope-Schema).

---

## 14. Offene Probleme (verbleibend)

Die fünf konzeptionellen Risse aus arch3 §11.2 sind durch §11–§13 **modellseitig gelöst**. Offen bleiben **Implementierungs-/Betriebsfragen** (modellunabhängig):

- **ID-Schema** (Content-Hash/UUID/hybrid), **Abfragesprache**, **Serialisierungsformat** — TBD.
- **Konkrete Resolver- & Clustering-Algorithmen** (datengetrieben, modellunabhängig).
- **Compaction** (§11.4): wann darf verborgener/überholter Zustand *physisch* entfernt werden — operative Frage; kollidiert mit Hard-Delete-Anforderungen (z. B. DSGVO), die mit Append-only in Spannung stehen.
- **Indexierung/Performance** der Sichtbarkeits- und Cluster-Auswertung (Predicate Pushdown, Cluster-Materialisierung).

## 15. Zusammenfassung in einem Satz

lakearch besteht aus genau einer Entität — Daten —, die andere Daten als Kontext besitzen kann; Typ, Identität und Zeit sind besondere Kontexte; alles ist append-only; **Identitäts-Auflösung (Anker + graduierte, revidierbare, quellen-vertrauens-gewichtete, im Batch gepflegte Klassen), Materialisierung (invalidierbare Checkpoints) und Zugriff (unumgehbares filter-before-resolve-Tor) sind Kernel-Prozesse**, deren Politik (Schwellen, Vertrauensränge, Kadenzen, Rollen) in domänenspezifischen Profilen liegt, die sich vollständig in lakearchs Primitiven ausdrücken.
