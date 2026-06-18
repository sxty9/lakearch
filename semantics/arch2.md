# lakearch — Architektur-Entwurf v2

Dieses Dokument beschreibt das semantische Datenmodell der lakearch. Es geht ausschließlich um die Architektur des Datenmodells, nicht um ihre technologische Umsetzung. arch2.md ersetzt arch1.md und fasst die bisherigen Designentscheidungen konsolidiert zusammen.

## 1. Grundprinzip: Eine Entität

Die lakearch kennt nur **eine** fundamentale Entität: **"Daten"**.

Alles, was im System existiert, ist eine Instanz von Daten. Es gibt keine zweite Entitätsklasse — kein Schema, kein Typ-System, keine Metadaten-Schicht, keine Versions-Objekte, keine Zeit-Objekte. Diese radikale Reduktion ist das Kernprinzip der Architektur; jede Ausnahme davon kostet konzeptionell überproportional viel und wird daher konsequent vermieden.

## 2. Kontext

**"Kontext"** ist keine eigene Entität, sondern eine *Rolle*, die eine Daten-Instanz einnimmt, wenn sie von einer anderen Daten-Instanz besessen wird.

- Daten A besitzt einen Kontext K. K ist selbst eine Daten-Instanz.
- Ein Verweis von Daten A auf Daten B wird ausgedrückt, indem A einen Kontext K besitzt, der den Verweis auf B trägt.
- Kontext ist also Daten *in einer bestimmten Beziehung* — nicht ein Wrapper *um* Daten.

Damit ist jede Aussage in lakearch ein Daten-Objekt, das von einem anderen Daten-Objekt besessen werden kann. Aussagen über Aussagen sind nativ möglich: ein weiterer Kontext kann über einen bestehenden Kontext aussagen (Reifikation ist kostenlos).

## 3. Vollskalierbarkeit

Daten haben keine feste Struktur. Jede beliebige Struktur ist möglich, weil sie über **"Typ"** erschlossen wird.

- Typ ist ein besonderer Kontext.
- Da Kontext Daten ist, ist auch Typ nur eine Instanz von Daten.
- Es gibt keinen Meta-Typ-Regress: Typ-Aussagen sind gewöhnliche Daten und werden wie alle anderen Daten behandelt.

Diese Konstruktion erlaubt es, jede beliebige Domäne abzubilden, ohne das Modell selbst zu erweitern.

## 4. Identität

Identität ist in lakearch **keine intrinsische Eigenschaft von Daten, sondern eine Aussage über Daten — und damit selbst ein Kontext.**

### 4.1 Drei Ebenen

**Physische Identität (Speicher-ID):** Jede Daten-Instanz, die je geschrieben wird, bekommt eine systeminterne, opake ID — vorzugsweise einen Content-Hash. Diese ID ist kein semantisches Urteil, sondern nur Adressierung.

**Wert-Identität (Deduplizierung):** Bitgleiche Inhalte werden über Content-Addressing automatisch dedupliziert. Ein primitives Daten existiert genau einmal im System, egal wie oft es referenziert wird.

**Referenzielle Identität ("ist das dasselbe Ding?"):** Wird ausschließlich über Kontexte ausgedrückt. Niemals durch destruktive Operationen.

### 4.2 Identität ist gradierbar

Es gibt nicht *eine* `sameAs`-Relation, sondern eine Familie von Identitäts-Kontexten mit unterschiedlicher Stärke und unterschiedlichem Geltungsbereich. Beispiele:

- `deckungsgleich` — strenge Identität, keine Konflikte
- `ergänzt` — Aussage über dasselbe Ding, ohne Widerspruch
- `widerspricht_in` — Widerspruch in benannten Attributen
- `verwandt_mit` — wahrscheinlich derselbe Bezug, Konfidenz unter Schwellwert
- `bekanntermaßen_verschieden` — explizit getrennt gehaltene Entitäten

Jede dieser Aussagen ist selbst ein Daten-Objekt mit eigenen Kontexten: betroffene Attribute, Konfidenz, Resolver, Zeitpunkt.

### 4.3 Quellsystem-Wissen als Kontext am Quellsystem

Eigenheiten von Quellsystemen — stabile Schlüssel, bekannte semantische Abweichungen zu anderen Quellen, Vertrauensgrade — sind Kontexte am Daten-Objekt, das das Quellsystem repräsentiert. Resolver lesen diese Kontexte zur Laufzeit und justieren ihr Verhalten entsprechend.

Damit wird Resolver-Verhalten datengetrieben und auditierbar, statt hartcodiert.

### 4.4 Drei Pfade der Aufnahme

**Trivial-Pfad (Update):** Gleiche Quelle, stabiler Primärschlüssel laut Quellsystem-Kontext, keine konfligierenden Attribute. Neuer Zustand wird angelegt, alter wird als ersetzt markiert.

**Korrelations-Pfad (probabilistisch):** Unterschiedliche Quellen oder kein eindeutiger Schlüssel. Das Datum wird *immer* als eigenständiges Daten angelegt. Der Resolver erzeugt gradierte Identitäts-Kontexte mit Konfidenzen.

**Konflikt-Pfad (explizit unklar):** Konfidenz reicht in keine Richtung, oder aktive Widersprüche bestehen. Wird als solcher modelliert; die Auflösung verschiebt sich auf die Leseseite.

Welcher Pfad greift, entscheidet sich aus den Kontexten am Quellsystem und an den Daten — nicht aus hartcodiertem Code.

## 5. Zeit und Versionierung

### 5.1 Zeit ist Daten

Zeit ist keine zweite Entität. Zeitpunkte und Zeiträume sind Daten-Instanzen, und Zeit-Aussagen sind besondere Kontexte — genau wie Typ ein besonderer Kontext ist.

### 5.2 Zwei Zeitachsen

lakearch unterscheidet zwei semantisch verschiedene Zeit-Kontexte:

**Aufzeichnungszeit (`aufgezeichnet_am`):** Wann hat das System diese Information erfahren?

**Gültigkeitszeit (`gilt_von`, `gilt_bis`):** Wann gilt der ausgesagte Sachverhalt in der Welt?

Die beiden können auseinanderfallen. Rückwirkende Korrekturen ("seit gestern wissen wir, dass X schon 2023 galt") sind damit nativ ausdrückbar.

### 5.3 Append-only

Veränderungen in der Außenwelt fließen als neue Daten ein, ohne vorheriges Wissen zu verwerfen. Der Beziehungs-Kontext `ersetzt` markiert ältere Daten als überholt, ohne sie zu löschen. Default ist append-only; physisches Überschreiben ist eine Ausnahme, kein Normalfall.

### 5.4 Versionierung: Speicher vs. Lesen

Versionierung in lakearch besteht aus zwei strikt zu trennenden Teilen:

**Auf der Speicherseite:** Jedes Daten kann Zeit-Kontexte tragen (`aufgezeichnet_am`, `gilt_von`, `gilt_bis`) sowie den Beziehungs-Kontext `ersetzt`. All das sind gewöhnliche Daten und Kontexte — Zeit-Kontexte sind besondere Instanzen von Kontext, mit zeitlicher Semantik, aber ohne Sonderstatus im Modell.

**Auf der Leseseite:** Eine historische Rekonstruktion ist eine Abfrage-Operation, die den Graphen unter einem Zeitfilter durchläuft. Sie erzeugt nichts Neues im Speicher, sie *projiziert* aus dem vorhandenen Bestand. Aus demselben Bestand lassen sich beliebig viele historische Zustände rekonstruieren.

Eine "Version" ist damit nichts Gespeichertes, sondern eine Leseregel. Die Vergangenheit wird aus demselben Speicher rekonstruierbar.

## 6. Konsequenzen für die Leseseite

Da Identität gradierbar und Zeit zweidimensional ist, verschiebt sich erhebliche Komplexität in die Abfrage-Schicht. Jede nicht-triviale Abfrage entscheidet implizit:

- Welche Konfidenz-Schwelle für `deckungsgleich`-Kontexte gilt?
- Welche Quellsysteme werden wie gewichtet?
- Welcher Zeitpunkt auf welcher Zeitachse wird betrachtet?

Das ist eine bewusste Designentscheidung: Mehrdeutigkeit wird nicht beim Schreiben verborgen, sondern beim Lesen ehrlich behandelt. Gleiche Frage an gleichen Datenbestand kann zu unterschiedlichen Ergebnissen führen — je nach Schwellwertwahl und Zeitperspektive. Im Big-Data-Kontext ist das eine Stärke, keine Schwäche.

## 7. Abgrenzung zu RDF

lakearch teilt mit RDF die Kernintuition: *Es gibt nur eine Sorte Ding, und Beziehungen zwischen Dingen sind selbst von dieser Sorte.* Typisierung und Selbstbeschreibung funktionieren analog.

Unterschiede:

- **Besitz statt Tripel-Symmetrie:** lakearch-Kontext gehört einem Daten-Objekt. RDF-Tripel sind symmetrisch.
- **Native Reifikation:** Aussagen über Aussagen sind in lakearch trivial; in RDF nur über Reifikation oder RDF-star.
- **Native gradierte Identität:** RDF kennt `owl:sameAs` als binäre Aussage; lakearch hat ein Spektrum eingebaut.
- **Native Bitemporalität:** RDF braucht externe Konventionen für Zeit; lakearch trennt Aufzeichnungs- und Gültigkeitszeit explizit.
- **Keine Literale (vermutlich):** lakearch macht keine Unterscheidung zwischen Resource und Literal — alles ist Daten.

RDF bringt ein reifes Ökosystem (SPARQL, RDFS, OWL, Triple-Stores). lakearch ist konzeptionell näher an Datomic/XTDB als an RDF: append-only, bitemporal, Identität als Aussage.

## 8. Was bewusst offen bleibt

- **Konkretes ID-Schema:** Content-Hash, UUID oder hybrid — Implementierungsentscheidung.
- **Abfragesprache:** noch offen.
- **Serialisierungsformat:** noch offen.
- **Konkrete Resolver-Strategien:** datengetrieben, daher modellunabhängig.
- **Compaction-Strategien:** wann darf historischer Zustand wirklich physisch entfernt werden — operative Frage, kein Modellaspekt.

## 9. Zusammenfassung in einem Satz

lakearch besteht aus genau einer Entität — Daten — die andere Daten als Kontext besitzen kann; Typ, Identität und Zeit sind besondere Kontexte; alles ist append-only; Versionierung, Identitätsauflösung und historische Rekonstruktion sind Lese-Operationen über denselben Speicher.
