# lakearch — Das Datenmodell

> Regelwerk. Vollständig, domänen-frei, technologie-frei.

**Präambel.** Dieses Dokument beschreibt das Datenmodell *lakearch* erschöpfend und allgemein. Es nennt keine Domäne, keine Anwendung, keine Technologie. Es ist als Axiomensystem gefasst: wenige Grundbegriffe, daraus eindeutig folgende Regeln. Jede Regel gilt ausnahmslos; wo eine Ausnahme nötig schiene, ist die Regel falsch gefasst.

**Notation.** *A, B, K* bezeichnen beliebige Daten. „A ⊳ K" liest sich „A besitzt den Kontext K". Beispiele sind rein abstrakt; lakearch kennt keine Inhalte.

---

## §1 Geltungsbereich

1.1 lakearch **speichert** Daten und ihre Kontexte.
1.2 lakearch **traversiert** entlang von Kontexten — vorwärts wie rückwärts.
1.3 lakearch **matcht strukturell**: Gleichheit auf Inhalts-/Adressebene, „zeigt ein Kontext auf ein Daten?", Zugehörigkeit zu einer per Kontext gegebenen Menge.
1.4 lakearch **rechnet nicht** (keine Arithmetik, Ordnung, Aggregation), **wertet nicht** (erzeugt keine Konfidenz, entscheidet keine Identität, validiert keine Eingabe) und **sortiert nicht**.
1.5 Alles Rechnen, Werten und Sortieren liegt in einer **Schicht über lakearch**. Sie liest per Traversierung und schreibt ihre Ergebnisse als Daten zurück.

## §2 Die Entität

2.1 Es gibt genau **eine** Art von Entität: das **Daten**. Alles, was existiert, ist ein Daten.
2.2 Es gibt keine zweite Entitätsklasse — kein Schema, keine Metadaten-, Versions-, Zeit- oder Typ-Objekte als eigene Art. Diese Reduktion ist das Kernprinzip.

## §3 Der Kontext

3.1 Ein **Kontext** ist keine eigene Entität, sondern eine **Rolle**: ein Daten K, das von einem Daten A besessen wird. K selbst ist ein gewöhnliches Daten.
3.2 Besitz ist **gerichtet**: „A ⊳ K" ist nicht symmetrisch.
3.3 Ein **Verweis** von A auf B wird ausgedrückt, indem A einen Kontext besitzt, der auf B zielt. Die Art des Verweises (die Relation) ist selbst ein Daten.
3.4 Ein Kontext kann selbst Kontexte besitzen. **Reifikation ist kostenlos**: Aussagen über Aussagen sind nativ.
3.5 Jede Aussage des Systems ist ein Daten, das von einem Daten besessen wird. Eine andere Form von Aussage existiert nicht.

## §4 Typ

4.1 **Typ** ist ein besonderer Kontext: ein Daten trägt seinen Typ als Kontext, der auf ein Typ-Daten zeigt.
4.2 Da ein Typ ein Daten ist, gibt es **keinen Meta-Typ-Regress**; Typ-Aussagen sind gewöhnliche Daten.
4.3 Daten haben keine vorgeschriebene Struktur. Struktur entsteht allein durch Kontexte. Jede Domäne ist abbildbar, **ohne das Modell zu erweitern**.

## §5 Identität

5.1 Identität ist **keine intrinsische Eigenschaft**, sondern eine Aussage über Daten — und damit selbst ein Kontext.
5.2 **Speicher-Identität:** Jedes je geschriebene Daten trägt eine opake ID, vorzugsweise einen **Inhalts-Hash**. Sie adressiert; sie urteilt nicht.
5.3 **Wert-Identität:** Inhaltsgleiche Daten sind dasselbe Daten — Inhaltsadressierung dedupliziert automatisch. Ein primitives Daten existiert genau einmal.
5.4 **Referenzielle Identität** („dasselbe Ding?") wird ausschließlich über Kontexte ausgedrückt, niemals durch destruktive Operationen.
5.5 Referenzielle Identität ist **gradiert**: eine Familie von Identitäts-Kontexten unterschiedlicher Stärke (z. B. *deckungsgleich, ergänzt, widerspricht-in, verwandt-mit, bekannt-verschieden*). Jeder trägt eigene Kontexte: betroffene Attribute, Konfidenz, Urheber, Zeit.
5.6 Eigenschaften einer Quelle (stabile Schlüssel, bekannte Abweichungen, Vertrauensgrad) sind Kontexte an dem Daten, das die Quelle repräsentiert.
5.7 Die Aufnahme eines Daten folgt genau einem von drei Pfaden, bestimmt allein aus Kontexten:
&nbsp;&nbsp;(a) **Fortschreibung** — gleiche Quelle, stabiler Schlüssel, kein Widerspruch: neuer Zustand, der alte wird als ersetzt markiert.
&nbsp;&nbsp;(b) **Korrelation** — andere Quelle oder kein eindeutiger Schlüssel: immer eigenständiges Daten, zuzüglich gradierter Identitäts-Kontexte.
&nbsp;&nbsp;(c) **Konflikt** — keine Richtung trägt oder es bestehen aktive Widersprüche: als solcher modelliert; Auflösung auf die Leseseite verschoben (§7).

## §6 Zeit

6.1 Zeit ist Daten. Zeitpunkte und Zeiträume sind Daten; Zeit-Aussagen sind besondere Kontexte.
6.2 Es gibt **zwei Zeitachsen**: **Aufzeichnungszeit** (wann das System es erfuhr) und **Gültigkeitszeit** (wann der Sachverhalt in der Welt gilt). Sie dürfen auseinanderfallen.
6.3 Das Modell ist **append-only**: neues Wissen kommt als neue Daten hinzu. Ein **Ersetzungs-Kontext** markiert Älteres als überholt, ohne es zu löschen.
6.4 Eine „Version" ist nichts Gespeichertes, sondern eine **Leseregel** (§7).

## §7 Auflösung beim Lesen

7.1 Was gradierte Identität (§5), Zeit (§6) und Konflikte bedeuten, wird **beim Lesen** entschieden, nicht beim Schreiben.
7.2 Eine Abfrage wählt implizit: Konfidenz-Schwellen, Quell-Gewichtung, Zeitpunkt und Zeitachse.
7.3 Dieselbe Frage an denselben Bestand kann je nach Wahl verschiedene Ergebnisse liefern. Mehrdeutigkeit wird beim Lesen ehrlich behandelt, nicht beim Schreiben verborgen.
7.4 Lesen erzeugt nichts im Speicher; es **projiziert** aus dem vorhandenen Bestand. Historische Zustände werden so rekonstruiert.

## §8 Strukturen der Identitäts-Auflösung

*lakearch hält die Strukturen; das Auflösen selbst (Schwellen, Entscheidungen) geschieht in der Schicht darüber (§1.5).*

8.1 **Repräsentantensystem:** Tragen mehrere Daten dieselbe referenzielle Identität, existiert ein eigenes **Anker-Daten** (die Klasse). Die Repräsentanten verweisen per Mitgliedschafts-Kontext auf den Anker.
8.2 Anderes verweist auf den **Anker**, nicht auf einen einzelnen Repräsentanten. Ein Repräsentant wird **niemals** in den Anker umgewandelt (§6.3).
8.3 Mitgliedschaft ist **gradiert und revidierbar** — ein Kontext, kein destruktiver Zusammenschluss.
8.4 Ein **Split** entsteht durch neue Kontexte, die alte ersetzen; betroffene Repräsentanten werden re-verwiesen.
8.5 **Kuratierung** fügt ausschließlich reversible Kontexte hinzu (*verbergen, ersetzen, Mitgliedschaft*); die Leseseite filtert sie. Es wird nie gelöscht; physisches Entfernen ist Compaction (§13).

## §9 Materialisierung

9.1 Ein berechnetes Ergebnis darf als Daten gespeichert werden; ein neueres ersetzt das ältere (§6.3).
9.2 Ein berechnetes Daten trägt seine **Herkunft als Kontext** — die Bindung an die Eingaben, aus denen es entstand.
9.3 Ändert sich eine Eingabe (auch rückwirkend, §6), werden die betroffenen Ergebnisse durch **Rückwärts-Traversierung** der Herkunfts-Kontexte gefunden (Invalidierung). Das Neu-Berechnen liegt außerhalb (§1.5).

## §10 Zugriff

10.1 **Beschreibung.** Ein **Bereich** ist ein Daten; Zugehörigkeit ist ein Kontext (ein Daten kann mehreren Bereichen angehören). Eine **Berechtigung** ist ein Daten mit Kontexten *Subjekt, Bereich, Recht, Zeit, Urheber* — auditierbar und bitemporal.
10.2 **Durchsetzung.** Jeder Lesevorgang passiert ein **unumgehbares Tor**. Das Tor bildet die Sichtbarkeit aus den Berechtigungen (reines strukturelles Matching: *Bereich ∈ gewährte Bereiche*, §1.3) und wendet sie **vor jeder Auflösung** an.
10.3 **Filtern vor Auflösen** ist zwingend: nicht-sichtbare Daten werden entfernt, bevor referenzielle Identität (§8) aufgelöst wird — damit nichts Nicht-Sichtbares in ein erlaubtes Ergebnis einfließt.
10.4 **Entzug** ist ein neuer Berechtigungs-Kontext, der den alten ersetzt; künftige Lesevorgänge filtern ihn, bereits Gelesenes bleibt (§6.3).
10.5 Das Tor ist Teil von lakearch — *immer aufgerufen, manipulationssicher, minimal*. Es matcht nur (§1.3); es rechnet nicht.

## §11 Föderation

11.1 Ein einzelner Bestand **und** mehrere verbundene Bestände sind beides möglich — mit denselben Regeln.
11.2 **Innerhalb eines Bestands** trennen Bereiche (§10) logisch.
11.3 **Über Bestände hinweg** tragen inhaltsgleiche Daten denselben Inhalts-Hash (§5.2) und sind damit bestand-übergreifend identisch — automatischer Abgleich. Referenzielle Identität wird über den Korrelations-Pfad (§5.7 b) verbunden; einen Bestand in einen anderen aufzunehmen *ist* dieser Pfad.
11.4 Inhalts-IDs sind bestand-unabhängig; **Anker-IDs (§8.1) sind bestand-lokal** und werden beim Zusammenführen über gradierte Identität versöhnt.

## §12 Atomarität

12.1 Ein Umbau, der mehrere Daten betrifft (Zusammenführen/Spalten §8, Berechtigungs-Wechsel §10), wird **gemeinsam sichtbar** durch ein einziges abschließendes **Aktiv-Schreiben**.
12.2 Bis der Aktiv-Marker gesetzt ist, gelten die Teile als inaktiv; Traversierung ignoriert sie.
12.3 Ein halb-vollzogener Umbau ist damit unsichtbar, bis er vollständig ist — Atomarität ohne Transaktions-Maschinerie.

## §13 Ableitung & Trennung

13.1 Eine **domänenspezifische Ableitung** erweitert das Modell nicht. Sie ist Daten *innerhalb* eines lakearch-Bestands: Vokabular (Typ- und Relations-Daten), Konventionen, Konfiguration.
13.2 **Trennungsregel.** Vokabular gehört in die Ableitung. Ein neues Speicher-, Traversier- oder Match-Primitiv gehört in lakearch und muss domänen-frei sein. Rechnen, Werten und Sortieren gehört in die Schicht darüber (§1).
13.3 lakearch kennt **keine** Ableitung namentlich. Es stellt nur Primitive bereit, in denen sich jede Ableitung vollständig ausdrückt.

## §14 Bewusst offen (Implementierung & Betrieb)

Diese Punkte sind kein Modell-Bestandteil, sondern Umsetzungs-Entscheidungen:
- **ID-Schema** (Inhalts-Hash / UUID / hybrid), **Serialisierung**, **Abfrage- und Traversier-Sprache**.
- **Compaction:** wann Überholtes oder Verborgenes *physisch* entfernt werden darf (Spannung Append-only ↔ Lösch-Pflichten).
- **Indexierung & Leistung** von Bereichs-Filter, Anker-Auflösung, Herkunfts-Rückwärts-Traversierung.
- **Nebenläufigkeit** über das Aktiv-Marker-Muster (§12) hinaus.

---

## Anhang A — Abgrenzung zu RDF

Geteilte Intuition: es gibt nur eine Sorte Ding, und Beziehungen sind selbst von dieser Sorte. Unterschiede: **Besitz statt Tripel-Symmetrie** (§3.2); **native Reifikation** (§3.4); **native gradierte Identität** als Repräsentation (§5.5); **native Bitemporalität** (§6.2); **keine Literal/Resource-Unterscheidung** — alles ist Daten (§2.1). Konzeptionell näher an append-only, bitemporalen Modellen (Datomic/XTDB) als an RDF.

## Anhang B — Wesen in einem Satz

lakearch ist ein append-only Substrat aus genau einer Entität — Daten, die andere Daten als Kontext besitzen —, das **speichert, traversiert und strukturell matcht** (Typ, Identität und Zeit sind besondere Kontexte; Identität ist gradiert, bitemporal und über Inhalts-Hash föderierbar; Anker, Materialisierung und ein unumgehbares Zugriffs-Tor sind native Strukturen; Atomarität entsteht durch einen Aktiv-Marker), während **Rechnen, Werten und Sortieren bewusst außerhalb** liegen.
