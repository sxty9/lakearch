# lakearch — Architektur-Entwurf v3

Dieses Dokument beschreibt das semantische Datenmodell der lakearch. Es geht ausschließlich um die Architektur des Datenmodells, **nicht** um ihre technologische Umsetzung.

**arch3.md ersetzt arch2.md.** Es übernimmt den konsolidierten Kern von arch2 unverändert in der Substanz und ergänzt drei Dinge, die in der Designsession zu studiq entstanden sind:
1. die **Schichtenarchitektur** (Kernel / Profil / App) und damit die saubere Antwort, was es heißt, dass ein domänenspezifisches Modell „von lakearch erbt" (§8),
2. die **Governance-Regel**, die lakearch domänen-rein und wiederverwendbar hält (§9),
3. die **konzeptionellen offenen Probleme**, die die erste abgeleitete Domäne (studiq) am Modell sichtbar gemacht hat (§11.2).

---

## 1. Grundprinzip: Eine Entität

Die lakearch kennt nur **eine** fundamentale Entität: **„Daten"**.

Alles, was im System existiert, ist eine Instanz von Daten. Es gibt keine zweite Entitätsklasse — kein Schema, kein Typ-System, keine Metadaten-Schicht, keine Versions-Objekte, keine Zeit-Objekte. Diese radikale Reduktion ist das Kernprinzip; jede Ausnahme kostet konzeptionell überproportional viel und wird konsequent vermieden.

## 2. Kontext

**„Kontext"** ist keine eigene Entität, sondern eine *Rolle*, die eine Daten-Instanz einnimmt, wenn sie von einer anderen Daten-Instanz besessen wird.

- Daten A besitzt einen Kontext K. K ist selbst eine Daten-Instanz.
- Ein Verweis von A auf B wird ausgedrückt, indem A einen Kontext K besitzt, der den Verweis auf B trägt.
- Kontext ist also Daten *in einer bestimmten Beziehung* — nicht ein Wrapper *um* Daten.
- Besitz ist **gerichtet** (asymmetrisch), anders als das symmetrische RDF-Tripel.

Jede Aussage in lakearch ist damit ein Daten-Objekt, das von einem anderen Daten-Objekt besessen werden kann. **Reifikation ist kostenlos:** ein Kontext kann über einen bestehenden Kontext aussagen (Aussagen über Aussagen sind nativ).

## 3. Vollskalierbarkeit & Typ

Daten haben keine feste Struktur. Jede beliebige Struktur ist möglich, weil sie über **„Typ"** erschlossen wird.

- Typ ist ein besonderer Kontext. Da Kontext Daten ist, ist auch Typ nur eine Instanz von Daten.
- Es gibt **keinen Meta-Typ-Regress**: Typ-Aussagen sind gewöhnliche Daten und werden wie alle anderen Daten behandelt.

Diese Konstruktion erlaubt es, jede beliebige Domäne abzubilden, **ohne das Modell selbst zu erweitern**. (Dieser Satz ist der Dreh- und Angelpunkt für §8: eine Domäne *erweitert lakearch nicht*, sie *drückt sich in lakearch aus*.)

## 4. Identität

Identität ist in lakearch **keine intrinsische Eigenschaft von Daten, sondern eine Aussage über Daten — und damit selbst ein Kontext.**

### 4.1 Drei Ebenen
- **Physische Identität (Speicher-ID):** Jede je geschriebene Daten-Instanz bekommt eine systeminterne, opake ID — vorzugsweise einen Content-Hash. Reine Adressierung, kein semantisches Urteil.
- **Wert-Identität (Deduplizierung):** Bitgleiche Inhalte werden über Content-Addressing automatisch dedupliziert. Ein primitives Daten existiert genau einmal, egal wie oft referenziert.
- **Referenzielle Identität („ist das dasselbe Ding?"):** Ausschließlich über Kontexte ausgedrückt, niemals durch destruktive Operationen.

### 4.2 Identität ist gradierbar
Es gibt nicht *eine* `sameAs`-Relation, sondern eine Familie von Identitäts-Kontexten unterschiedlicher Stärke und Reichweite, z. B.:
`deckungsgleich` · `ergänzt` · `widerspricht_in` · `verwandt_mit` · `bekanntermaßen_verschieden`.
Jede dieser Aussagen ist selbst ein Daten-Objekt mit eigenen Kontexten: betroffene Attribute, Konfidenz, Resolver, Zeitpunkt.

### 4.3 Quellsystem-Wissen als Kontext am Quellsystem
Eigenheiten von Quellsystemen — stabile Schlüssel, bekannte Abweichungen, Vertrauensgrade — sind Kontexte am Daten-Objekt, das das Quellsystem repräsentiert. Resolver lesen diese Kontexte zur Laufzeit und justieren ihr Verhalten. Damit ist Resolver-Verhalten **datengetrieben und auditierbar**, nicht hartcodiert.

### 4.4 Drei Pfade der Aufnahme
- **Trivial-Pfad (Update):** Gleiche Quelle, stabiler Primärschlüssel, keine Konflikte. Neuer Zustand angelegt, alter als ersetzt markiert.
- **Korrelations-Pfad (probabilistisch):** Unterschiedliche Quellen / kein eindeutiger Schlüssel. Das Datum wird *immer* eigenständig angelegt; der Resolver erzeugt gradierte Identitäts-Kontexte mit Konfidenzen.
- **Konflikt-Pfad (explizit unklar):** Konfidenz reicht in keine Richtung oder es bestehen aktive Widersprüche. Wird als solcher modelliert; Auflösung verschiebt sich auf die Leseseite.

Welcher Pfad greift, entscheidet sich aus den Kontexten an Quellsystem und Daten — nicht aus hartcodiertem Code.

## 5. Zeit und Versionierung

- **Zeit ist Daten.** Zeitpunkte/Zeiträume sind Daten-Instanzen, Zeit-Aussagen besondere Kontexte.
- **Zwei Zeitachsen:** *Aufzeichnungszeit* (`aufgezeichnet_am` — wann das System es erfuhr) und *Gültigkeitszeit* (`gilt_von`, `gilt_bis` — wann der Sachverhalt in der Welt gilt). Sie dürfen auseinanderfallen; rückwirkende Korrekturen sind nativ.
- **Append-only.** Veränderungen fließen als neue Daten ein; `ersetzt` markiert Älteres als überholt, ohne es zu löschen. Physisches Überschreiben ist die Ausnahme.
- **Versionierung = Speicher vs. Lesen.** Auf der Speicherseite trägt jedes Daten Zeit- und `ersetzt`-Kontexte. Auf der Leseseite ist historische Rekonstruktion eine *Abfrage* unter Zeitfilter — sie erzeugt nichts Neues, sie *projiziert*. Eine „Version" ist eine Leseregel, kein gespeichertes Objekt.

## 6. Konsequenzen für die Leseseite

Da Identität gradierbar und Zeit zweidimensional ist, verschiebt sich Komplexität in die Abfrage-Schicht. Jede nicht-triviale Abfrage entscheidet implizit: Konfidenz-Schwelle für `deckungsgleich`? Gewichtung der Quellsysteme? Zeitpunkt auf welcher Achse? Mehrdeutigkeit wird **nicht beim Schreiben verborgen, sondern beim Lesen ehrlich behandelt**. Gleiche Frage an gleichen Bestand kann je nach Schwellwert/Zeit unterschiedliche Ergebnisse liefern — im Big-Data-Kontext eine Stärke.

## 7. Abgrenzung zu RDF

Geteilte Kernintuition: *eine Sorte Ding; Beziehungen sind selbst von dieser Sorte.* Unterschiede: **Besitz statt Tripel-Symmetrie**, **native Reifikation**, **native gradierte Identität**, **native Bitemporalität**, **keine Literal/Resource-Unterscheidung**. Konzeptionell näher an Datomic/XTDB als an RDF.

---

## 8. NEU — Schichtenarchitektur: Kernel, Profil, App

lakearch ist als **wiederverwendbares Substrat für beliebig viele domänenspezifische Modelle** gedacht (studiq ist das erste, weitere folgen). Daraus ergeben sich drei klar getrennte Schichten:

### 8.1 lakearch = Kernel/Engine
Die Laufzeit, die die §1–§7-Semantik implementiert: Content-Addressing & Dedup, Kontext-Besitz, Identitäts-Resolver-Mechanik, gradierte Auflösung, bitemporales Lesen/Projektion. **Domänen-rein.** Einmal implementiert, von jedem Domänenprojekt wiederverwendbar. Der Kernel weiß nichts von „Konzept", „Kunde" o. Ä.

### 8.2 Profil = abgeleitetes Domänenmodell — *als Daten*
Ein Profil (z. B. `studiqarch`, später `crmarch`, …) ist **kein Code-Subtyp** und **erweitert das Modell nicht**. Weil Typ in lakearch nur ein Kontext (= Daten) ist, **lebt ein Profil als Daten in einem lakearch-Store**. Es besteht aus:
- **Vokabular** (Typ-Daten und Relations-Daten der Domäne),
- **Konventionen** (welche Identitäts-Grade, welche Aufnahme-Pfade die Domäne nutzt),
- **Config** (Resolver-Schwellen, Projektions-/Sichten-Definitionen),
- ggf. **registrierten Erweiterungen** an den Kernel-Erweiterungspunkten (eigene Resolver-/Projektions-Implementierungen).

**„studiqarch erbt von lakearch"** bedeutet präzise: *vollständig in lakearchs Primitiven ausgedrückt und auf lakearchs Engine lauffähig* — nicht „fügt dem Modell Felder/Entitäten hinzu".

### 8.3 App
Die Anwendung (z. B. studiq) liest/schreibt über den Kernel unter Nutzung ihres Profils. Sie hält die UX und die menschlichen Interaktionen; ihre „einfache" Sicht ist eine materialisierte Lese-Projektion über dem komplexen Store (Komplexität im Store, Simplizität in der Sicht).

## 9. NEU — Governance-Regel (Kernel-Reinheit)

Jeder Wunsch „die Domäne braucht X" wird an genau einer Frage entschieden:

> **Vokabular → Profil. Primitiv → Kernel.**
> - Neuer **Typ / Relation / Identitäts-Grad / Projektion** → **Profil** (Daten/Config, domänen-lokal, billig).
> - Neues **Primitiv** (etwas, das die *Engine nativ verstehen* muss) → **Kernel-Änderung**, muss **domänen-agnostisch** gerechtfertigt sein und kommt *allen* abgeleiteten Profilen zugute.

Lern-, CRM- oder sonstige Domänenspezifika landen damit nie im Kernel. Beispiel-Diskriminierung aus der studiq-Session: *bitemporales Lesen = Kernel, Vergessenskurve = Profil; Such-Index = Kernel, Match-Schwelle = Profil.*

Der Kernel stellt **Erweiterungspunkte** bereit (registrierbare Resolver- und Projektions-Strategien); Profile bestücken sie. Das ist die kontrollierte Naht zwischen den Schichten.

## 10. NEU — Methodik: Kernel zuerst, Domäne als Schleifstein

Weil der Kernel viele Domänen tragen soll, wird seine Semantik **zuerst** verfeinert und rein gehalten. Aber ein rein abstrakt polierter Kernel bekommt die falschen Gelenke. Daher: **die erste Domäne (studiq) ist der Schleifstein, nicht die Form.** Der Kernel wird am echten Druck eines vertikalen Dünnschnitts (eine reale Lernszene end-to-end) geschärft — was geschärft wird, bleibt allgemein. An jeder Reibungsstelle entscheidet die Governance-Regel (§9).

---

## 11. Offene Probleme

### 11.1 Implementierungsfragen (modellunabhängig, TBD)
- **Konkretes ID-Schema:** Content-Hash, UUID oder hybrid.
- **Abfragesprache:** noch offen.
- **Serialisierungsformat:** noch offen.
- **Konkrete Resolver-Strategien:** datengetrieben, daher modellunabhängig.
- **Compaction:** wann darf historischer Zustand physisch entfernt werden — operative Frage.

### 11.2 Konzeptionelle Lücken, sichtbar gemacht durch die erste Domäne (studiq) — „Schleifstein-Agenda"
Diese fünf „Risse" liegen *nicht* am Schnitt Kernel↔Profil (der hält), sondern im resultierenden Wissen selbst und an der Naht Schreiben↔Lesen. **Lösungsansätze sind in Arbeit (vom Nutzer); studiq treibt die Auflösung.** Kernel-gewurzelte Formulierung:

- **R1 — Anker/Repräsentant referenzieller Identität.** „Das Ding" (z. B. ein Konzept) ist in lakearch kein Daten, sondern ein *Lese-Cluster* aus Identitäts-Kontexten. Apps brauchen aber stabile Griffe, an die sie anderes hängen. Braucht der Kernel/das Profil einen Repräsentanten- bzw. Anker-Begriff? Verhalten bei Merge/Un-Merge?
- **R2 — Materialisierung & Aktualität von Projektionen.** Append-only + „alles wird beim Lesen berechnet" ist für hochfrequente, große Projektionen teuer. Dürfen materialisierte Projektionen selbst als (per `ersetzt` überholbare) Daten im Store liegen? Cache-Invalidierungs-Semantik?
- **R3 — Resolver-Vorrang/Autorität.** Mehrere Resolver (Mensch vs. Maschine vs. neuere Maschine) treffen widersprüchliche Identitäts-Urteile. Es fehlt eine definierte **Präzedenz-Ordnung** (insb. „menschliche Korrektur haftet"). Config-im-Profil oder Kernel-Primitiv?
- **R4 — Mandanten/Sichtbarkeit/Zugriff.** lakearch ist *ein* logischer, append-only Graph; Zugriffsgrenzen (wer darf was sehen/schreiben) kommen nicht vor. Multi-User-Domänen brauchen sie. Ist „darf sehen" auch nur ein Kontext — oder Engine-Sache? (Domänen-agnostisch → Kernel-Kandidat.)
- **R5 — Kuratierung unter Append-only.** Graphen sammeln Rauschen (Halb-Dubletten, tote Knoten); gelöscht wird nichts. „Aufräumen" = Lese-Filter + „Verbergen"-Kontexte. Mechanik vermutlich Kernel, Policy Profil.

## 12. Zusammenfassung in einem Satz

lakearch besteht aus genau einer Entität — Daten — die andere Daten als Kontext besitzen kann; Typ, Identität und Zeit sind besondere Kontexte; alles ist append-only; Versionierung, Identitätsauflösung und historische Rekonstruktion sind Lese-Operationen über denselben Speicher — und domänenspezifische Modelle *erben*, indem sie sich als Profil-Daten vollständig in diesen Primitiven ausdrücken, auf einem domänen-reinen Kernel, der nach der Regel „Vokabular ins Profil, Primitiv in den Kernel" wächst.
