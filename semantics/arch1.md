Die lakearch etabliert ein minimalistischen Datenmodell, welches mit einer minimalen Anzahl von Entitäten jede beliebige Domäne abbilden soll.

Dabei werden zwei Arten von Entitäten betrachtet:
1. "Daten"
2. "Kontext"

Dabei ist "Kontext" lediglich ein Wrapper von "Daten". Daher ist streng genommen "Daten" die einzige Entität.

Direktionalität:
Eine Instanz von "Daten" besitzt verweist auf beliebig viele Instanzen von "Kontext". Ein weiteres "Daten" kann von dem Quell-"Daten" mittels "Kontext" verwiesen werden.

Typisierung:
"Typ" wird mithilfe von "Daten" abgebildet.
Dabei kann ein "Daten" ein "Kontext" haben, der den "Typ" semantisch abbildet. "Typ" ist also nur eine Instanz von "Kontext"