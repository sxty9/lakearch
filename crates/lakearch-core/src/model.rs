//! Das abstrakte Daten-Modell (was kanonisiert und gehasht wird).
//!
//! Maßgeblich: `semantics/canonical-encoding.md` §K2 und das Gesetzbuch
//! `semantics/lakearch.md` §2–§5. Es gibt genau **eine** Entität: das Daten
//! (§2.1). Struktur entsteht **allein durch Kontexte** (§4.3); es gibt **keine
//! zweite Entitätsklasse** (§2.2) und **kein** privilegiertes „Inhalts"-Feld
//! neben den Kontexten.
//!
//! Ein Daten hat für die Zwecke der Kanonik genau **zwei** mögliche Klassen
//! (§K2.1):
//!
//! - **Blatt (atomar):** eine opake atomare Nutzlast (`payload`), **keine**
//!   besessenen Kontexte. Dedupliziert auf seinen atomaren Bytes allein
//!   (§5.3 „ein primitives Daten existiert genau einmal").
//! - **Knoten (besitzend):** **keine** atomare Nutzlast, eine nicht-leere,
//!   **sortiert-deduplizierte Menge** der `ContentId`s seiner besessenen
//!   Kontexte (§3.1/§K2.3). Identität entsteht vollständig aus dieser Menge
//!   (§4.3).
//!
//! Die gemischte Klasse (payload **und** owns) und das „leere Nichts" (weder
//! payload noch owns) sind **wohlgeformtheits-fehlerhaft** (§K2.1) und werden
//! durch die Konstruktoren dieses Moduls schon im Typ verhindert.
//!
//! Ein **Kontext** ist keine eigene Entität, sondern die **Rolle** eines
//! besessenen Daten (§3.1). Er wird daher **nicht** als separater adressierbarer
//! Typ modelliert; in der `owns`-Menge erscheint Besitz **ausschließlich** als
//! die `ContentId` des besessenen Daten (§K2.2). Die Kante `A ⊳ K` bekommt
//! **keine** eigene `ContentId` und existiert physisch nur als später
//! abgeleiteter Index-Eintrag.

use crate::id::ContentId;

/// Ein Daten (§2.1) — die einzige Entität. Entweder ein atomares Blatt oder ein
/// besitzender Knoten; nie beides, nie keines (§K2.1).
///
/// Floats sind im v1-Modell **modell-weit verboten** (§K3.4); deshalb gibt es
/// hier keinen Float-Bestandteil. Atomare Nutzlast ist stets ein **opaker
/// Byte-String** (§K3.7) — lakearch interpretiert ihn nicht (§1.4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Datum {
    inner: DatumKind,
}

/// Die zwei wohlgeformten Klassen eines Daten (§K2.1). Privat, damit die
/// Invarianten (Sortierung/Deduplizierung der `owns`-Menge, Nicht-Leere des
/// Knotens, Ausschluss der gemischten Klasse) **ausschließlich** über die
/// Konstruktoren hergestellt werden können.
#[derive(Clone, PartialEq, Eq, Debug)]
enum DatumKind {
    /// Primitives Blatt: opake atomare Nutzlast, keine Kontexte (§K2.1).
    Leaf { payload: Vec<u8> },
    /// Besitzender Knoten: nicht-leere, aufsteigend sortierte, deduplizierte
    /// Menge der `ContentId`s der besessenen Kontexte (§K2.3). Die Invariante
    /// „sortiert + dedupliziert + nicht leer" gilt für jeden konstruierbaren
    /// Wert.
    Node { owns: Vec<ContentId> },
}

impl Datum {
    /// Erzeugt ein **atomares Blatt** aus opaken Bytes (§K2.1). Ein leeres Blatt
    /// (`payload = []`) ist wohlgeformt und von „kein payload" (= Knoten)
    /// verschieden (§K3.5).
    pub fn leaf(payload: impl Into<Vec<u8>>) -> Self {
        Datum {
            inner: DatumKind::Leaf {
                payload: payload.into(),
            },
        }
    }

    /// Erzeugt einen **besitzenden Knoten** aus einer beliebig sortierten,
    /// möglicherweise Duplikate enthaltenden Sammlung besessener Kontext-IDs.
    ///
    /// Der Konstruktor stellt die kanonische Invariante her (§K2.3): die IDs
    /// werden **aufsteigend in 32-Byte-lexikographischer Reihenfolge** sortiert
    /// und **dedupliziert**. Die Einfüge-Reihenfolge und Vielfachheit haben
    /// damit **keine** Bedeutung — zwei Knoten mit derselben Kontext-Menge
    /// tragen dieselbe `ContentId` (§5.3-Erhalt).
    ///
    /// Gibt `None` zurück, wenn nach der Deduplizierung **keine** Kontext-ID
    /// übrig bleibt: ein Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1) —
    /// das wäre entweder ein Blatt oder gar kein Daten. (Der Kernel **validiert**
    /// keine fachliche Eingabe, §1.4; dies ist allein die mechanische Wahrung
    /// der Konstruktions-Invariante, nicht eine inhaltliche Wertung.)
    pub fn node(owned_contexts: impl IntoIterator<Item = ContentId>) -> Option<Self> {
        let mut owns: Vec<ContentId> = owned_contexts.into_iter().collect();
        // Sortierung ist rein adressbasiert (32-Byte-Order), kein Wert-Sort
        // (§1.4/§5.2): sie ordnet Adressen, nicht Werte, und ist
        // föderationsstabil.
        owns.sort_unstable();
        owns.dedup();
        if owns.is_empty() {
            return None;
        }
        Some(Datum {
            inner: DatumKind::Node { owns },
        })
    }

    /// Die atomare Nutzlast, falls dies ein Blatt ist (§K2.1).
    pub fn payload(&self) -> Option<&[u8]> {
        match &self.inner {
            DatumKind::Leaf { payload } => Some(payload),
            DatumKind::Node { .. } => None,
        }
    }

    /// Die kanonisch sortiert-deduplizierte Menge der besessenen Kontext-IDs,
    /// falls dies ein Knoten ist (§K2.3). Die Reihenfolge ist die kanonische
    /// (aufsteigende 32-Byte-Order).
    pub fn owns(&self) -> Option<&[ContentId]> {
        match &self.inner {
            DatumKind::Node { owns } => Some(owns),
            DatumKind::Leaf { .. } => None,
        }
    }

    /// `true`, wenn dies ein primitives Blatt ist (§K2.1).
    pub fn is_leaf(&self) -> bool {
        matches!(self.inner, DatumKind::Leaf { .. })
    }

    /// `true`, wenn dies ein besitzender Knoten ist (§K2.1).
    pub fn is_node(&self) -> bool {
        matches!(self.inner, DatumKind::Node { .. })
    }
}

/// Platzhalter-Daten (§3.6) — referenzielle Geschlossenheit ohne baumelnde
/// Verweise.
///
/// **Konvention (§3.6).** Ein Verweis zeigt **stets auf ein vorhandenes Daten**.
/// Ein noch nicht eingetroffenes Ziel wird durch ein **Platzhalter-Daten**
/// dargestellt: ein **gewöhnliches** Daten (ein Knoten, §K2.1) mit einem
/// Kontext, der es als *unaufgelöst/erwartet* ausweist. So ist jeder Verweis
/// geschlossen — es gibt **keine** baumelnden Verweise, nur explizit als
/// unaufgelöst markierte Daten.
///
/// **Grenze (§1.4/§7.2).** Der **Kernel** materialisiert Platzhalter **nicht**
/// und validiert die Geschlossenheit **nicht** — das erzwingt die *schreibende
/// Schicht*. Dieses Modul stellt allein die **Konvention** bereit (welches Atom
/// markiert „unaufgelöst", wie sieht ein Platzhalter-Knoten aus), damit Indizes
/// und Traversierung (spätere Phasen) auf der geschlossenen-Verweis-Invariante
/// bauen können. Die **volle** Platzhalter-Behandlung (Ersetzung §6.3,
/// Korrelations-Pfad §5.7 b) ist **Phase 3**.
///
/// **Aufbau.** Das Marker-Atom [`Datum::unresolved_marker`] ist ein gewöhnliches
/// Blatt-Daten (§2.1) mit fester, eingefrorener atomarer Nutzlast; seine
/// `ContentId` ist das eingefrorene Relations-/Typ-Daten „unaufgelöst/erwartet"
/// (§3.3/§4.1). Ein Platzhalter [`Datum::placeholder`] ist der **Knoten**, der
/// dieses Marker-Atom **und** die erwarteten Ziel-Kontexte besitzt.
impl Datum {
    /// Das eingefrorene **Marker-Atom** „unaufgelöst/erwartet" (§3.6) — ein
    /// gewöhnliches Blatt-Daten (§2.1) mit fester atomarer Nutzlast.
    ///
    /// Die Nutzlast ist exakt der ASCII-String `lakearch/unresolved/v1`; sie ist
    /// **eingefroren** (eine Änderung verschöbe die Marker-`ContentId` und damit
    /// die Erkennbarkeit aller Platzhalter). lakearch interpretiert die Bytes
    /// **nicht** (§1.4); der Wert ist allein eine wohlbekannte, föderationsweit
    /// gleiche Konvention (gleiche Bytes ⇒ gleiche `ContentId`, §5.3/§12.3).
    pub fn unresolved_marker() -> Self {
        Datum::leaf(*UNRESOLVED_MARKER_PAYLOAD)
    }

    /// Erzeugt ein **Platzhalter-Daten** (§3.6): ein Knoten, der das
    /// [`unresolved`](Datum::unresolved_marker)-Marker-Atom **und** die
    /// erwarteten Ziel-Kontexte besitzt.
    ///
    /// `expected_contexts` sind die `ContentId`s der Kontexte, auf die das
    /// erwartete Ziel zeigen soll (sie dürfen leer sein — dann ist der
    /// Platzhalter „nur als unaufgelöst markiert", ohne weitere Erwartung). Wie
    /// bei [`Datum::node`] ist die `owns`-Menge **sortiert + dedupliziert**; das
    /// Marker-Atom wird hinzugefügt, dann kanonisiert.
    ///
    /// Gibt **immer** `Some` zurück: das Marker-Atom ist stets in der Menge, ein
    /// Platzhalter ist also nie der leere (nicht wohlgeformte) Knoten (§K2.1).
    ///
    /// Der Kernel **wertet nicht** (§1.4): er prüft **nicht**, ob die erwarteten
    /// Ziele existieren — das ist Sache der schreibenden Schicht (§7.2).
    pub fn placeholder(expected_contexts: impl IntoIterator<Item = ContentId>) -> Self {
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        let owns = core::iter::once(marker).chain(expected_contexts);
        // `node` gibt nur `None` für die leere Menge zurück; das Marker-Atom ist
        // immer dabei, daher ist der Platzhalter stets wohlgeformt (§K2.1).
        Datum::node(owns).expect("Platzhalter besitzt stets das Marker-Atom (§3.6)")
    }

    /// `true`, wenn dieser Knoten das eingefrorene „unaufgelöst/erwartet"-Marker-
    /// Atom besitzt — also ein **Platzhalter-Daten** ist (§3.6).
    ///
    /// Reines **strukturelles Matching** (§1.3): „besitzt der Knoten den Marker-
    /// Kontext?". Keine Wertung (§1.4). Ein Blatt ist nie ein Platzhalter.
    pub fn is_placeholder(&self) -> bool {
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        match self.owns() {
            // `owns` ist aufsteigend sortiert ⇒ Binärsuche ist zulässig und
            // ändert die Semantik nicht (reines Mengen-Matching, §1.3).
            Some(owns) => owns.binary_search(&marker).is_ok(),
            None => false,
        }
    }
}

/// Eingefrorene atomare Nutzlast des Marker-Atoms „unaufgelöst/erwartet" (§3.6).
/// Exakt 22 Bytes ASCII; **niemals** ändern (verschöbe alle Platzhalter-IDs).
const UNRESOLVED_MARKER_PAYLOAD: &[u8; 22] = b"lakearch/unresolved/v1";

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> ContentId {
        ContentId::from_bytes([byte; 32])
    }

    #[test]
    fn leaf_keeps_opaque_payload() {
        let d = Datum::leaf([1u8, 2, 3]);
        assert!(d.is_leaf());
        assert_eq!(d.payload(), Some(&[1u8, 2, 3][..]));
        assert_eq!(d.owns(), None);
    }

    #[test]
    fn empty_leaf_is_well_formed_and_distinct_from_node() {
        // Leeres Blatt: payload = [] ist wohlgeformt (§K3.5).
        let d = Datum::leaf([]);
        assert!(d.is_leaf());
        assert_eq!(d.payload(), Some(&[][..]));
    }

    #[test]
    fn node_sorts_and_dedups_owned_contexts() {
        // Einfüge-Reihenfolge + Duplikat dürfen das Resultat nicht ändern (§K2.3).
        let a = cid(0x01);
        let b = cid(0x02);
        let n1 = Datum::node([b, a, b]).expect("nicht-leerer Knoten");
        let n2 = Datum::node([a, b]).expect("nicht-leerer Knoten");
        let n3 = Datum::node([b, a]).expect("nicht-leerer Knoten");
        assert_eq!(n1, n2);
        assert_eq!(n2, n3);
        assert_eq!(n1.owns(), Some(&[a, b][..]), "aufsteigend sortiert");
    }

    #[test]
    fn node_without_contexts_is_rejected() {
        // Ein Knoten ohne Kontexte ist nicht wohlgeformt (§K2.1).
        assert!(Datum::node([]).is_none());
    }

    #[test]
    fn node_is_not_a_leaf() {
        let n = Datum::node([cid(0x07)]).expect("nicht-leerer Knoten");
        assert!(n.is_node());
        assert!(!n.is_leaf());
        assert_eq!(n.payload(), None);
    }

    #[test]
    fn unresolved_marker_is_a_frozen_leaf() {
        // §3.6: das Marker-Atom ist ein gewöhnliches Blatt (§2.1) mit fester
        // Nutzlast.
        let m = Datum::unresolved_marker();
        assert!(m.is_leaf());
        assert_eq!(m.payload(), Some(&b"lakearch/unresolved/v1"[..]));
    }

    #[test]
    fn placeholder_owns_the_marker_and_is_a_node() {
        // §3.6: ein Platzhalter ist ein Knoten, der das Marker-Atom besitzt.
        let p = Datum::placeholder([]);
        assert!(p.is_node());
        assert!(p.is_placeholder());
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        assert_eq!(p.owns(), Some(&[marker][..]));
    }

    #[test]
    fn placeholder_includes_expected_contexts_sorted_and_dedup() {
        // §3.6 + §K2.3: Marker + erwartete Ziele, kanonisch sortiert/dedupliziert.
        let target = cid(0xff); // > Marker-CID in 32-Byte-Order
        let p = Datum::placeholder([target, target]);
        assert!(p.is_placeholder());
        let marker = ContentId::of_datum(&Datum::unresolved_marker());
        let owns = p.owns().expect("Knoten");
        assert_eq!(owns.len(), 2, "Marker + ein dedupliziertes Ziel");
        assert!(owns.contains(&marker));
        assert!(owns.contains(&target));
        // Aufsteigend sortiert (§K2.3).
        assert!(owns[0] < owns[1]);
    }

    #[test]
    fn ordinary_node_is_not_a_placeholder() {
        // Reines strukturelles Matching (§1.3): ohne Marker kein Platzhalter.
        let n = Datum::node([cid(0x07)]).unwrap();
        assert!(!n.is_placeholder());
        // Ein Blatt ist nie ein Platzhalter.
        assert!(!Datum::leaf([0x01]).is_placeholder());
    }
}
