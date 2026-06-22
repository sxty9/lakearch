//! Föderation (§12) — öffentliche Ende-zu-Ende-Tests über die `pub`-API.
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md` §12 (Föderation) und der
//! gehärtete Plan (Abschnitt „Föderations-Idempotenz"). Geprüft wird:
//!
//! - **§12.3:** inhaltsgleiche Daten zweier getrennter Bestände S1, S2 fallen beim
//!   Aufnehmen **automatisch** über ihre `ContentId` zusammen (Dedup §5.3) — kein
//!   Sonderfall (§12.5).
//! - **§12.4:** referenziell „dasselbe Ding" (bestand-lokale Anker) wird über
//!   **deterministische** gradierte-Identitäts-Versöhnungs-Kontexte verbunden
//!   (Korrelations-Pfad §5.7 b).
//! - **Idempotenz (§12.4):** denselben fremden Bestand **zweimal** (sequenziell
//!   **und** simuliert nebenläufig) aufnehmen ⇒ **byte-gleicher** Bestand (gleiche
//!   Inhalts-Menge **und** gleiche Versöhnungs-Kontexte).

use std::sync::Arc;

use lakearch_core::{ContentId, Datum, Kernel, LakearchKernel};
use tempfile::tempdir;

/// Öffnet einen frischen Kernel (redb-Engine) in einem temporären Verzeichnis.
/// Der `TempDir` muss am Leben bleiben, solange der Kernel offen ist.
fn open(dir: &std::path::Path) -> LakearchKernel<lakearch_core::RedbEdgeIndex> {
    LakearchKernel::open(dir).expect("open kernel")
}

/// Baut in einem Bestand einen kleinen Graphen mit einem **Anker** (§9.1) und einem
/// Repräsentanten, der über eine gradierte Mitgliedschaft (§9.3) auf ihn verweist;
/// `class_payload` bestimmt die (inhaltsgleiche oder verschiedene) Klasse. Liefert
/// `(anchor_id, rep_id, shared_leaf_id)`.
fn build_anchor_graph(
    k: &LakearchKernel<lakearch_core::RedbEdgeIndex>,
    class_payload: &[u8],
    grade_payload: &[u8],
) -> (ContentId, ContentId, ContentId) {
    // Ein BESTAND-ÜBERGREIFEND inhaltsgleiches Blatt (§12.3): beide Bestände bauen
    // exakt dasselbe Daten ⇒ gleiche ContentId.
    let shared = k.append(&Datum::leaf(b"shared-leaf".to_vec())).unwrap();

    // Der Anker (§9.1) — ein gewöhnliches inhaltsadressiertes Daten.
    let class = k.append(&Datum::leaf(class_payload.to_vec())).unwrap();
    k.append(&Datum::anchor_marker()).unwrap();
    let anchor = k.append(&Datum::anchor([class, shared])).unwrap();

    // Eine gradierte Mitgliedschaft (§9.3): erst Grad-Wert + Grad-Sub-Kontext, dann
    // die Mitgliedschaft, dann der Repräsentant.
    let grade = k.append(&Datum::leaf(grade_payload.to_vec())).unwrap();
    k.append(&Datum::membership_marker()).unwrap();
    k.append(&Datum::membership_grade_marker()).unwrap();
    k.append(&Datum::membership_grade(grade)).unwrap();
    let m = k.append(&Datum::membership(anchor, grade)).unwrap();
    let rep = k.append(&Datum::node([m, shared]).unwrap()).unwrap();

    (anchor, rep, shared)
}

#[test]
fn content_equal_data_collapse_across_bestaende_via_content_id() {
    // §12.3/§12.5: zwei getrennte Bestände S1, S2 mit inhaltsgleichen Daten; beim
    // Aufnehmen von S2 in S1 fallen die inhaltsgleichen Daten AUTOMATISCH über ihre
    // ContentId zusammen (Dedup §5.3) — kein Sonderfall (§12.5).
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    let s1 = open(d1.path());
    let s2 = open(d2.path());

    // Beide Bestände bauen DASSELBE inhaltsgleiche Blatt + einen je eigenen.
    let shared1 = s1.append(&Datum::leaf(b"gemeinsam".to_vec())).unwrap();
    s1.append(&Datum::leaf(b"nur-in-s1".to_vec())).unwrap();
    let shared2 = s2.append(&Datum::leaf(b"gemeinsam".to_vec())).unwrap();
    let only2 = s2.append(&Datum::leaf(b"nur-in-s2".to_vec())).unwrap();

    // §12.3: inhaltsgleich ⇒ dieselbe ContentId (bestand-unabhängig).
    assert_eq!(shared1, shared2, "inhaltsgleiche Daten tragen dieselbe ContentId (§12.3)");

    let before = s1.content_set().unwrap();
    // S2 in S1 aufnehmen.
    let (new_count, dedup_count) = s1.federate(&s2).unwrap();
    // Das gemeinsame Blatt kollabiert (Dedup), das s2-exklusive ist neu.
    assert_eq!(dedup_count, 1, "das gemeinsame Daten kollabiert via ContentId (§12.3)");
    assert_eq!(new_count, 1, "nur das s2-exklusive Daten ist neu");

    let after = s1.content_set().unwrap();
    assert_eq!(after.len(), before.len() + 1, "genau ein neues Daten");
    assert!(after.contains(&only2), "das s2-exklusive Daten ist jetzt in S1");
    // Das gemeinsame Daten existiert nur EINMAL (Wert-Identität §5.3).
    assert_eq!(after.iter().filter(|id| **id == shared1).count(), 1);
}

#[test]
fn referentially_same_anchors_connect_via_reconciliation_contexts() {
    // §12.4: die bestand-lokalen Anker von S1 und S2 sind referenziell „dasselbe
    // Ding"; sie werden über einen DETERMINISTISCHEN gradierten Identitäts-
    // Versöhnungs-Kontext verbunden (Korrelations-Pfad §5.7 b). Der Kernel
    // ENTSCHEIDET die Identität NICHT — die Schicht darüber bestimmt das Paar.
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    let s1 = open(d1.path());
    let s2 = open(d2.path());

    let (anchor1, _rep1, _) = build_anchor_graph(&s1, b"klasse-A", b"g1");
    let (anchor2, _rep2, _) = build_anchor_graph(&s2, b"klasse-A", b"g1");
    // Bei inhaltsgleicher Klasse + gemeinsamem Blatt sind sogar die Anker inhalts-
    // gleich (§12.3) — hier prüfen wir bewusst die VERSÖHNUNG als eigenständiges
    // Primitiv, daher bauen wir den Fall mit verschiedenen Klassen separat unten.

    // S2 in S1 aufnehmen (Inhalts-Kollaps automatisch).
    s1.federate(&s2).unwrap();

    // Die Schicht darüber entscheidet: anchor1 und anchor2 sind dasselbe Ding.
    let rule = Datum::leaf(b"stabiler-schluessel".to_vec());
    let reconcile_id = s1.reconcile_anchor(anchor1, anchor2, &rule).unwrap();

    // Der Versöhnungs-Kontext verbindet beide Anker (von beiden aus auffindbar §5.5).
    let snap = s1.pin_snapshot().unwrap();
    let cap = s1
        .authorize(lakearch_core::GrantedScopes::from_scope_ids([]), snap)
        .unwrap();
    let links1 = s1.graded_identity_links_visible(anchor1, &cap, snap).unwrap();
    let links2 = s1.graded_identity_links_visible(anchor2, &cap, snap).unwrap();
    assert!(links1.contains(&reconcile_id), "von anchor1 aus auffindbar (§5.5)");
    assert!(links2.contains(&reconcile_id), "von anchor2 aus auffindbar (§5.5)");
}

#[test]
fn anchors_with_different_local_classes_are_reconciled_deterministically() {
    // §12.4: zwei VERSCHIEDENE bestand-lokale Anker (verschiedene Klassen ⇒
    // verschiedene ContentIds) werden über die deterministische Versöhnung
    // verbunden. Der Versöhnungs-Kontext ist eine reine Funktion von (foreign,
    // local, rule) ⇒ idempotent.
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    let s1 = open(d1.path());
    let s2 = open(d2.path());

    let (anchor1, _, _) = build_anchor_graph(&s1, b"klasse-lokal-1", b"g1");
    let (anchor2, _, _) = build_anchor_graph(&s2, b"klasse-lokal-2", b"g2");
    assert_ne!(anchor1, anchor2, "verschiedene Klassen ⇒ verschiedene Anker-ContentIds");

    s1.federate(&s2).unwrap();

    let rule = Datum::leaf(b"korrelations-regel".to_vec());
    let r_a = s1.reconcile_anchor(anchor1, anchor2, &rule).unwrap();
    // Zweiter Aufruf mit denselben Argumenten ⇒ byte-gleicher Kontext (Dedup §5.3).
    let r_b = s1.reconcile_anchor(anchor1, anchor2, &rule).unwrap();
    assert_eq!(r_a, r_b, "deterministisch ⇒ derselbe Versöhnungs-Kontext (§12.4)");
}

/// Baut zwei kleine Bestände S1, S2: S1 ist der lokale Ziel-Bestand, S2 der fremde.
/// Liefert die Pfade (müssen am Leben bleiben) plus die fremden Anker-IDs.
fn build_two_bestaende() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    LakearchKernel<lakearch_core::RedbEdgeIndex>,
    LakearchKernel<lakearch_core::RedbEdgeIndex>,
) {
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    let s1 = open(d1.path());
    let s2 = open(d2.path());
    // S1 hat eigene Daten.
    build_anchor_graph(&s1, b"klasse-S1", b"g-s1");
    // S2 hat eigene Daten + ein bestand-übergreifend inhaltsgleiches Blatt.
    build_anchor_graph(&s2, b"klasse-S2", b"g-s2");
    (d1, d2, s1, s2)
}

#[test]
fn double_ingest_sequential_is_idempotent_byte_identical() {
    // §12.4: denselben fremden Bestand ZWEIMAL sequenziell aufnehmen ⇒ byte-gleicher
    // Bestand. Inhaltsgleiche Daten kollabieren beim zweiten Mal vollständig (Dedup
    // §5.3); KEINE neuen Daten, KEINE doppelten Versöhnungs-Kontexte.
    let (_d1, _d2, s1, s2) = build_two_bestaende();

    // Ein fremder + ein lokaler Anker, die die Schicht darüber korreliert.
    let foreign_anchor = s2.anchor_cids().unwrap()[0];
    let local_anchor = s1.anchor_cids().unwrap()[0];
    let rule = Datum::leaf(b"regel".to_vec());

    // Erster Ingest + Versöhnung.
    s1.federate(&s2).unwrap();
    s1.reconcile_anchor(foreign_anchor, local_anchor, &rule).unwrap();
    let after_first = s1.content_set().unwrap();

    // Zweiter Ingest + Versöhnung — exakt dieselben Operationen.
    let (new_count, dedup_count) = s1.federate(&s2).unwrap();
    s1.reconcile_anchor(foreign_anchor, local_anchor, &rule).unwrap();
    let after_second = s1.content_set().unwrap();

    assert_eq!(new_count, 0, "zweiter Ingest schreibt NICHTS Neues (Dedup §5.3/§12.4)");
    assert!(dedup_count > 0, "alle fremden Daten kollabieren via ContentId");
    assert_eq!(
        after_first, after_second,
        "byte-gleicher Bestand nach Doppel-Ingest (idempotent §12.4)"
    );
}

#[test]
fn double_ingest_concurrent_is_idempotent_byte_identical() {
    // §12.4: denselben fremden Bestand NEBENLÄUFIG zweimal aufnehmen ⇒ byte-gleicher
    // Bestand. Der lokale Append-Pfad serialisiert (eine Pipeline §7.1); die
    // deterministischen Versöhnungs-Kontexte kollabieren per Hash (§5.3) — das
    // Ergebnis ist unabhängig von der Verschränkung.
    let (_d1, _d2, s1, s2) = build_two_bestaende();
    let foreign_anchor = s2.anchor_cids().unwrap()[0];
    let local_anchor = s1.anchor_cids().unwrap()[0];

    let s1 = Arc::new(s1);
    let s2 = Arc::new(s2);

    // Eine Referenz-Sicht: was EIN Ingest+Versöhnung ergäbe.
    {
        let ref_local = local_anchor;
        let ref_foreign = foreign_anchor;
        s1.federate(&s2).unwrap();
        s1.reconcile_anchor(ref_foreign, ref_local, &Datum::leaf(b"regel".to_vec()))
            .unwrap();
    }
    let reference = s1.content_set().unwrap();

    // Jetzt NEBENLÄUFIG dieselben Operationen ein zweites Mal (zwei Threads), die
    // den fremden Bestand gleichzeitig einspielen + dieselbe Versöhnung anhängen.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s1c = Arc::clone(&s1);
        let s2c = Arc::clone(&s2);
        let f = foreign_anchor;
        let l = local_anchor;
        handles.push(std::thread::spawn(move || {
            s1c.federate(&s2c).unwrap();
            s1c.reconcile_anchor(f, l, &Datum::leaf(b"regel".to_vec()))
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let after_concurrent = s1.content_set().unwrap();
    assert_eq!(
        reference, after_concurrent,
        "nebenläufiger Doppel-Ingest ⇒ byte-gleicher Bestand (idempotent §12.4)"
    );
}
