//! Compaction & physische Erasure (§15/§9.5) — öffentliche Ende-zu-Ende-Tests über
//! die `pub`-API.
//!
//! Maßgeblich: Gesetzbuch `semantics/lakearch.md` (§15 Compaction; §9.5 Kuratierung;
//! §3.6 Geschlossenheit; §6.3 Ersetzung; §12.3 Föderation) und der gehärtete Plan
//! (Abschnitt „Storage-Engine, Compaction/DSGVO, Scale-out"). Geprüft wird:
//!
//! - **Crypto-Shredding (§15/§Crypto-Shred):** ein erastes Daten ist nach Zerstören
//!   des Lösch-Schlüssels unrückholbar; die `ContentId`/Kanten bleiben (Tombstone,
//!   §3.6); andere Dedup-Referenzen überleben (Refcount §5.3).
//! - **Compaction (§15):** lässt verwaiste Records physisch fallen, ohne Content-
//!   Adressierung oder live Leser zu brechen, und rekonstruiert eine konsistente,
//!   reproduzierbare Generation.
//! - **Erasure ist gegatet + auditiert + nicht-transitiv (§15/§11/§12.3):** ohne das
//!   Erasure-Recht verweigert; mit Recht wird ein Audit-Daten angehängt; eine Erasure
//!   in einem Bestand propagiert NICHT in einen anderen (Föderation §12.3).

use std::collections::HashSet;

use lakearch_core::{
    CompactedSegment, ContentId, Datum, ErasureKey, Kernel, KernelError, LakearchKernel,
};
use tempfile::tempdir;

fn open(dir: &std::path::Path) -> LakearchKernel<lakearch_core::RedbEdgeIndex> {
    LakearchKernel::open(dir).expect("open kernel")
}

#[test]
fn crypto_shredded_bytes_unrecoverable_refs_closed_others_survive() {
    // §15/§Crypto-Shred/§3.6/§5.3: erase + compact ⇒ nach Schlüssel-Zerstörung sind
    // die erasten Bytes unrückholbar; ContentId/Kanten bleiben (Tombstone); eine
    // andere Dedup-Referenz überlebt.
    let dir = tempdir().unwrap();
    let k = open(dir.path());

    let public = k.append(&Datum::leaf(b"oeffentlich".to_vec())).unwrap();
    let personal = k.append(&Datum::leaf(b"personenbezogen".to_vec())).unwrap();
    // Ein Knoten besitzt beide ⇒ er referenziert `personal` (Kante bleibt §3.6).
    let owner = k.append(&Datum::node([public, personal]).unwrap()).unwrap();

    // Gegatete, auditierte Erasure von `personal`.
    let key = ErasureKey::derive(b"subjekt-master-geheimnis", personal);
    let audit = k.erase(personal, &Datum::erasure_right(), key).unwrap();

    // Compaction: die nächste Generation versiegelt `personal`.
    let (seg, mut keystore, report) = k.compact().unwrap();
    assert_eq!(report.sealed, 1);
    assert!(seg.is_sealed(personal));

    // Mit dem lebenden Schlüssel noch lesbar.
    assert_eq!(seg.datum(personal, &keystore).unwrap(), Some(Datum::leaf(b"personenbezogen".to_vec())));

    // "Recht auf Vergessen": Schlüssel zerstören ⇒ Bytes unrückholbar.
    assert!(keystore.destroy(personal));
    assert_eq!(seg.canonical_bytes(personal, &keystore).unwrap(), None, "geschreddert");
    // §3.6: die ContentId bleibt als Adresse + Kante erreichbar (geschlossener Verweis).
    assert!(seg.contains(personal), "Tombstone bleibt (§3.6)");
    // Andere Referenzen überleben (Refcount §5.3).
    assert_eq!(seg.datum(public, &keystore).unwrap(), Some(Datum::leaf(b"oeffentlich".to_vec())));
    assert_eq!(seg.datum(owner, &keystore).unwrap(), Some(Datum::node([public, personal]).unwrap()));
    // Das Audit-Daten überlebt (Beleg §15).
    assert!(seg.contains(audit));
}

#[test]
fn erasure_is_denied_without_right_and_audited_with_right() {
    // §15/§11: gegatet (ohne Recht verweigert, nichts angehängt) + auditiert (mit Recht
    // ein Audit-Daten angehängt).
    let dir = tempdir().unwrap();
    let k = open(dir.path());
    let target = k.append(&Datum::leaf(b"d".to_vec())).unwrap();
    let before = k.content_set().unwrap().len();

    // Ohne Recht: verweigert, nichts angehängt.
    let denied = k.erase(target, &Datum::leaf(b"kein-recht".to_vec()), ErasureKey::from_bytes([0; 32]));
    assert!(matches!(denied, Err(KernelError::ErasureDenied)));
    assert_eq!(k.content_set().unwrap().len(), before);

    // Mit Recht: Audit angehängt.
    let audit = k.erase(target, &Datum::erasure_right(), ErasureKey::from_bytes([1; 32])).unwrap();
    let snap = k.pin_snapshot().unwrap();
    let cap = k.authorize(lakearch_core::GrantedScopes::from_scope_ids([]), snap).unwrap();
    let sealed = k.get_by_content_id(audit, &cap, snap).unwrap().expect("Audit vorhanden");
    let audit_d = lakearch_core::strict_decode(
        lakearch_core::open(&sealed, &cap).unwrap().canonical_bytes(),
    )
    .unwrap();
    assert_eq!(audit_d.erasure_audit_target(), Some(target));
}

#[test]
fn compaction_does_not_break_live_readers_or_content_addressing() {
    // §15: Compaction schreibt eine NEUE Generation; das laufende Append-Log, das ein
    // Leser hält, wird NICHT unmappt — der Leser sieht weiterhin alles.
    let dir = tempdir().unwrap();
    let k = open(dir.path());
    let a = k.append(&Datum::leaf(b"a".to_vec())).unwrap();
    let b = k.append(&Datum::leaf(b"b".to_vec())).unwrap();

    // Ein Leser pinnt VOR der Compaction.
    let snap = k.pin_snapshot().unwrap();
    let cap = k.authorize(lakearch_core::GrantedScopes::from_scope_ids([]), snap).unwrap();

    let (seg, _ks, _report) = k.compact().unwrap();

    // Der vor-Compaction-Leser liest weiter aus dem (nicht unmappten) Log.
    assert!(k.get_by_content_id(a, &cap, snap).unwrap().is_some());
    assert!(k.get_by_content_id(b, &cap, snap).unwrap().is_some());
    // Die compactierte Generation hält beide über ihre stabile logische ID.
    assert!(seg.contains(a) && seg.contains(b));
}

#[test]
fn erasure_is_non_transitive_across_federation() {
    // §15/§12.3: eine Erasure in S1 propagiert NICHT in S2. Ein bestand-übergreifend
    // inhaltsgleiches Daten trägt zwar dieselbe ContentId (§12.3), aber der Lösch-
    // Schlüssel ist bestand-LOKAL — S2 behält seine Klartext-Bytes, bis S2 selbst
    // (eigenständig gegatet + auditiert) erast.
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    let s1 = open(d1.path());
    let s2 = open(d2.path());

    // Inhaltsgleiches Daten in beiden Beständen (§12.3 ⇒ gleiche ContentId).
    let id1 = s1.append(&Datum::leaf(b"gemeinsam-personenbezogen".to_vec())).unwrap();
    let id2 = s2.append(&Datum::leaf(b"gemeinsam-personenbezogen".to_vec())).unwrap();
    assert_eq!(id1, id2, "inhaltsgleich ⇒ gleiche ContentId (§12.3)");

    // S1 erast + compactiert (lokal).
    let key = ErasureKey::from_bytes([0xab; 32]);
    s1.erase(id1, &Datum::erasure_right(), key).unwrap();
    let (seg1, mut ks1, _r) = s1.compact().unwrap();
    assert!(ks1.destroy(id1));
    assert_eq!(seg1.canonical_bytes(id1, &ks1).unwrap(), None, "in S1 geschreddert");

    // S2 ist UNBERÜHRT: seine Klartext-Bytes bleiben (nicht-transitiv §12.3). Ohne
    // Erasure ist S2s Datum weiterhin voll lesbar.
    let (seg2, ks2, r2) = s2.compact().unwrap();
    assert_eq!(r2.sealed, 0, "in S2 wurde NICHTS erast (nicht-transitiv §12.3)");
    assert_eq!(
        seg2.datum(id2, &ks2).unwrap(),
        Some(Datum::leaf(b"gemeinsam-personenbezogen".to_vec())),
        "S2 behält die Klartext-Bytes (Erasure ist nicht-transitiv §12.3)"
    );
}

#[test]
fn compaction_physically_drops_orphan_and_generation_round_trips() {
    // §15: ein explizit übergebenes verwaistes Daten wird physisch entfernt; die
    // unveränderliche Generation round-trippt auf Platte (Index rekonstruiert).
    let dir = tempdir().unwrap();
    let k = open(dir.path());
    let keep = k.append(&Datum::leaf(b"behalten".to_vec())).unwrap();
    let orphan = k.append(&Datum::leaf(b"verwaist".to_vec())).unwrap();

    let mut drop: HashSet<ContentId> = HashSet::new();
    drop.insert(orphan);
    let (seg, ks, report) = k.compact_with_drop(drop).unwrap();
    assert!(report.dropped >= 1);
    assert!(!seg.contains(orphan));
    assert!(seg.contains(keep));

    // Reopen der Generation von Platte ⇒ identische Sicht (deterministisch §5.2/§1.4).
    let gdir = lakearch_core::generation_dir(dir.path(), report.generation);
    let seg2 = CompactedSegment::read_from(&gdir).unwrap();
    assert_eq!(seg2.ids(), seg.ids());
    assert_eq!(seg2.datum(keep, &ks).unwrap(), Some(Datum::leaf(b"behalten".to_vec())));
}
