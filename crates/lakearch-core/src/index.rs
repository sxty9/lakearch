//! Sekundär-**Kanten-Indizes** (§1.2/§10.3) — reine, löschbare, **neu-baubare**
//! Derivate über dem Log (§8.4).
//!
//! Maßgeblich: das Gesetzbuch `semantics/lakearch.md` (§1.2 Vor-/Rückwärts-
//! Traversierung; §3.1/§3.2 gerichteter Besitz; §8.4 Log = alleinige Wahrheit;
//! §10.3 Rückwärts-Traversierung der Herkunft) und der gehärtete Plan
//! (Abschnitte „Log-als-alleinige-Wahrheit + neu-baubarer Index", „Storage-
//! Engine").
//!
//! ## Die beiden Kanten-Richtungen (§3.2)
//!
//! Besitz `A ⊳ K` ist **gerichtet** (§3.2). Eine Kante existiert physisch
//! **ausschließlich** als abgeleiteter Index-Eintrag und bekommt **keine** eigene
//! `ContentId` (§2.2/§3.1/§K2.2). Dieses Modul hält genau die zwei abgeleiteten
//! Richtungen, die spätere mechanische Traversierung (Phase 2) braucht:
//!
//! - **`owner → contexts`** (Vorwärts, §1.2/§3.2): von einem besitzenden Knoten
//!   `A` zu den `ContentId`s der von ihm besessenen Kontexte `K`.
//! - **`target → referrers`** (Rückwärts, §1.2/§10.3): von einem Ziel-Daten `K`
//!   zu den `ContentId`s der Knoten `A`, die es besitzen — die Grundlage der
//!   Rückwärts-Traversierung/Invalidierung (§10.3).
//!
//! ## Log-als-Wahrheit (§8.4) — Watermark, Ordnung, Neu-Bau
//!
//! Der Index ist ein **reines Derivat**: er darf jederzeit verworfen und aus dem
//! Log neu gebaut werden. Dazu persistiert er **transaktional in seinem eigenen
//! Commit** ein **Watermark** „bis Log-Offset N nachgezogen". Die strikte
//! Ordnung ist **log-fsync → index-commit** (nie umgekehrt; der Index lagt per
//! Design). Recovery (im [`crate::store`]) versöhnt: Watermark `W` < durabler
//! Log-Tail `T` ⇒ `[W..T)` nachspielen; `W > T` ⇒ Index ist unsicher ⇒
//! voller Neu-Bau ([`EdgeIndex::wipe`] + Replay), **keine** Suffix-Chirurgie.
//!
//! ## Engine hinter einem Trait (billig revidierbar)
//!
//! Weil das Log die Wahrheit ist, ist die Engine **billig revidierbar**: der
//! [`EdgeIndex`]-Trait gibt **owned** `ContentId`s heraus (keine geliehenen
//! redb-Guards lecken nach außen), sodass eine Fremd-Engine (LMDB/RocksDB)
//! eingesetzt werden kann, ohne den Aufrufer zu berühren. Die konkrete Impl ist
//! [`RedbEdgeIndex`] (pure-Rust redb; RocksDB ist heute bewusst ausgeschlossen —
//! `libclang` fehlt; vgl. `DECISIONS-FOR-REVIEW.md`).
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: es arbeitet nur über die sichere
//! redb-API und `Vec`/`[u8; 32]`.

#![forbid(unsafe_code)]

use redb::{Database, Durability, MultimapTableDefinition, ReadableTable, TableDefinition};

use crate::error::KernelError;
use crate::id::ContentId;

/// redb-Tabelle **`owner → contexts`** (Vorwärts-Kante, §1.2/§3.2): Schlüssel ist
/// die 32-Byte-`ContentId` des besitzenden Knotens, Werte sind die `ContentId`s
/// der besessenen Kontexte. Multimap, weil ein Knoten viele Kontexte besitzt.
const OWNER_CONTEXTS: MultimapTableDefinition<[u8; 32], [u8; 32]> =
    MultimapTableDefinition::new("owner_contexts");

/// redb-Tabelle **`target → referrers`** (Rückwärts-Kante, §1.2/§10.3): Schlüssel
/// ist die 32-Byte-`ContentId` des Ziel-Daten, Werte sind die `ContentId`s der
/// Knoten, die es besitzen. Multimap, weil viele Knoten dasselbe Ziel besitzen.
const TARGET_REFERRERS: MultimapTableDefinition<[u8; 32], [u8; 32]> =
    MultimapTableDefinition::new("target_referrers");

/// redb-Tabelle für das **Watermark** (§8.4): „Index bis Log-Offset N nachgezogen".
/// Ein-Eintrag-Tabelle unter dem festen Schlüssel [`WATERMARK_KEY`]; **im selben
/// Commit** wie die Kanten geschrieben (transaktionale Atomarität).
const WATERMARK: TableDefinition<&str, u64> = TableDefinition::new("watermark");

/// Fester Schlüssel des Watermark-Eintrags.
const WATERMARK_KEY: &str = "log_offset";

/// Eine abgeleitete **Kante** (§3.2) für den Index: der besitzende Knoten `owner`
/// besitzt den Kontext `context`. Sie hat **keine** eigene `ContentId` (§2.2);
/// sie ist nur ein Index-Eintrag, der in **beide** Richtungen abgelegt wird
/// (`owner→contexts` **und** `target→referrers`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Edge {
    /// Der besitzende Knoten (§3.1).
    pub owner: ContentId,
    /// Das besessene Kontext-Daten (§3.1) — zugleich das Ziel der Kante.
    pub context: ContentId,
}

/// Die **Kanten-Index-Schnittstelle** (§1.2/§10.3). Engine-unabhängig: liefert
/// **owned** `ContentId`s und persistiert das Watermark transaktional in seinem
/// eigenen Commit (§8.4).
///
/// **Reines Derivat (§8.4):** jede Implementierung MUSS [`EdgeIndex::wipe`]
/// erlauben (alles löschen, Watermark auf 0) und garantieren, dass ein
/// vollständiger Neu-Bau aus dem Log denselben Inhalt erzeugt.
pub trait EdgeIndex {
    /// **Commit eines Batches** abgeleiteter Kanten **zusammen mit** dem neuen
    /// Watermark — in **einer** atomaren Transaktion (§8.4: Watermark
    /// transaktional im Index-Commit). Ordnung über dem Log: der Aufrufer ruft
    /// dies **erst nach** dem Log-`fsync` (log-fsync → index-commit).
    ///
    /// `new_watermark` ist der committed Log-Offset, bis zu dem dieser Batch den
    /// Index nachgezogen hat. Er MUSS monoton **nicht-fallend** sein
    /// (§8.4-Invariante); ein Rückschritt ist [`KernelError::Inconsistent`].
    fn commit_edges(&mut self, edges: &[Edge], new_watermark: u64) -> Result<(), KernelError>;

    /// Die **Kontexte**, die `owner` besitzt (`owner → contexts`, Vorwärts,
    /// §1.2/§3.2) — owned, **aufsteigend** in 32-Byte-`ContentId`-Order
    /// (deterministischer, föderationsstabiler Tiebreak; §5.2 „adressiert, urteilt
    /// nicht"; **kein** Wert-Sort, §1.4). Leerer Vec, wenn `owner` nichts besitzt.
    fn contexts_of(&self, owner: ContentId) -> Result<Vec<ContentId>, KernelError>;

    /// Die **Verweiser** auf `target` (`target → referrers`, Rückwärts,
    /// §1.2/§10.3) — owned, aufsteigend in 32-Byte-Order. Leerer Vec, wenn
    /// niemand `target` besitzt.
    fn referrers_of(&self, target: ContentId) -> Result<Vec<ContentId>, KernelError>;

    /// Das aktuelle **Watermark** (§8.4): der Log-Offset, bis zu dem der Index
    /// nachgezogen ist. 0 für einen frischen/gewipten Index.
    fn watermark(&self) -> Result<u64, KernelError>;

    /// **Präfix-/Range-Scan** der besitzenden Knoten (`owner`-Schlüssel) im
    /// halb-offenen Intervall `[start, end)` der 32-Byte-`ContentId`-Order. Liefert
    /// jeden `owner` **mit** seinen Kontexten, owner-aufsteigend. Reines
    /// strukturelles Durchlaufen der Adress-Order (§5.2/§1.3), **kein** Wert-Sort
    /// (§1.4). Wird für Neu-Bau-Vergleiche und spätere Bulk-Traversierung genutzt.
    fn scan_owners(
        &self,
        start: ContentId,
        end: ContentId,
    ) -> Result<Vec<(ContentId, Vec<ContentId>)>, KernelError>;

    /// **Wipe** (§8.4): löscht **alle** Kanten **und** setzt das Watermark auf 0 —
    /// in einer Transaktion. Danach ist der Index leer und muss aus dem Log neu
    /// gebaut werden ([`crate::store::ContentStore::rebuild_index_from_log`]).
    fn wipe(&mut self) -> Result<(), KernelError>;
}

/// Konkrete **redb-Implementierung** von [`EdgeIndex`] (pure-Rust embedded KV).
///
/// Tabellen-Layout (§Storage-Engine):
/// - `owner_contexts` : Multimap `[u8;32] → [u8;32]` (Vorwärts, `owner→contexts`).
/// - `target_referrers` : Multimap `[u8;32] → [u8;32]` (Rückwärts, `target→referrers`).
/// - `watermark` : Tabelle `&str → u64`, ein Eintrag `"log_offset"`.
///
/// **Durability:** Index-Commits laufen mit [`Durability::Immediate`] (der Index
/// soll nach `commit_edges` durabel sein). Geht der Index trotzdem verloren oder
/// läuft er dem Log voraus (`W > T`), ist er als reines Derivat (§8.4) **neu
/// baubar** — er ist nie die Wahrheit.
pub struct RedbEdgeIndex {
    db: Database,
}

impl RedbEdgeIndex {
    /// Öffnet (oder erstellt) den Index unter `path`. Beim ersten Öffnen werden
    /// die Tabellen und der Watermark-Eintrag (`0`) angelegt.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, KernelError> {
        let db = Database::create(path).map_err(|_| KernelError::Io)?;
        let me = RedbEdgeIndex { db };
        me.ensure_initialized()?;
        Ok(me)
    }

    /// Stellt sicher, dass die Tabellen existieren und ein Watermark-Eintrag
    /// gesetzt ist (idempotent). Läuft in einer eigenen Immediate-Transaktion.
    fn ensure_initialized(&self) -> Result<(), KernelError> {
        let mut wtx = self.db.begin_write().map_err(|_| KernelError::Io)?;
        wtx.set_durability(Durability::Immediate);
        {
            // Tabellen öffnen = anlegen, falls fehlend.
            let _ = wtx
                .open_multimap_table(OWNER_CONTEXTS)
                .map_err(|_| KernelError::Io)?;
            let _ = wtx
                .open_multimap_table(TARGET_REFERRERS)
                .map_err(|_| KernelError::Io)?;
            let mut wm = wtx.open_table(WATERMARK).map_err(|_| KernelError::Io)?;
            let existing = wm
                .get(WATERMARK_KEY)
                .map_err(|_| KernelError::Io)?
                .map(|g| g.value());
            if existing.is_none() {
                wm.insert(WATERMARK_KEY, 0u64)
                    .map_err(|_| KernelError::Io)?;
            }
        }
        wtx.commit().map_err(|_| KernelError::Io)?;
        Ok(())
    }
}

impl EdgeIndex for RedbEdgeIndex {
    fn commit_edges(&mut self, edges: &[Edge], new_watermark: u64) -> Result<(), KernelError> {
        // Watermark MUSS monoton nicht-fallend sein (§8.4-Invariante).
        let current = self.watermark()?;
        if new_watermark < current {
            return Err(KernelError::Inconsistent);
        }

        let mut wtx = self.db.begin_write().map_err(|_| KernelError::Io)?;
        wtx.set_durability(Durability::Immediate);
        {
            let mut fwd = wtx
                .open_multimap_table(OWNER_CONTEXTS)
                .map_err(|_| KernelError::Io)?;
            let mut bwd = wtx
                .open_multimap_table(TARGET_REFERRERS)
                .map_err(|_| KernelError::Io)?;
            for e in edges {
                // Vorwärts: owner → context.
                fwd.insert(e.owner.as_bytes(), e.context.as_bytes())
                    .map_err(|_| KernelError::Io)?;
                // Rückwärts: context (Ziel) → owner (Verweiser).
                bwd.insert(e.context.as_bytes(), e.owner.as_bytes())
                    .map_err(|_| KernelError::Io)?;
            }
            // Watermark **im selben Commit** setzen (transaktionale Atomarität, §8.4).
            let mut wm = wtx.open_table(WATERMARK).map_err(|_| KernelError::Io)?;
            wm.insert(WATERMARK_KEY, new_watermark)
                .map_err(|_| KernelError::Io)?;
        }
        wtx.commit().map_err(|_| KernelError::Io)?;
        Ok(())
    }

    fn contexts_of(&self, owner: ContentId) -> Result<Vec<ContentId>, KernelError> {
        let rtx = self.db.begin_read().map_err(|_| KernelError::Io)?;
        let table = rtx
            .open_multimap_table(OWNER_CONTEXTS)
            .map_err(|_| KernelError::Io)?;
        read_multimap_values(&table, owner)
    }

    fn referrers_of(&self, target: ContentId) -> Result<Vec<ContentId>, KernelError> {
        let rtx = self.db.begin_read().map_err(|_| KernelError::Io)?;
        let table = rtx
            .open_multimap_table(TARGET_REFERRERS)
            .map_err(|_| KernelError::Io)?;
        read_multimap_values(&table, target)
    }

    fn watermark(&self) -> Result<u64, KernelError> {
        let rtx = self.db.begin_read().map_err(|_| KernelError::Io)?;
        let table = rtx.open_table(WATERMARK).map_err(|_| KernelError::Io)?;
        let v = table
            .get(WATERMARK_KEY)
            .map_err(|_| KernelError::Io)?
            .map(|g| g.value())
            .unwrap_or(0);
        Ok(v)
    }

    fn scan_owners(
        &self,
        start: ContentId,
        end: ContentId,
    ) -> Result<Vec<(ContentId, Vec<ContentId>)>, KernelError> {
        let rtx = self.db.begin_read().map_err(|_| KernelError::Io)?;
        let table = rtx
            .open_multimap_table(OWNER_CONTEXTS)
            .map_err(|_| KernelError::Io)?;
        let mut out = Vec::new();
        let range = table
            .range::<[u8; 32]>(*start.as_bytes()..*end.as_bytes())
            .map_err(|_| KernelError::Io)?;
        for entry in range {
            let (key_guard, values) = entry.map_err(|_| KernelError::Io)?;
            let owner = ContentId::from_bytes(key_guard.value());
            let mut ctxs = Vec::new();
            for v in values {
                let guard = v.map_err(|_| KernelError::Io)?;
                ctxs.push(ContentId::from_bytes(guard.value()));
            }
            // redb liefert Multimap-Werte bereits aufsteigend in Key-Order; zur
            // Sicherheit (deterministischer Tiebreak, §5.2) erzwingen wir es.
            ctxs.sort_unstable();
            out.push((owner, ctxs));
        }
        Ok(out)
    }

    fn wipe(&mut self) -> Result<(), KernelError> {
        let mut wtx = self.db.begin_write().map_err(|_| KernelError::Io)?;
        wtx.set_durability(Durability::Immediate);
        {
            // Beide Multimap-Tabellen löschen (sie werden beim nächsten Öffnen neu
            // angelegt) und das Watermark auf 0 zurücksetzen — alles in einer
            // Transaktion (§8.4: Wipe ist atomar).
            wtx.delete_multimap_table(OWNER_CONTEXTS)
                .map_err(|_| KernelError::Io)?;
            wtx.delete_multimap_table(TARGET_REFERRERS)
                .map_err(|_| KernelError::Io)?;
            // Tabellen leer neu anlegen, damit Leser nach dem Wipe nie auf eine
            // fehlende Tabelle treffen.
            let _ = wtx
                .open_multimap_table(OWNER_CONTEXTS)
                .map_err(|_| KernelError::Io)?;
            let _ = wtx
                .open_multimap_table(TARGET_REFERRERS)
                .map_err(|_| KernelError::Io)?;
            let mut wm = wtx.open_table(WATERMARK).map_err(|_| KernelError::Io)?;
            wm.insert(WATERMARK_KEY, 0u64)
                .map_err(|_| KernelError::Io)?;
        }
        wtx.commit().map_err(|_| KernelError::Io)?;
        Ok(())
    }
}

/// Liest alle Multimap-Werte zu `key` als owned, aufsteigend sortierte
/// `ContentId`s (deterministischer Tiebreak, §5.2/§1.4).
fn read_multimap_values(
    table: &redb::ReadOnlyMultimapTable<[u8; 32], [u8; 32]>,
    key: ContentId,
) -> Result<Vec<ContentId>, KernelError> {
    let values = table.get(key.as_bytes()).map_err(|_| KernelError::Io)?;
    let mut out = Vec::new();
    for v in values {
        let guard = v.map_err(|_| KernelError::Io)?;
        out.push(ContentId::from_bytes(guard.value()));
    }
    out.sort_unstable();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cid(b: u8) -> ContentId {
        ContentId::from_bytes([b; 32])
    }

    fn open_index(dir: &std::path::Path) -> RedbEdgeIndex {
        RedbEdgeIndex::open(dir.join("index.redb")).expect("open index")
    }

    #[test]
    fn fresh_index_is_empty_with_zero_watermark() {
        let dir = tempdir().unwrap();
        let idx = open_index(dir.path());
        assert_eq!(idx.watermark().unwrap(), 0);
        assert!(idx.contexts_of(cid(0x01)).unwrap().is_empty());
        assert!(idx.referrers_of(cid(0x02)).unwrap().is_empty());
    }

    #[test]
    fn commit_records_both_directions() {
        // A besitzt B und C: owner(A)→{B,C}, referrer(B)→A, referrer(C)→A.
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        let a = cid(0x0A);
        let b = cid(0x0B);
        let c = cid(0x0C);
        idx.commit_edges(
            &[
                Edge { owner: a, context: b },
                Edge { owner: a, context: c },
            ],
            100,
        )
        .unwrap();

        assert_eq!(idx.contexts_of(a).unwrap(), vec![b, c]);
        assert_eq!(idx.referrers_of(b).unwrap(), vec![a]);
        assert_eq!(idx.referrers_of(c).unwrap(), vec![a]);
        assert_eq!(idx.watermark().unwrap(), 100);
    }

    #[test]
    fn multiple_owners_share_a_target() {
        // A und D besitzen beide B ⇒ referrer(B) → {A, D}.
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        let a = cid(0x0A);
        let d = cid(0x0D);
        let b = cid(0x0B);
        idx.commit_edges(
            &[
                Edge { owner: a, context: b },
                Edge { owner: d, context: b },
            ],
            50,
        )
        .unwrap();
        assert_eq!(idx.referrers_of(b).unwrap(), vec![a, d]);
    }

    #[test]
    fn watermark_advances_monotonically_and_rejects_regress() {
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        idx.commit_edges(&[], 10).unwrap();
        assert_eq!(idx.watermark().unwrap(), 10);
        idx.commit_edges(&[], 20).unwrap();
        assert_eq!(idx.watermark().unwrap(), 20);
        // Ein gleichbleibendes Watermark ist erlaubt (nicht-fallend).
        idx.commit_edges(&[], 20).unwrap();
        // Ein Rückschritt ist Inkonsistenz (§8.4-Invariante).
        assert!(matches!(
            idx.commit_edges(&[], 19),
            Err(KernelError::Inconsistent)
        ));
        assert_eq!(idx.watermark().unwrap(), 20);
    }

    #[test]
    fn wipe_clears_edges_and_watermark() {
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        let a = cid(0x0A);
        let b = cid(0x0B);
        idx.commit_edges(&[Edge { owner: a, context: b }], 99)
            .unwrap();
        assert!(!idx.contexts_of(a).unwrap().is_empty());
        idx.wipe().unwrap();
        assert!(idx.contexts_of(a).unwrap().is_empty());
        assert!(idx.referrers_of(b).unwrap().is_empty());
        assert_eq!(idx.watermark().unwrap(), 0);
    }

    #[test]
    fn reopen_recovers_edges_and_watermark() {
        let dir = tempdir().unwrap();
        let a = cid(0x0A);
        let b = cid(0x0B);
        {
            let mut idx = open_index(dir.path());
            idx.commit_edges(&[Edge { owner: a, context: b }], 77)
                .unwrap();
        }
        // Reopen: der durable Index ist da.
        let idx = open_index(dir.path());
        assert_eq!(idx.contexts_of(a).unwrap(), vec![b]);
        assert_eq!(idx.referrers_of(b).unwrap(), vec![a]);
        assert_eq!(idx.watermark().unwrap(), 77);
    }

    #[test]
    fn scan_owners_walks_the_address_range() {
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        let a = cid(0x10);
        let b = cid(0x20);
        let c = cid(0x30);
        idx.commit_edges(
            &[
                Edge { owner: a, context: cid(0xAA) },
                Edge { owner: b, context: cid(0xBB) },
                Edge { owner: c, context: cid(0xCC) },
            ],
            5,
        )
        .unwrap();
        // Halb-offenes Intervall [a, c): a und b, nicht c.
        let scanned = idx.scan_owners(a, c).unwrap();
        let owners: Vec<ContentId> = scanned.iter().map(|(o, _)| *o).collect();
        assert_eq!(owners, vec![a, b]);
        assert_eq!(scanned[0].1, vec![cid(0xAA)]);
    }

    #[test]
    fn duplicate_edge_is_idempotent() {
        // Dieselbe Kante zweimal committen ⇒ Multimap hält sie genau einmal.
        let dir = tempdir().unwrap();
        let mut idx = open_index(dir.path());
        let a = cid(0x0A);
        let b = cid(0x0B);
        idx.commit_edges(&[Edge { owner: a, context: b }], 1)
            .unwrap();
        idx.commit_edges(&[Edge { owner: a, context: b }], 2)
            .unwrap();
        assert_eq!(idx.contexts_of(a).unwrap(), vec![b]);
        assert_eq!(idx.referrers_of(b).unwrap(), vec![a]);
    }
}
