# Nacht-Fortschritt — lakearch Kernel

Branch: `kernel-impl` · Plan: `~/.claude/plans/lakearch-geht-in-die-indexed-sphinx.md`
· Gesetzbuch: `semantics/lakearch.md`

| Phase | Status | Commit | Notiz |
|---|---|---|---|
| 0 — Skeleton & Invarianten | ✅ Start | (scaffold) | Workspace + ContentId/AnchorId, build+test+clippy grün |
| 0.5 — Irreversibles einfrieren | ✅ | kernel-impl | eingefrorene kanonische CBOR (selbst erzwungen) + Golden Vectors + 2. Encoder, model/serialize/id, Tor-Typ-Skelett, API-Trait; build+test (45)+clippy -D warnings grün |
| 1 — Append + Store + Index + Betrieb | ✅ | kernel-impl | `pwrite`-Log + Read-mmap + Group-Commit + Recovery (HALT bei Korruption), redb-Kanten-Indizes (`owner→contexts`/`target→referrers`), Content-Store + Dedup (§5.3), Log-als-Wahrheit + Wipe-&-Rebuild, gegateter `get_by_content_id`, Betriebs-/Metrik-Basis; build+test (125)+clippy -D warnings grün |
| 2 — Traversierung + Tor-Logik | ✅ | kernel-impl | drei §1.3-Match-Prädikate (`content_equal`/`context_points_to`/`is_member_of_set`), beschränkte zyklensichere mechanische Traversierung (`traverse.rs`: Visited-Set §1.6, `max_depth`/`max_nodes`-Budget + Schritt-Budget, `CancelFlag`, deterministische aufsteigende `(to,edge_ctx,from)`-Adress-Order §5.2/§1.4, strukturelles `edge_type_filter` §3.3); Tor-Logik §11 (Bereichs-/Berechtigungs-/Entzugs-Modell als reine Konvention, in-memory neu-baubare Derivate, Filter-vor-Auflösen + VANISH, `get_by_content_id` kein Existenz-Orakel, fail-closed bei Korruption mit `fail_closed_count`-Metrik, sichtbarkeits-blinde Telemetrie); **Policy-Default no-area=unrestricted** (DECISIONS-FOR-REVIEW.md, bitte bestätigen); build+test (166: 143 lib + 12 Kanonik + 6 E2E + 5 Store)+clippy -D warnings grün |
| 3 — Bitemporal + Platzhalter | ⏳ | – | |
| 4 — Anker / referenzielle Identität | ⏳ | – | |
| 5 — Atomarität (Aktiv-Marker) | ⏳ | – | |
| 6 — Materialisierung & Invalidierung | ⏳ | – | |
| 7 — Daemon + Protokoll | ⏳ | – | |
| 8 — Föderation & Compaction | ⏳ | – | |

Legende: ✅ fertig/grün · ⏳ offen · 🔧 in Arbeit · ⛔ blockiert (siehe DECISIONS-FOR-REVIEW.md)
