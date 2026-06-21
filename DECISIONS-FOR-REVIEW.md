# Decisions For Review — autonomer Nacht-Lauf

Protokoll der Entscheidungen, die während des autonomen Übernacht-Laufs getroffen
wurden. **Bitte morgens durchsehen.** Politik: Best-Default wählen + hier
markieren; nur bei wirklich unumkehrbaren Weichen anhalten und warten.

## Vom Nutzer vorab bestätigt (2026-06-22)
- **Kanonik (irreversibel):** RFC 8949 Kerndeterminismus, selbst erzwungen +
  Golden Vectors + zweiter unabhängiger Encoder als Gegenprobe in CI.
- **Checkpoints:** Branch `kernel-impl`, ein Commit pro grüner Phase (deutsche
  Messages, Repo-Stil), **kein Push**.
- **Gabelungen:** Best-Default + Eintrag hier; nur Unumkehrbares blockiert.
- **Qualität:** Fundament zuerst; jede committete Phase ist grün
  (`cargo build` + `cargo test` + `cargo clippy -D warnings`); adversarielle
  Review je Phase.
- **Sprache = Rust**, **Trust-Modell:** Embedding nur Einzel-Vertrauenszone,
  mandantenfähig ⇒ Daemon. **Performance:** erst messen (Benchmark-Gate Phase 1).

## Während des Laufs getroffen
_(wird ergänzt)_
