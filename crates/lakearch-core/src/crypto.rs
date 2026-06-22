//! **Crypto-Shredding** (§15/§9.5, Plan „Compaction/DSGVO") — die bevorzugte
//! Lösch-Form für das „Recht auf Vergessen": die erasbare Nutzlast wird mit einem
//! **pro-Lösch-Schlüssel** versiegelt (eine pure-Rust AEAD, ChaCha20-Poly1305);
//! das **Zerstören des Schlüssels** macht die Bytes **unrückholbar**, während die
//! [`ContentId`] und alle Kanten **intakt** bleiben (§3.6: geschlossene Verweise —
//! eine Traversierung, die einen erasten Knoten erreicht, trifft einen
//! Tombstone/Platzhalter, **keine** baumelnde Lücke).
//!
//! Maßgeblich: der gehärtete Plan (Abschnitt „Storage-Engine, Compaction/DSGVO,
//! Scale-out": „Crypto-Shredding bevorzugen … Schlüssel zerstören macht Bytes
//! unrückholbar, ContentId/Kanten bleiben → §3.6 gewahrt, Löschung O(1)") und das
//! Gesetzbuch `semantics/lakearch.md` (§15 Compaction; §9.5 Kuratierung;
//! §3.6 referenzielle Geschlossenheit).
//!
//! ## Reine, deterministische AEAD (kein Wall-Clock, kein Random)
//!
//! Damit Compaction **reproduzierbar** und der Bestand **föderationsstabil** bleibt
//! (§12.3/§Append-Order-Semantik), ist das Versiegeln eine **reine Funktion** von
//! `(Schlüssel, ContentId, kanonische Bytes)`: der 12-Byte-Nonce wird
//! **deterministisch** aus der `ContentId` abgeleitet (sie ist je versiegeltem Daten
//! eindeutig → kein Nonce-Reuse über verschiedene Daten unter **demselben**
//! Schlüssel), **kein** `getrandom`, **keine** Uhr. Ein erneutes Versiegeln
//! desselben Daten unter demselben Schlüssel liefert **byte-gleiche** Chiffre.
//!
//! ## Die Lösch-Garantie
//!
//! - **Versiegelt** ([`seal`]): Chiffre = AEAD(Schlüssel, Nonce(ContentId), Bytes).
//!   Die Klartext-Bytes existieren danach **nirgends** mehr im compactierten
//!   Segment — nur die Chiffre.
//! - **Geöffnet** ([`open`]): mit dem **lebenden** Schlüssel liefert die AEAD die
//!   Klartext-Bytes zurück (Integrität per Poly1305-Tag geprüft).
//! - **Geschreddert:** ist der Schlüssel **zerstört** (aus dem Keystore entfernt),
//!   gibt es **keinen** Weg mehr zu den Bytes — [`open`] ist nicht mehr aufrufbar,
//!   die `ContentId` bleibt als **Tombstone** (Adresse + Kanten, §3.6) erhalten.
//!
//! Dieses Modul ist `#![forbid(unsafe_code)]`: es nutzt allein die sichere
//! `chacha20poly1305`-API und `Vec<u8>`/`[u8; N]`.

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::KernelError;
use crate::id::ContentId;

/// Länge eines **Lösch-Schlüssels** (§Crypto-Shredding) in Bytes — der
/// ChaCha20-Poly1305-Schlüssel (256 bit).
pub const ERASURE_KEY_LEN: usize = 32;

/// Domain-Tag der **assoziierten Daten** (AEAD AAD, §K5.1-Analogon): bindet jede
/// Chiffre an genau **diese** `ContentId`, sodass ein Vertauschen der Chiffren
/// zweier erasbarer Daten (selber Schlüssel) das Poly1305-Tag bricht. Eingefroren;
/// **niemals** ändern (verschöbe die Entschlüsselbarkeit aller versiegelten
/// Nutzlasten).
const SHRED_AAD_TAG: &[u8; 21] = b"lakearch/shred/aad/v1";

/// Domain-Tag der **deterministischen Nonce-Ableitung**: der 12-Byte-Nonce wird als
/// die ersten 12 Bytes von `BLAKE3(NONCE_TAG || ContentId)` gebildet — eine reine
/// Funktion der `ContentId` (eindeutig je Daten), **kein** Random/keine Uhr.
/// Eingefroren.
const SHRED_NONCE_TAG: &[u8; 23] = b"lakearch/shred/nonce/v1";

/// Ein **Lösch-Schlüssel** (§Crypto-Shredding) — der pro-Lösch-Schlüssel, der eine
/// erasbare Nutzlast versiegelt. **Sensibel:** wird er aus dem Keystore entfernt
/// (zerstört), sind die zugehörigen Bytes unrückholbar (das **ist** die Löschung,
/// O(1)). Der Schlüssel selbst ist **kein** Daten (er geht **nie** ins Log, §8.4 —
/// das Log ist der unveränderliche, replizierbare Inhalt; der Schlüssel lebt im
/// Keystore, der zerstört werden darf).
#[derive(Clone, PartialEq, Eq)]
pub struct ErasureKey([u8; ERASURE_KEY_LEN]);

impl ErasureKey {
    /// Konstruiert einen Schlüssel aus 32 rohen Bytes. Die **Erzeugung** frischer
    /// Schlüssel (Zufalls-Quelle) liegt bewusst in der **Schicht darüber** / im
    /// Daemon (sie kennt die Schlüssel-Politik, §8.4: der Kernel rechnet/wertet
    /// nicht, §1.4) — der Kernel **hält und benutzt** den Schlüssel nur.
    pub fn from_bytes(bytes: [u8; ERASURE_KEY_LEN]) -> Self {
        ErasureKey(bytes)
    }

    /// **Deterministische** Schlüssel-Ableitung aus einem opaken Geheimnis (z. B.
    /// einem pro-Subjekt-Master-Geheimnis der Schicht darüber) **und** der erasbaren
    /// `ContentId`: `key = BLAKE3(secret || ContentId)`. So ist die Schlüssel-Vergabe
    /// reproduzierbar (kein Random nötig), und ein Lösch-Schlüssel ist pro Daten
    /// distinkt (kein Nonce-Reuse-Risiko selbst bei naiver Nonce). Die Schicht
    /// darüber wählt die Granularität (ein Schlüssel je Subjekt/Datensatz).
    pub fn derive(secret: &[u8], content_id: ContentId) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(secret);
        h.update(content_id.as_bytes());
        ErasureKey(*h.finalize().as_bytes())
    }

    /// Die rohen Schlüssel-Bytes (für den persistenten Keystore). Bewusst `pub(crate)`:
    /// der Schlüssel verlässt das Crate nicht versehentlich.
    pub(crate) fn as_bytes(&self) -> &[u8; ERASURE_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for ErasureKey {
    /// Sichtbarkeits-blind (§11.3): der Schlüssel-Wert wird **nie** in Logs/Debug
    /// ausgegeben (sonst wäre die Crypto-Shred-Garantie wertlos).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ErasureKey(<redacted>)")
    }
}

/// **seal** (§Crypto-Shredding) — versiegelt die kanonischen Bytes `plaintext` eines
/// Daten `id` unter dem Lösch-Schlüssel `key`. Liefert die Chiffre (inkl.
/// angehängtem Poly1305-Tag). Reine Funktion von `(key, id, plaintext)` — der Nonce
/// ist **deterministisch** aus `id` abgeleitet (kein Random, keine Uhr), die `id`
/// dient zugleich als AEAD-AAD (bindet die Chiffre an genau dieses Daten).
///
/// Der Klartext existiert nach dem Versiegeln **nicht** mehr im compactierten
/// Segment — nur die Chiffre. Zerstört der Operator später den Schlüssel, sind die
/// Bytes unrückholbar (die `ContentId`/Kanten bleiben, §3.6).
pub fn seal(key: &ErasureKey, id: ContentId, plaintext: &[u8]) -> Result<Vec<u8>, KernelError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = derive_nonce(id);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(id),
            },
        )
        .map_err(|_| KernelError::Inconsistent)
}

/// **open** (§Crypto-Shredding) — entsiegelt eine Chiffre `ciphertext` des Daten
/// `id` mit dem **lebenden** Schlüssel `key`. Liefert die kanonischen Klartext-
/// Bytes; ein gebrochenes Poly1305-Tag (falscher Schlüssel, vertauschte/verfälschte
/// Chiffre) ⇒ [`KernelError::Inconsistent`] (fail-closed §11). Ist der Schlüssel
/// **zerstört**, gibt es **keinen** Aufrufer mehr (die Bytes sind geschreddert).
pub fn open(key: &ErasureKey, id: ContentId, ciphertext: &[u8]) -> Result<Vec<u8>, KernelError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = derive_nonce(id);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(id),
            },
        )
        .map_err(|_| KernelError::Inconsistent)
}

/// Die **AEAD-AAD** für ein Daten `id`: `SHRED_AAD_TAG || ContentId`. Bindet die
/// Chiffre an genau dieses Daten (Vertauschen bricht das Tag).
fn aad(id: ContentId) -> Vec<u8> {
    let mut v = Vec::with_capacity(SHRED_AAD_TAG.len() + 32);
    v.extend_from_slice(SHRED_AAD_TAG);
    v.extend_from_slice(id.as_bytes());
    v
}

/// **Deterministische** 12-Byte-Nonce-Ableitung aus der `ContentId`: die ersten 12
/// Bytes von `BLAKE3(SHRED_NONCE_TAG || ContentId)`. Eindeutig je Daten (die
/// `ContentId` ist eindeutig), daher **kein** Nonce-Reuse über verschiedene Daten
/// unter demselben Schlüssel. Reine Funktion — kein Random, keine Uhr.
fn derive_nonce(id: ContentId) -> [u8; 12] {
    let mut h = blake3::Hasher::new();
    h.update(SHRED_NONCE_TAG);
    h.update(id.as_bytes());
    let full = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full.as_bytes()[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Datum;

    fn id_of(bytes: &[u8]) -> ContentId {
        ContentId::of_datum(&Datum::leaf(bytes.to_vec()))
    }

    #[test]
    fn seal_open_round_trips_with_living_key() {
        let key = ErasureKey::from_bytes([0x11; 32]);
        let id = id_of(b"sensibel");
        let pt = b"streng-geheime-nutzlast".to_vec();
        let ct = seal(&key, id, &pt).expect("seal");
        // Die Chiffre ist NICHT der Klartext.
        assert_ne!(ct, pt);
        // Mit dem lebenden Schlüssel: Klartext zurück.
        assert_eq!(open(&key, id, &ct).expect("open"), pt);
    }

    #[test]
    fn seal_is_deterministic_pure_function() {
        // Reine Funktion (kein Random/keine Uhr): zweimal versiegeln ⇒ byte-gleich.
        let key = ErasureKey::from_bytes([0x22; 32]);
        let id = id_of(b"d");
        let a = seal(&key, id, b"x").expect("a");
        let b = seal(&key, id, b"x").expect("b");
        assert_eq!(a, b, "deterministisch ⇒ reproduzierbare Compaction (§12.3)");
    }

    #[test]
    fn shredded_bytes_are_unrecoverable_with_wrong_key() {
        // §Crypto-Shredding: ein zerstörter (= nicht mehr verfügbarer) Schlüssel
        // wird hier durch einen FALSCHEN Schlüssel modelliert: kein Weg zu den Bytes.
        let key = ErasureKey::from_bytes([0x33; 32]);
        let id = id_of(b"d");
        let ct = seal(&key, id, b"vergiss-mich").expect("seal");
        let wrong = ErasureKey::from_bytes([0x44; 32]);
        assert!(open(&wrong, id, &ct).is_err(), "falscher Schlüssel ⇒ unrückholbar");
    }

    #[test]
    fn ciphertext_is_bound_to_its_content_id() {
        // Die AAD bindet die Chiffre an genau diese ContentId: Entsiegeln unter einer
        // ANDEREN id (selber Schlüssel) bricht das Poly1305-Tag.
        let key = ErasureKey::from_bytes([0x55; 32]);
        let id1 = id_of(b"daten-1");
        let id2 = id_of(b"daten-2");
        let ct = seal(&key, id1, b"p").expect("seal");
        assert!(open(&key, id2, &ct).is_err(), "Chiffre an ihre ContentId gebunden");
    }

    #[test]
    fn derive_key_is_deterministic_and_per_datum() {
        let id1 = id_of(b"a");
        let id2 = id_of(b"b");
        let k1 = ErasureKey::derive(b"master", id1);
        let k1b = ErasureKey::derive(b"master", id1);
        let k2 = ErasureKey::derive(b"master", id2);
        assert_eq!(k1, k1b, "deterministische Ableitung");
        assert_ne!(k1, k2, "pro Daten distinkt");
    }

    #[test]
    fn debug_redacts_key_material() {
        let key = ErasureKey::from_bytes([0x66; 32]);
        let s = format!("{key:?}");
        assert!(s.contains("redacted"), "Schlüssel-Wert nie im Debug (§11.3)");
        assert!(!s.contains("66"));
    }
}
