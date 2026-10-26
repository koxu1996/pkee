//! Key slots: the key file, wrapped once per authenticator.
//!
//! Slots live next to the database, one JSON file each, so devices that add or
//! remove their own slot never touch the same file (no sync conflicts):
//!
//! ```text
//! ~/Sync/main.kdbx
//! ~/Sync/main.kdbx.slots/air.json
//! ~/Sync/main.kdbx.slots/workstation.json
//! ```
//!
//! A slot's key is HKDF-SHA256 of the authenticator's `hmac-secret` output for
//! the slot's salt; it seals the key file with AES-256-GCM. The slot's fields
//! (all but the label) are the AEAD's associated data, so editing them makes
//! the slot fail to open rather than open to something else.

use crate::fido::{self, Authenticator};
use crate::keyfile::KeyFile;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::Nonce;
use anyhow::{Context, Result, anyhow, bail};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Format version, also bound into the key derivation and associated data.
const VERSION: u32 = 1;
const KIND_FIDO2: &str = "fido2-hmac-secret";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub v: u32,
    /// File stem; unique within the slots directory.
    pub id: String,
    /// Free text, e.g. "MacBook Air". Not authenticated: renaming is harmless.
    pub label: String,
    pub kind: String,
    /// Device name at enrolment, for display.
    pub authenticator: String,
    pub rp_id: String,
    #[serde(with = "b64")]
    pub cred_id: Vec<u8>,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

impl Slot {
    /// Create a credential on `auth` (one fingerprint to create it, one to
    /// derive its secret) and seal `key` with it.
    pub fn create(auth: &dyn Authenticator, id: &str, label: &str, prompt: &str, key: &KeyFile) -> Result<Self> {
        let cred_id = auth.create_credential(prompt)?;
        let mut slot = Slot {
            v: VERSION,
            id: id.to_owned(),
            label: label.to_owned(),
            kind: KIND_FIDO2.to_owned(),
            authenticator: auth.name().to_owned(),
            rp_id: fido::RP_ID.to_owned(),
            cred_id,
            salt: fido::random::<32>()?.to_vec(),
            nonce: fido::random::<12>()?.to_vec(),
            ct: Vec::new(),
        };
        let secret = auth.hmac_secret(&slot.cred_id, &slot.salt()?)?;
        slot.ct = slot
            .cipher(&secret)?
            .encrypt(&slot.nonce()?, Payload { msg: key.as_bytes(), aad: &slot.aad() })
            .map_err(|_| anyhow!("sealing the key file failed"))?;
        Ok(slot)
    }

    /// Unwrap the key file with `auth` (one fingerprint).
    pub fn open(&self, auth: &dyn Authenticator) -> Result<KeyFile> {
        self.check_supported()?;
        let secret = auth.hmac_secret(&self.cred_id, &self.salt()?)?;
        let plain = Zeroizing::new(
            self.cipher(&secret)?
                .decrypt(&self.nonce()?, Payload { msg: &self.ct, aad: &self.aad() })
                .map_err(|_| anyhow!("slot {}: wrong authenticator or tampered slot", self.id))?,
        );
        let key = <[u8; 32]>::try_from(plain.as_slice())
            .map_err(|_| anyhow!("slot {}: sealed key is not 32 bytes", self.id))?;
        Ok(KeyFile::from_bytes(key))
    }

    fn check_supported(&self) -> Result<()> {
        if self.v != VERSION || self.kind != KIND_FIDO2 {
            bail!("slot {}: unsupported (v{} {})", self.id, self.v, self.kind);
        }
        Ok(())
    }

    fn salt(&self) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(self.salt.as_slice()).map_err(|_| anyhow!("slot {}: salt is not 32 bytes", self.id))
    }

    fn nonce(&self) -> Result<Nonce<Aes256Gcm>> {
        Nonce::<Aes256Gcm>::try_from(self.nonce.as_slice()).map_err(|_| anyhow!("slot {}: nonce is not 12 bytes", self.id))
    }

    fn cipher(&self, secret: &[u8; 32]) -> Result<Aes256Gcm> {
        let mut kek = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, secret)
            .expand(b"pkee/slot/v1/kek", kek.as_mut())
            .map_err(|_| anyhow!("hkdf"))?;
        Ok(Aes256Gcm::new_from_slice(kek.as_ref()).expect("32-byte key"))
    }

    /// Every field but the label and the ciphertext, length-prefixed.
    fn aad(&self) -> Vec<u8> {
        let mut aad = b"pkee/slot".to_vec();
        aad.extend_from_slice(&self.v.to_be_bytes());
        for field in [
            self.id.as_bytes(),
            self.kind.as_bytes(),
            self.rp_id.as_bytes(),
            &self.cred_id,
            &self.salt,
            &self.nonce,
        ] {
            aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }
}

/// The slots directory of one database: `<db>.slots/`.
pub struct Slots {
    dir: PathBuf,
}

impl Slots {
    pub fn for_db(db: &Path) -> Self {
        let mut dir = db.as_os_str().to_owned();
        dir.push(".slots");
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// All slots, sorted by id. Files that don't parse are reported, not skipped
    /// silently: a broken slot is something the user should know about.
    pub fn list(&self) -> Result<Vec<Slot>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        let mut slots = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let slot: Slot = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
            if path.file_stem().is_none_or(|s| s != slot.id.as_str()) {
                bail!("{}: file name does not match slot id {:?}", path.display(), slot.id);
            }
            slots.push(slot);
        }
        slots.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(slots)
    }

    /// Write a new slot. Never overwrites: the temp file is linked into place,
    /// which fails if the id is taken.
    pub fn add(&self, slot: &Slot) -> Result<PathBuf> {
        valid_id(&slot.id)?;
        std::fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
        let path = self.path(&slot.id);
        let tmp = self.dir.join(format!(".{}.json.tmp", slot.id));
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(serde_json::to_string_pretty(slot)?.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        let linked = std::fs::hard_link(&tmp, &path);
        std::fs::remove_file(&tmp)?;
        linked.with_context(|| format!("slot {:?} already exists ({})", slot.id, path.display()))?;
        Ok(path)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        valid_id(id)?;
        let path = self.path(id);
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
    }

    /// An id not yet used, based on `label`: "MacBook Air" → "macbook-air",
    /// then "macbook-air-2", …
    pub fn free_id(&self, label: &str) -> Result<String> {
        let base: String = label
            .to_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let base = if base.is_empty() { "slot".to_owned() } else { base };
        let taken: Vec<String> = self.list()?.into_iter().map(|s| s.id).collect();
        Ok((1..)
            .map(|n| if n == 1 { base.clone() } else { format!("{base}-{n}") })
            .find(|id| !taken.contains(id))
            .expect("unbounded"))
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }
}

/// Ids become file names: keep them boring.
fn valid_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        bail!("invalid slot id {id:?}: use a-z, 0-9 and '-'");
    }
    Ok(())
}

/// Find a slot one of `auths` can open, and open it. Ownership is probed
/// silently first, so only the matching device asks for a fingerprint.
pub fn unlock(slots: &[Slot], auths: &[impl Authenticator]) -> Result<(KeyFile, Slot)> {
    if slots.is_empty() {
        bail!("no slots: run `pkee init` or `pkee slot add`");
    }
    if auths.is_empty() {
        bail!("no FIDO2 authenticator with hmac-secret found (is linux-passkey running?)");
    }
    for auth in auths {
        for slot in slots.iter().filter(|s| s.kind == KIND_FIDO2) {
            if auth.owns(&slot.cred_id)? {
                return Ok((slot.open(auth)?, slot.clone()));
            }
        }
    }
    bail!(
        "none of the {} slot(s) belongs to a connected authenticator ({})",
        slots.len(),
        auths.iter().map(|a| a.name()).collect::<Vec<_>>().join(", ")
    )
}

mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::hmac::{Hmac, Mac};

    /// Stands in for a FIDO2 device: hmac-secret is HMAC-SHA256(device secret ‖ cred, salt).
    struct FakeAuth {
        secret: [u8; 32],
        creds: std::cell::RefCell<Vec<Vec<u8>>>,
    }

    impl FakeAuth {
        fn new(secret: u8) -> Self {
            Self { secret: [secret; 32], creds: Default::default() }
        }
    }

    impl Authenticator for FakeAuth {
        fn name(&self) -> &str {
            "fake"
        }
        fn create_credential(&self, _label: &str) -> Result<Vec<u8>> {
            let id = fido::random::<16>()?.to_vec();
            self.creds.borrow_mut().push(id.clone());
            Ok(id)
        }
        fn owns(&self, cred_id: &[u8]) -> Result<bool> {
            Ok(self.creds.borrow().iter().any(|c| c == cred_id))
        }
        fn hmac_secret(&self, cred_id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
            if !self.owns(cred_id)? {
                bail!("CTAP2_ERR_NO_CREDENTIALS");
            }
            let mut mac = Hmac::<Sha256>::new_from_slice(&[&self.secret[..], cred_id].concat()).unwrap();
            mac.update(salt);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pkee-test-{}", hex::encode(fido::random::<8>().unwrap())));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn seal_and_open() {
        let auth = FakeAuth::new(1);
        let key = KeyFile::generate().unwrap();
        let slot = Slot::create(&auth, "air", "Air", "test", &key).unwrap();
        assert_eq!(slot.open(&auth).unwrap(), key);
    }

    #[test]
    fn tampering_fails() {
        let auth = FakeAuth::new(1);
        let key = KeyFile::generate().unwrap();
        let slot = Slot::create(&auth, "air", "Air", "test", &key).unwrap();

        let mut renamed = slot.clone();
        renamed.id = "other".into();
        assert!(renamed.open(&auth).is_err());

        let mut flipped = slot.clone();
        flipped.ct[0] ^= 1;
        assert!(flipped.open(&auth).is_err());

        let mut relabelled = slot.clone();
        relabelled.label = "Renamed".into();
        assert_eq!(relabelled.open(&auth).unwrap(), key);
    }

    #[test]
    fn unlock_picks_the_owning_device() {
        let (air, ws) = (FakeAuth::new(1), FakeAuth::new(2));
        let key = KeyFile::generate().unwrap();
        let slots = vec![
            Slot::create(&air, "air", "Air", "test", &key).unwrap(),
            Slot::create(&ws, "ws", "Workstation", "test", &key).unwrap(),
        ];
        let (got, slot) = unlock(&slots, &[ws]).unwrap();
        assert_eq!((got, slot.id.as_str()), (key, "ws"));
        assert!(unlock(&slots, &[FakeAuth::new(3)]).is_err());
    }

    #[test]
    fn directory() {
        let dir = tempdir();
        let slots = Slots::for_db(&dir.join("main.kdbx"));
        assert!(slots.list().unwrap().is_empty());
        assert_eq!(slots.free_id("MacBook Air").unwrap(), "macbook-air");

        let auth = FakeAuth::new(1);
        let key = KeyFile::generate().unwrap();
        let slot = Slot::create(&auth, "macbook-air", "MacBook Air", "test", &key).unwrap();
        slots.add(&slot).unwrap();
        assert!(slots.add(&slot).is_err(), "never overwrites");
        assert_eq!(slots.free_id("MacBook Air").unwrap(), "macbook-air-2");

        let listed = slots.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].open(&auth).unwrap(), key);

        slots.remove("macbook-air").unwrap();
        assert!(slots.list().unwrap().is_empty());
        assert!(slots.remove("../main").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
