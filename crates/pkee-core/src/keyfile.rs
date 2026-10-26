//! The database's only credential: a 32-byte KeePass key file.
//!
//! pkee writes the KeePass XML 2.0 format (what KeePassXC generates as `.keyx`):
//! hex text with a short SHA-256 check, so it can be printed as a paper backup
//! and typed back in. Any key file KeePassXC accepts can be imported.

use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A key file's 32-byte key: what KeePass hashes into the composite key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyFile([u8; 32]);

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyFile(..)")
    }
}

impl KeyFile {
    /// A fresh random key.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::fido::random::<32>()?))
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a key file the way KeePass does: XML (2.0 hex with its hash
    /// checked, or 1.0 base64), then 32 raw bytes, then 64 hex characters, and
    /// otherwise the SHA-256 of the whole file.
    pub fn parse(file: &[u8]) -> Result<Self> {
        if let Some(key) = parse_xml(file)? {
            return Ok(key);
        }
        if let Ok(raw) = <[u8; 32]>::try_from(file) {
            return Ok(Self(raw));
        }
        if file.len() == 64 {
            let mut key = [0u8; 32];
            if hex::decode_to_slice(file, &mut key).is_ok() {
                return Ok(Self(key));
            }
        }
        Ok(Self(Sha256::digest(file).into()))
    }

    /// KeePass XML key file, version 2.0.
    pub fn to_xml(&self) -> Zeroizing<String> {
        let hex = Zeroizing::new(hex::encode_upper(self.0));
        let mut xml = Zeroizing::new(String::new());
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n");
        xml.push_str("    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n");
        let _ = writeln!(xml, "    <Key>\n        <Data Hash=\"{}\">", self.check());
        for line in hex.as_bytes().chunks(32) {
            let groups: Vec<&str> = line
                .chunks(8)
                .map(|g| std::str::from_utf8(g).unwrap_or_default())
                .collect();
            let _ = writeln!(xml, "            {}", groups.join(" "));
        }
        xml.push_str("        </Data>\n    </Key>\n</KeyFile>\n");
        xml
    }

    /// The 2.0 format's `Hash` attribute: first 4 bytes of SHA-256, upper hex.
    fn check(&self) -> String {
        hex::encode_upper(&Sha256::digest(self.0)[..4])
    }
}

/// `Ok(None)` if `file` isn't a KeePass XML key file at all.
fn parse_xml(file: &[u8]) -> Result<Option<KeyFile>> {
    let Ok(text) = std::str::from_utf8(file) else {
        return Ok(None);
    };
    if !text.contains("<KeyFile>") {
        return Ok(None);
    }
    let version = between(text, "<Version>", "</Version>").map(str::trim);
    let data_tag = between(text, "<Data", ">").ok_or_else(|| anyhow!("key file has no <Data>"))?;
    let data = between(text, &format!("<Data{data_tag}>"), "</Data>")
        .ok_or_else(|| anyhow!("key file has no <Data>"))?;
    let data: Zeroizing<String> = Zeroizing::new(data.chars().filter(|c| !c.is_whitespace()).collect());

    match version {
        Some("2.0") => {
            let mut key = [0u8; 32];
            hex::decode_to_slice(data.as_bytes(), &mut key)
                .map_err(|_| anyhow!("key file data is not 32 bytes of hex"))?;
            let key = KeyFile(key);
            if let Some(hash) = between(data_tag, "Hash=\"", "\"") {
                if !hash.eq_ignore_ascii_case(&key.check()) {
                    bail!("key file hash mismatch: a typo in the hex?");
                }
            }
            Ok(Some(key))
        }
        Some("1.0") | None => {
            use base64::Engine as _;
            let raw = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(data.as_bytes())
                    .map_err(|_| anyhow!("key file 1.0 data is not base64"))?,
            );
            let key = <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| anyhow!("key file 1.0 data is not 32 bytes"))?;
            Ok(Some(KeyFile(key)))
        }
        Some(v) => bail!("unsupported key file version {v}"),
    }
}

/// The text between the first `start` and the following `end`.
fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = s.find(start)? + start.len();
    let len = s[from..].find(end)?;
    Some(&s[from..from + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_round_trip() {
        let key = KeyFile::generate().unwrap();
        assert_eq!(KeyFile::parse(key.to_xml().as_bytes()).unwrap(), key);
    }

    /// Byte for byte what `keepassxc-cli db-create --set-key-file` (2.7.12) writes.
    #[test]
    fn xml_layout_matches_keepassxc() {
        let keepassxc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash=\"9A2DB2E2\">
            ABABABAB ABABABAB ABABABAB ABABABAB
            ABABABAB ABABABAB ABABABAB ABABABAB
        </Data>
    </Key>
</KeyFile>
";
        let key = KeyFile::from_bytes([0xab; 32]);
        assert_eq!(key.to_xml().as_str(), keepassxc);
        assert_eq!(KeyFile::parse(keepassxc.as_bytes()).unwrap(), key);
    }

    #[test]
    fn xml_typo_is_caught() {
        let key = KeyFile::from_bytes([0x11; 32]);
        let xml = key.to_xml().replacen("11111111", "11111112", 1);
        assert!(KeyFile::parse(xml.as_bytes()).is_err());
    }

    #[test]
    fn other_formats() {
        let raw = [7u8; 32];
        assert_eq!(KeyFile::parse(&raw).unwrap().as_bytes(), &raw);
        let hex = hex::encode(raw);
        assert_eq!(KeyFile::parse(hex.as_bytes()).unwrap().as_bytes(), &raw);
        let bare = b"any file at all";
        assert_eq!(KeyFile::parse(bare).unwrap().as_bytes(), &<[u8; 32]>::from(Sha256::digest(bare)));
    }

    /// keepass-rs reads our bytes the same way KeePassXC reads the XML.
    #[test]
    fn opens_database() {
        let key = KeyFile::generate().unwrap();
        let mut db = keepass::Database::new();
        db.root_mut().add_entry().edit(|e| e.set_unprotected("Title", "hello"));
        let mut buf = Vec::new();
        db.save(&mut buf, crate::db::database_key(&key)).unwrap();

        let db = crate::db::open_bytes(&buf, &key).unwrap();
        assert_eq!(db.num_entries(), 1);
        let other = KeyFile::generate().unwrap();
        assert!(crate::db::open_bytes(&buf, &other).is_err());
    }
}
