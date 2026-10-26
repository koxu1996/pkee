//! Opening a KDBX database with a key file and no password.

use crate::keyfile::KeyFile;
use anyhow::{Context, Result};
use keepass::{Database, DatabaseKey};
use std::path::Path;

/// The KeePass composite key for a key-file-only database.
pub fn database_key(key: &KeyFile) -> DatabaseKey {
    // keepass-rs takes 32 raw bytes as the key itself, the same value KeePassXC
    // gets from the XML file's hex.
    DatabaseKey::new()
        .with_keyfile(&mut &key.as_bytes()[..])
        .expect("reading from a slice cannot fail")
}

pub fn open(path: &Path, key: &KeyFile) -> Result<Database> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    open_bytes(&data, key).with_context(|| format!("opening {}", path.display()))
}

pub fn open_bytes(data: &[u8], key: &KeyFile) -> Result<Database> {
    Ok(Database::parse(data, database_key(key))?)
}
