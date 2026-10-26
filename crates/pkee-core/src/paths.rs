//! Where pkee keeps per-database state and its agent socket.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A short id for a database: hash of its canonical path. Keeps state for
/// different databases apart without putting their paths in file names.
pub fn db_id(db: &Path) -> String {
    let db = std::fs::canonicalize(db).unwrap_or_else(|_| db.to_owned());
    hex::encode(&Sha256::digest(db.as_os_str().as_encoded_bytes())[..8])
}

/// `$XDG_STATE_HOME/pkee` (default `~/.local/state/pkee`).
pub fn state_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".local/state"),
    };
    Ok(base.join("pkee"))
}

/// `$XDG_RUNTIME_DIR/pkee`: per-user, tmpfs, gone at logout.
pub fn runtime_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .context("XDG_RUNTIME_DIR is not set")?;
    Ok(PathBuf::from(base).join("pkee"))
}

pub fn frecency_file(db: &Path) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("frecency-{}.json", db_id(db))))
}

pub fn agent_socket(db: &Path) -> Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("agent-{}.sock", db_id(db))))
}
