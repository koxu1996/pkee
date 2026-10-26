//! Frecency: how often and how recently each entry was used.
//!
//! Each use adds 1 to a score that halves every [`HALF_LIFE`]: an entry used
//! daily stays near the top, one used a lot last year fades. Stored per
//! database (see [`crate::paths::frecency_file`]), keyed by entry UUID, outside the KDBX
//! so using an entry never rewrites (and re-syncs) the database.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Seconds for a score to halve.
pub const HALF_LIFE: f64 = 7.0 * 24.0 * 3600.0;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Use {
    /// Score as of `at`.
    score: f64,
    /// Unix seconds of the last use.
    at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Frecency {
    entries: HashMap<String, Use>,
}

impl Frecency {
    /// Record a use of `uuid` at `now` (unix seconds).
    pub fn record(&mut self, uuid: &str, now: u64) {
        let score = self.score(uuid, now) + 1.0;
        self.entries.insert(uuid.to_owned(), Use { score, at: now });
    }

    /// The decayed score of `uuid` at `now`; 0 if never used.
    pub fn score(&self, uuid: &str, now: u64) -> f64 {
        self.entries.get(uuid).map_or(0.0, |u| {
            let age = now.saturating_sub(u.at) as f64;
            u.score * (-age / HALF_LIFE).exp2()
        })
    }

    /// Drop entries that are gone from the database or have faded to nothing.
    pub fn prune(&mut self, live: impl Fn(&str) -> bool, now: u64) {
        let faded: Vec<String> = self
            .entries
            .keys()
            .filter(|k| !live(k) || self.score(k, now) < 0.01)
            .cloned()
            .collect();
        for k in faded {
            self.entries.remove(&k);
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write via a temp file and rename, so a crash never leaves half a file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(self)?).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;

    #[test]
    fn decays_and_accumulates() {
        let mut f = Frecency::default();
        let t = 1_000_000_000;
        f.record("a", t);
        f.record("a", t);
        assert!((f.score("a", t) - 2.0).abs() < 1e-9);
        assert!((f.score("a", t + 7 * DAY) - 1.0).abs() < 1e-9, "halves in a week");
        assert_eq!(f.score("never", t), 0.0);
    }

    #[test]
    fn recent_use_beats_old_habit() {
        let mut f = Frecency::default();
        let t = 1_000_000_000;
        for i in 0..10 {
            f.record("old", t + i);
        }
        f.record("new", t + 60 * DAY);
        assert!(f.score("new", t + 60 * DAY) > f.score("old", t + 60 * DAY));
    }

    #[test]
    fn prune_and_round_trip() {
        let dir = std::env::temp_dir().join(format!("pkee-frec-{}", hex::encode(crate::fido::random::<8>().unwrap())));
        let path = dir.join("f.json");
        let mut f = Frecency::default();
        f.record("keep", 0);
        f.record("gone", 0);
        f.prune(|k| k == "keep", 0);
        f.save(&path).unwrap();
        let g = Frecency::load(&path).unwrap();
        assert_eq!(g.score("keep", 0), 1.0);
        assert_eq!(g.score("gone", 0), 0.0);
        assert!(Frecency::load(&dir.join("missing.json")).unwrap().entries.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
