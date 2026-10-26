//! Wayland clipboard for secrets: marked sensitive so clipboard managers skip
//! it, served from the agent so the popup can close at once, and cleared after
//! a while unless something else was copied since.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use wl_clipboard_rs::copy::{self, ClipboardType, MimeType, Options, Seat, Source};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Clipboard {
    /// Bumped on every copy, so a timer only clears its own copy.
    generation: Arc<AtomicU64>,
}

impl Clipboard {
    pub fn copy(&self, text: Zeroizing<String>, clear_after: Duration) -> Result<()> {
        let mut opts = Options::new();
        // Serve in our thread (below) rather than a forked process we can't track.
        opts.foreground(true).sensitive(true);
        // Prepare here so "no Wayland" fails the request, not a background thread.
        let prepared = opts
            .prepare_copy(Source::Bytes(text.as_bytes().into()), MimeType::Text)
            .context("Wayland clipboard")?;
        drop(text);

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let replaced = Arc::new(AtomicBool::new(false));
        std::thread::spawn({
            let replaced = replaced.clone();
            move || {
                // Returns once another selection replaces ours.
                let _ = prepared.serve();
                replaced.store(true, Ordering::SeqCst);
            }
        });
        let current = self.generation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(clear_after);
            if !replaced.load(Ordering::SeqCst) && current.load(Ordering::SeqCst) == generation {
                let _ = copy::clear(ClipboardType::Regular, Seat::All);
            }
        });
        Ok(())
    }
}
