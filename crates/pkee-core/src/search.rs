//! Fuzzy search ranked by frecency.
//!
//! Matching is nucleo's (fzf syntax: `^prefix`, `suffix$`, `'exact`, `!not`,
//! space-separated terms all have to match). An entry is matched against its
//! title alone and against "title username host path tags"; a title match
//! counts for more. Frecency then lifts entries you actually use.

use crate::entries::EntryMeta;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// Weight of `ln(1 + frecency)` against nucleo's score (about 16 per matched
/// character plus bonuses): an entry used daily for a week (frecency ≈ 4)
/// gains about what three more matching characters would.
const FRECENCY_WEIGHT: f64 = 30.0;

pub struct Searcher {
    matcher: Matcher,
    buf: Vec<char>,
}

impl Default for Searcher {
    fn default() -> Self {
        Self { matcher: Matcher::new(Config::DEFAULT), buf: Vec::new() }
    }
}

impl Searcher {
    /// Indices into `entries`, best first. `frecency(i)` is entry i's score.
    /// An empty query lists everything by frecency, then title.
    pub fn rank(&mut self, entries: &[EntryMeta], query: &str, frecency: impl Fn(usize) -> f64) -> Vec<usize> {
        let query = query.trim();
        let mut ranked: Vec<(usize, f64)> = if query.is_empty() {
            (0..entries.len()).map(|i| (i, frecency(i))).collect()
        } else {
            let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
            entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    let title = self.score(&pattern, &e.title).map(|s| s * 3 / 2);
                    let all = self.score(&pattern, &haystack(e));
                    let fuzzy = title.max(all)?;
                    Some((i, fuzzy as f64 + FRECENCY_WEIGHT * frecency(i).ln_1p()))
                })
                .collect()
        };
        ranked.sort_by(|(a, sa), (b, sb)| {
            sb.total_cmp(sa)
                .then_with(|| entries[*a].title.to_lowercase().cmp(&entries[*b].title.to_lowercase()))
        });
        ranked.into_iter().map(|(i, _)| i).collect()
    }

    fn score(&mut self, pattern: &Pattern, text: &str) -> Option<u32> {
        pattern.score(Utf32Str::new(text, &mut self.buf), &mut self.matcher)
    }
}

fn haystack(e: &EntryMeta) -> String {
    let mut s = format!("{} {} {} {}", e.title, e.username, e.host(), e.path);
    for t in &e.tags {
        s.push(' ');
        s.push_str(t);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(title: &str, username: &str, url: &str, path: &str) -> EntryMeta {
        EntryMeta {
            uuid: title.into(),
            title: title.into(),
            username: username.into(),
            url: url.into(),
            path: path.into(),
            tags: vec![],
            has_password: true,
            has_otp: false,
        }
    }

    fn entries() -> Vec<EntryMeta> {
        vec![
            e("GitHub", "andrew", "https://github.com/login", "Dev"),
            e("GitLab", "andrew", "https://gitlab.com", "Dev"),
            e("Bank", "1234", "https://bank.example", "Money"),
            e("Router", "admin", "http://192.168.1.1", "Home"),
        ]
    }

    fn titles(es: &[EntryMeta], idx: Vec<usize>) -> Vec<&str> {
        idx.into_iter().map(|i| es[i].title.as_str()).collect()
    }

    #[test]
    fn fuzzy_title() {
        let es = entries();
        let got = titles(&es, Searcher::default().rank(&es, "ghub", |_| 0.0));
        assert_eq!(got, ["GitHub"]);
    }

    #[test]
    fn matches_other_fields() {
        let es = entries();
        assert_eq!(titles(&es, Searcher::default().rank(&es, "money", |_| 0.0)), ["Bank"]);
        assert_eq!(titles(&es, Searcher::default().rank(&es, "192.168", |_| 0.0)), ["Router"]);
        assert_eq!(titles(&es, Searcher::default().rank(&es, "dev lab", |_| 0.0)), ["GitLab"]);
    }

    #[test]
    fn frecency_breaks_close_calls() {
        let es = entries();
        let plain = titles(&es, Searcher::default().rank(&es, "git", |_| 0.0));
        assert_eq!(plain, ["GitHub", "GitLab"], "tie → title order");
        let used = titles(&es, Searcher::default().rank(&es, "git", |i| if i == 1 { 5.0 } else { 0.0 }));
        assert_eq!(used, ["GitLab", "GitHub"]);
    }

    #[test]
    fn empty_query_is_frecency_then_title() {
        let es = entries();
        let got = titles(&es, Searcher::default().rank(&es, "  ", |i| if i == 3 { 1.0 } else { 0.0 }));
        assert_eq!(got, ["Router", "Bank", "GitHub", "GitLab"]);
    }
}
