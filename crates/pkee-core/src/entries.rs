//! What the launcher shows: entry metadata, never secrets.

use keepass::Database;
use keepass::db::{EntryId, GroupId, GroupRef};
use serde::{Deserialize, Serialize};

/// One database entry as listed and searched. Passwords, notes and OTP secrets
/// stay in the agent; this only says whether they exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryMeta {
    /// The entry's KeePass UUID (hyphenated): stable across edits and renames.
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    /// Group path below the root, e.g. "Work/Cloud".
    pub path: String,
    pub tags: Vec<String>,
    pub has_password: bool,
    pub has_otp: bool,
}

impl EntryMeta {
    /// The URL's host, for display and search: "https://github.com/login" → "github.com".
    pub fn host(&self) -> &str {
        let rest = self.url.split_once("://").map_or(self.url.as_str(), |(_, r)| r);
        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        host.rsplit_once('@').map_or(host, |(_, h)| h)
    }
}

/// All entries outside the recycle bin, in tree order.
pub fn list(db: &Database) -> Vec<EntryMeta> {
    list_with_ids(db).into_iter().map(|(meta, _)| meta).collect()
}

/// [`list`], with the ids to look the entries up again (`Database::entry`).
pub fn list_with_ids(db: &Database) -> Vec<(EntryMeta, EntryId)> {
    let bin = db.recycle_bin().map(|g| g.id());
    let mut out = Vec::new();
    walk(db.root(), "", bin, &mut out);
    out
}

fn walk(group: GroupRef<'_>, path: &str, bin: Option<GroupId>, out: &mut Vec<(EntryMeta, EntryId)>) {
    for e in group.entries() {
        let field = |v: Option<&str>| v.unwrap_or_default().to_owned();
        let meta = EntryMeta {
            uuid: e.id().uuid().hyphenated().to_string(),
            title: field(e.get_title()),
            username: field(e.get_username()),
            url: field(e.get_url()),
            path: path.to_owned(),
            tags: e.tags.clone(),
            has_password: e.get_password().is_some_and(|p| !p.is_empty()),
            has_otp: e.get_raw_otp_value().is_some_and(|o| !o.is_empty()),
        };
        out.push((meta, e.id()));
    }
    for g in group.groups() {
        if Some(g.id()) == bin {
            continue;
        }
        let sub = if path.is_empty() { g.name.clone() } else { format!("{path}/{}", g.name) };
        walk(g, &sub, bin, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(url: &str) -> EntryMeta {
        EntryMeta {
            uuid: String::new(),
            title: String::new(),
            username: String::new(),
            url: url.into(),
            path: String::new(),
            tags: vec![],
            has_password: false,
            has_otp: false,
        }
    }

    #[test]
    fn host() {
        assert_eq!(meta("https://github.com/login").host(), "github.com");
        assert_eq!(meta("https://me@mail.example.org:8443/x?y#z").host(), "mail.example.org:8443");
        assert_eq!(meta("example.com/path").host(), "example.com");
        assert_eq!(meta("").host(), "");
    }

    #[test]
    fn lists_groups_and_skips_the_recycle_bin() {
        let mut db = Database::new();
        let bin_id = {
            let mut root = db.root_mut();
            root.add_entry().edit(|e| {
                e.set_unprotected("Title", "top");
                e.set_protected("Password", "pw");
            });
            {
                let mut work = root.add_group();
                work.name = "Work".into();
                let mut cloud = work.add_group();
                cloud.name = "Cloud".into();
                cloud.add_entry().edit(|e| {
                    e.set_unprotected("Title", "aws");
                    e.set_unprotected("UserName", "me");
                    e.set_unprotected("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
                });
            }
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            bin.add_entry().edit(|e| e.set_unprotected("Title", "deleted"));
            bin.id()
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());

        let all = list(&db);
        let titles: Vec<_> = all.iter().map(|e| (e.title.as_str(), e.path.as_str())).collect();
        assert_eq!(titles, [("top", ""), ("aws", "Work/Cloud")]);
        assert!(all[0].has_password && !all[0].has_otp);
        assert!(!all[1].has_password && all[1].has_otp);
        assert_eq!(all[1].username, "me");
    }
}
