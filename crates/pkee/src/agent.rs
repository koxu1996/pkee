//! The agent: holds one database unlocked for a while, so the popup opens
//! instantly and needs a fingerprint only when the agent is locked.
//!
//! It keeps the key file (to reload when the database changes on disk) and the
//! open database in memory, and answers the popup over a Unix socket that only
//! this user can reach. Secrets leave it only to the clipboard, or to a
//! `Reveal` caller (`pkee get --print`). It locks after `idle` without use and
//! after `max` at the latest.

use crate::clip::Clipboard;
use crate::proto::{Field, Request, Response};
use anyhow::{Context, Result, anyhow, bail};
use keepass::Database;
use keepass::db::EntryId;
use pkee_core::entries::{self, EntryMeta};
use pkee_core::fido;
use pkee_core::frecency::{self, Frecency};
use pkee_core::keyfile::KeyFile;
use pkee_core::slot::{self, Slots};
use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

pub struct Config {
    pub idle: Duration,
    pub max: Duration,
    pub clear_after: Duration,
}

struct Unlocked {
    key: KeyFile,
    db: Database,
    entries: Vec<EntryMeta>,
    ids: HashMap<String, EntryId>,
    modified: Option<SystemTime>,
    since: Instant,
    last_used: Instant,
}

struct Agent {
    db_path: PathBuf,
    slots: Slots,
    cfg: Config,
    unlocked: Option<Unlocked>,
    frecency: Frecency,
    frecency_path: PathBuf,
    clipboard: Clipboard,
}

pub fn run(db_path: &Path, cfg: Config) -> Result<()> {
    harden();
    let socket = pkee_core::paths::agent_socket(db_path)?;
    let listener = bind(&socket)?;
    let frecency_path = pkee_core::paths::frecency_file(db_path)?;
    let mut agent = Agent {
        db_path: db_path.to_owned(),
        slots: Slots::for_db(db_path),
        cfg,
        unlocked: None,
        frecency: Frecency::load(&frecency_path)?,
        frecency_path,
        clipboard: Clipboard::default(),
    };
    eprintln!("pkee agent: {} on {}", db_path.display(), socket.display());

    loop {
        // Wake at least once a second to apply the lock timeouts.
        if poll_readable(&listener, Duration::from_secs(1))? {
            let (stream, _) = listener.accept()?;
            if let Err(e) = agent.serve(stream) {
                eprintln!("pkee agent: {e:#}");
            }
        }
        agent.lock_if_expired();
    }
}

impl Agent {
    fn serve(&mut self, stream: UnixStream) -> Result<()> {
        check_peer(&stream)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        if line.is_empty() {
            return Ok(()); // a client checking that we're up
        }
        let req: Request = serde_json::from_str(&line).context("bad request")?;
        let resp = self.handle(req).unwrap_or_else(|e| Response::Error(format!("{e:#}")));
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        (&stream).write_all(out.as_bytes())?;
        Ok(())
    }

    fn handle(&mut self, req: Request) -> Result<Response> {
        self.lock_if_expired();
        Ok(match req {
            Request::Status => Response::Status { unlocked: self.unlocked.is_some() },
            Request::Unlock => {
                let slot = self.unlock()?;
                Response::Unlocked { slot }
            }
            Request::Lock => {
                self.lock("on request");
                Response::Locked
            }
            Request::Entries => {
                let now = frecency::now();
                let u = self.open()?;
                let entries = u.entries.clone();
                let frecency = entries.iter().map(|e| self.frecency.score(&e.uuid, now)).collect();
                Response::Entries { entries, frecency }
            }
            Request::Copy { uuid, field } => {
                let value = self.value(&uuid, field)?;
                self.clipboard.copy(value, self.cfg.clear_after)?;
                self.record_use(&uuid);
                Response::Copied { clear_after_secs: self.cfg.clear_after.as_secs() }
            }
            Request::Reveal { uuid, field } => {
                let value = self.value(&uuid, field)?;
                self.record_use(&uuid);
                Response::Value(value.to_string())
            }
        })
    }

    /// Unlock with whichever slot a connected authenticator owns.
    fn unlock(&mut self) -> Result<String> {
        if self.unlocked.is_some() {
            return Ok("(already unlocked)".into());
        }
        let auths = fido::authenticators();
        let (key, slot) = slot::unlock(&self.slots.list()?, &auths)?;
        self.unlocked = Some(load(&self.db_path, key)?);
        eprintln!("pkee agent: unlocked with slot {}", slot.id);
        Ok(slot.label)
    }

    /// The unlocked database, reloaded if the file changed (e.g. KeePassXC
    /// saved, or Syncthing brought a new version).
    fn open(&mut self) -> Result<&Unlocked> {
        let u = self.unlocked.as_mut().ok_or_else(|| anyhow!("locked"))?;
        u.last_used = Instant::now();
        if modified(&self.db_path) != u.modified {
            let reloaded = load(&self.db_path, u.key.clone())?;
            let (since, last_used) = (u.since, u.last_used);
            *u = Unlocked { since, last_used, ..reloaded };
            let live: std::collections::HashSet<&str> = u.entries.iter().map(|e| e.uuid.as_str()).collect();
            self.frecency.prune(|k| live.contains(k), frecency::now());
            eprintln!("pkee agent: reloaded {}", self.db_path.display());
        }
        Ok(self.unlocked.as_ref().expect("checked above"))
    }

    fn value(&mut self, uuid: &str, field: Field) -> Result<Zeroizing<String>> {
        let u = self.open()?;
        let id = *u.ids.get(uuid).ok_or_else(|| anyhow!("no entry {uuid}"))?;
        let e = u.db.entry(id).ok_or_else(|| anyhow!("no entry {uuid}"))?;
        let text = match field {
            Field::Password => e.get_password(),
            Field::Username => e.get_username(),
            Field::Url => e.get_url(),
            Field::Totp => {
                let code = e.get_otp().map_err(|err| anyhow!("TOTP: {err}"))?.value_now()?;
                return Ok(Zeroizing::new(code.code));
            }
        };
        match text {
            Some(t) if !t.is_empty() => Ok(Zeroizing::new(t.to_owned())),
            _ => bail!("{} has no {}", e.get_title().unwrap_or("entry"), field.name()),
        }
    }

    fn record_use(&mut self, uuid: &str) {
        self.frecency.record(uuid, frecency::now());
        if let Err(e) = self.frecency.save(&self.frecency_path) {
            eprintln!("pkee agent: {e:#}");
        }
    }

    fn lock_if_expired(&mut self) {
        let Some(u) = &self.unlocked else { return };
        if u.last_used.elapsed() >= self.cfg.idle {
            self.lock("idle");
        } else if u.since.elapsed() >= self.cfg.max {
            self.lock("max unlock time reached");
        }
    }

    fn lock(&mut self, why: &str) {
        if self.unlocked.take().is_some() {
            // KeyFile zeroizes itself on drop; the Database does not, which is
            // one more reason to keep the unlocked window short.
            eprintln!("pkee agent: locked ({why})");
        }
    }
}

fn load(db_path: &Path, key: KeyFile) -> Result<Unlocked> {
    let modified = modified(db_path);
    let db = pkee_core::db::open(db_path, &key)?;
    let (entries, ids): (Vec<_>, Vec<_>) = entries::list_with_ids(&db).into_iter().unzip();
    let ids = entries.iter().map(|e| e.uuid.clone()).zip(ids).collect();
    let now = Instant::now();
    Ok(Unlocked { key, db, entries, ids, modified, since: now, last_used: now })
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Bind the socket in a 0700 directory. A socket file nobody answers on is
/// left over from a crash and replaced; one that answers means another agent.
fn bind(socket: &Path) -> Result<UnixListener> {
    let dir = socket.parent().expect("socket has a directory");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("an agent is already running on {}", socket.display());
        }
        std::fs::remove_file(socket)?;
    }
    UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))
}

/// Only this user may talk to the agent (the directory is 0700 too).
fn check_peer(stream: &UnixStream) -> Result<()> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        bail!("SO_PEERCRED: {}", std::io::Error::last_os_error());
    }
    let me = unsafe { libc::getuid() };
    if cred.uid != me {
        bail!("refusing peer uid {} (pid {})", cred.uid, cred.pid);
    }
    Ok(())
}

/// Not dumpable: no core dumps with secrets in them, and other processes of
/// this user can't ptrace the agent or read its memory through /proc.
fn harden() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn poll_readable(listener: &UnixListener, timeout: Duration) -> Result<bool> {
    let mut fds = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let rc = unsafe { libc::poll(&mut fds, 1, timeout.as_millis() as libc::c_int) };
    match rc {
        -1 if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => Ok(false),
        -1 => Err(std::io::Error::last_os_error().into()),
        n => Ok(n > 0),
    }
}
