//! pkee: fingerprint-unlocked KeePass launcher. Without a command it opens the
//! popup; the commands manage key slots and script the agent.

mod agent;
mod clip;
mod proto;
mod ui;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use pkee_core::fido::{self, Authenticator, HidAuthenticator};
use pkee_core::keyfile::KeyFile;
use pkee_core::slot::{self, Slot, Slots};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use pkee_core::search::Searcher;
use proto::{Client, Field, Request, Response};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The KeePass database. Its slots live in `<db>.slots/`.
    #[arg(long, env = "PKEE_DB", global = true)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the search popup (the default).
    Ui,
    /// Copy (or print) a field of the best match for QUERY.
    Get {
        query: String,
        #[arg(long, value_enum, default_value = "password")]
        field: Field,
        /// Print to stdout instead of copying.
        #[arg(long)]
        print: bool,
    },
    /// Show whether the agent is unlocked.
    Status,
    /// Lock the agent now.
    Lock,
    /// Run the agent in the foreground (normally started on demand).
    Agent {
        /// Lock after this many seconds without use.
        #[arg(long, default_value_t = 600)]
        idle: u64,
        /// Lock this many seconds after unlocking, used or not.
        #[arg(long, default_value_t = 8 * 3600)]
        max: u64,
        /// Clear a copied secret from the clipboard after this many seconds.
        #[arg(long, default_value_t = 20)]
        clear_after: u64,
    },
    /// Generate the database key file and the first slot on this device.
    Init {
        /// Where to write the key file (KeePass XML 2.0). Keep it as your backup.
        #[arg(long)]
        keyfile_out: PathBuf,
        #[command(flatten)]
        enrol: Enrol,
    },
    /// Manage key slots.
    #[command(subcommand)]
    Slot(SlotCmd),
    /// Print the key file (unlocks with a slot).
    Keyfile {
        /// Write here (created, mode 0600) instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Unlock and open the database, to check that everything fits.
    Check {
        /// Use this key file instead of a slot.
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SlotCmd {
    /// List slots.
    List,
    /// Add a slot on a connected authenticator.
    Add {
        /// Take the key file from here (`-` for stdin) instead of unlocking a slot.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[command(flatten)]
        enrol: Enrol,
    },
    /// Remove a slot. This doesn't revoke a key file the device already saw.
    Rm { id: String },
}

#[derive(Args)]
struct Enrol {
    /// Slot label (default: this machine's hostname).
    #[arg(long)]
    label: Option<String>,
    /// Which authenticator, as listed, when more than one is connected.
    #[arg(long)]
    device: Option<usize>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = cli.db.context("no database: pass --db or set PKEE_DB")?;
    let slots = Slots::for_db(&db);
    match cli.cmd.unwrap_or(Cmd::Ui) {
        Cmd::Ui => ui::run(db),
        Cmd::Get { query, field, print } => get(&db, &query, field, print),
        Cmd::Status => {
            let client = Client::connect_or_spawn(&db)?;
            match client.call(&Request::Status)? {
                Response::Status { unlocked: true } => println!("unlocked"),
                _ => println!("locked"),
            }
            Ok(())
        }
        Cmd::Lock => {
            Client::connect_or_spawn(&db)?.call(&Request::Lock)?;
            eprintln!("locked");
            Ok(())
        }
        Cmd::Agent { idle, max, clear_after } => agent::run(
            &db,
            agent::Config {
                idle: Duration::from_secs(idle),
                max: Duration::from_secs(max),
                clear_after: Duration::from_secs(clear_after),
            },
        ),
        Cmd::Init { keyfile_out, enrol } => init(&db, &slots, &keyfile_out, &enrol),
        Cmd::Slot(SlotCmd::List) => list(&slots),
        Cmd::Slot(SlotCmd::Add { keyfile, enrol }) => {
            let key = match keyfile {
                Some(path) => read_keyfile(&path)?,
                None => unlock(&slots)?,
            };
            add(&db, &slots, &key, &enrol)
        }
        Cmd::Slot(SlotCmd::Rm { id }) => {
            slots.remove(&id)?;
            eprintln!("removed slot {id}");
            if slots.list()?.is_empty() {
                eprintln!("warning: no slots left; only the key file opens the database now");
            }
            Ok(())
        }
        Cmd::Keyfile { out } => {
            let key = unlock(&slots)?;
            match out {
                Some(path) => write_keyfile(&path, &key),
                None => {
                    if std::io::stdout().is_terminal() {
                        eprintln!("warning: printing the database key to the terminal");
                    }
                    std::io::stdout().write_all(key.to_xml().as_bytes())?;
                    Ok(())
                }
            }
        }
        Cmd::Check { keyfile } => {
            let key = match keyfile {
                Some(path) => read_keyfile(&path)?,
                None => unlock(&slots)?,
            };
            let t = Instant::now();
            let kdbx = pkee_core::db::open(&db, &key)?;
            println!("{}: {} entries, opened in {} ms", db.display(), kdbx.num_entries(), t.elapsed().as_millis());
            Ok(())
        }
    }
}

/// `pkee get`: the same ranking as the popup, best match only.
fn get(db: &Path, query: &str, field: Field, print: bool) -> Result<()> {
    let client = Client::connect_or_spawn(db)?;
    if let Response::Status { unlocked: false } = client.call(&Request::Status)? {
        eprintln!("unlocking: approve and touch the sensor…");
        client.call(&Request::Unlock)?;
    }
    let Response::Entries { entries, frecency } = client.call(&Request::Entries)? else {
        bail!("unexpected reply from agent");
    };
    let ranked = Searcher::default().rank(&entries, query, |i| frecency[i]);
    let Some(&best) = ranked.first() else { bail!("no entry matches {query:?}") };
    let e = &entries[best];
    let uuid = e.uuid.clone();
    if print {
        if let Response::Value(v) = client.call(&Request::Reveal { uuid, field })? {
            println!("{v}");
        }
    } else if let Response::Copied { clear_after_secs } = client.call(&Request::Copy { uuid, field })? {
        eprintln!("copied {} of {:?}; clears in {clear_after_secs}s", field.name(), e.title);
    }
    Ok(())
}

fn init(db: &Path, slots: &Slots, keyfile_out: &Path, enrol: &Enrol) -> Result<()> {
    if !slots.list()?.is_empty() {
        bail!("{} already has slots; use `pkee slot add`", db.display());
    }
    let key = KeyFile::generate()?;
    // Key file first: if enrolment fails, it is still there to retry with.
    write_keyfile(keyfile_out, &key)?;
    add(db, slots, &key, enrol).with_context(|| {
        format!(
            "no slot created; retry with: pkee --db {} slot add --keyfile {}",
            db.display(),
            keyfile_out.display()
        )
    })?;
    eprintln!(
        "\nNext:\n  1. Back up {kf} (print it, or copy it somewhere offline).\n  \
         2. In KeePassXC: Database > Database Security > set key file {kf}, remove the password.\n     \
         Optionally lower Argon2 there: a 256-bit key file needs no slow KDF.\n  \
         3. pkee --db {db} check",
        kf = keyfile_out.display(),
        db = db.display(),
    );
    Ok(())
}

fn add(db: &Path, slots: &Slots, key: &KeyFile, enrol: &Enrol) -> Result<()> {
    let auths = fido::authenticators();
    let auth = pick(&auths, enrol.device)?;
    let label = match &enrol.label {
        Some(l) => l.clone(),
        None => hostname()?,
    };
    let id = slots.free_id(&label)?;
    let db_name = db.file_name().map_or_else(|| db.display().to_string(), |n| n.to_string_lossy().into_owned());
    eprintln!("creating slot {id:?} on {}: approve and touch the sensor (twice)…", auth.name());
    let slot = Slot::create(auth, &id, &label, &format!("{db_name} ({label})"), key)?;
    let path = slots.add(&slot)?;
    eprintln!("added slot {id} ({})", path.display());
    Ok(())
}

fn unlock(slots: &Slots) -> Result<KeyFile> {
    let all = slots.list()?;
    let auths = fido::authenticators();
    eprintln!("unlocking: approve and touch the sensor…");
    let (key, slot) = slot::unlock(&all, &auths)?;
    eprintln!("unlocked with slot {} ({})", slot.id, slot.label);
    Ok(key)
}

fn list(slots: &Slots) -> Result<()> {
    let all = slots.list()?;
    if all.is_empty() {
        eprintln!("no slots in {}", slots.dir().display());
    }
    for s in all {
        println!("{:<20} {:<24} {}", s.id, s.label, s.authenticator);
    }
    Ok(())
}

fn pick(auths: &[HidAuthenticator], device: Option<usize>) -> Result<&HidAuthenticator> {
    match (auths, device) {
        ([], _) => bail!("no FIDO2 authenticator with hmac-secret found (is linux-passkey running?)"),
        ([only], None) => Ok(only),
        (_, Some(i)) => auths.get(i).with_context(|| format!("no authenticator {i}")),
        (_, None) => {
            for (i, a) in auths.iter().enumerate() {
                eprintln!("[{i}] {}", a.name());
            }
            bail!("several authenticators connected: pick one with --device")
        }
    }
}

fn read_keyfile(path: &Path) -> Result<KeyFile> {
    let mut buf = Vec::new();
    if path == Path::new("-") {
        std::io::stdin().read_to_end(&mut buf)?;
    } else {
        buf = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    }
    let key = KeyFile::parse(&buf);
    buf.fill(0);
    key
}

fn write_keyfile(path: &Path, key: &KeyFile) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite)", path.display()))?;
    f.write_all(key.to_xml().as_bytes())?;
    f.sync_all()?;
    eprintln!("wrote key file {}", path.display());
    Ok(())
}

fn hostname() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/hostname")
        .context("reading hostname; pass --label")?
        .trim()
        .to_owned())
}
