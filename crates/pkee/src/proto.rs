//! Agent protocol: one JSON request line, one JSON response line per
//! connection, over `$XDG_RUNTIME_DIR/pkee/agent-<db id>.sock`.

use anyhow::{Context, Result, bail};
use pkee_core::entries::EntryMeta;
use serde::{Deserialize, Serialize};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Status,
    /// Unlock with a slot: the agent asks for the fingerprint.
    Unlock,
    Entries,
    /// Put a field on the clipboard (the agent serves and later clears it).
    Copy { uuid: String, field: Field },
    /// Return a field's value, for scripts (`pkee get --print`).
    Reveal { uuid: String, field: Field },
    Lock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Field {
    Password,
    Username,
    Totp,
    Url,
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::Password => "password",
            Field::Username => "username",
            Field::Totp => "TOTP code",
            Field::Url => "URL",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Status { unlocked: bool },
    Unlocked { slot: String },
    /// Entries with their frecency scores, index for index.
    Entries { entries: Vec<EntryMeta>, frecency: Vec<f64> },
    /// On the clipboard until replaced, or cleared after `clear_after_secs`.
    Copied { clear_after_secs: u64 },
    Value(String),
    Locked,
    Error(String),
}

/// Connection to the agent for one database.
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// Connect to the database's agent, starting one in the background if none
    /// is running (it inherits this environment, so WAYLAND_DISPLAY too).
    pub fn connect_or_spawn(db: &Path) -> Result<Self> {
        let client = Client { socket: pkee_core::paths::agent_socket(db)? };
        if UnixStream::connect(&client.socket).is_ok() {
            return Ok(client);
        }
        spawn_agent(db)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if UnixStream::connect(&client.socket).is_ok() {
                return Ok(client);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!(
            "agent did not start; see {}",
            pkee_core::paths::state_dir()?.join("agent.log").display()
        )
    }

    pub fn call(&self, req: &Request) -> Result<Response> {
        let mut stream = UnixStream::connect(&self.socket)
            .with_context(|| format!("connecting to {}", self.socket.display()))?;
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply)?;
        if reply.is_empty() {
            bail!("agent closed the connection");
        }
        match serde_json::from_str(&reply).context("bad reply from agent")? {
            Response::Error(e) => bail!("{e}"),
            r => Ok(r),
        }
    }
}

fn spawn_agent(db: &Path) -> Result<()> {
    let log_path = pkee_core::paths::state_dir()?.join("agent.log");
    std::fs::create_dir_all(log_path.parent().expect("has parent"))?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("--db").arg(db).arg("agent");
    cmd.stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    // Own session: outlives the popup or shell that started it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().context("starting pkee agent")?;
    Ok(())
}
