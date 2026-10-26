//! The popup: type to search, Enter to copy, gone. Keyboard only.
//!
//! Talks to the agent; unlocking (the fingerprint) happens in the agent while
//! the popup says so. Secrets never reach this process: copying is the agent's
//! job, which is also why the window can close right after.

use crate::proto::{Client, Field, Request, Response};
use anyhow::Result;
use eframe::egui::{self, Key, Modifiers, RichText};
use pkee_core::entries::EntryMeta;
use pkee_core::search::Searcher;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

/// Rows to lay out; the rest is a search away.
const MAX_ROWS: usize = 200;

pub fn run(db: PathBuf) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pkee")
            // Hyprland: `windowrule = float, class:^(pkee)$` (and center, pin…).
            .with_app_id("pkee")
            .with_inner_size([720.0, 440.0]),
        ..Default::default()
    };
    eframe::run_native("pkee", options, Box::new(move |cc| Ok(Box::new(App::new(cc, db)))))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

enum Phase {
    Connecting,
    Unlocking,
    Ready,
    Failed(String),
}

/// What the background thread reports.
enum Event {
    Unlocking,
    Loaded { client: Client, entries: Vec<EntryMeta>, frecency: Vec<f64> },
    Failed(String),
}

struct App {
    phase: Phase,
    events: Receiver<Event>,
    client: Option<Client>,
    entries: Vec<EntryMeta>,
    frecency: Vec<f64>,
    searcher: Searcher,
    query: String,
    ranked: Vec<usize>,
    selected: usize,
    /// Message for the footer (e.g. "no TOTP for this entry").
    note: Option<String>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, db: PathBuf) -> Self {
        let (tx, events) = channel();
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || {
            let send = |ev| {
                let _ = tx.send(ev);
                ctx.request_repaint();
            };
            match load(&db, || send(Event::Unlocking)) {
                Ok((client, entries, frecency)) => send(Event::Loaded { client, entries, frecency }),
                Err(e) => send(Event::Failed(format!("{e:#}"))),
            }
        });
        Self {
            phase: Phase::Connecting,
            events,
            client: None,
            entries: Vec::new(),
            frecency: Vec::new(),
            searcher: Searcher::default(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            note: None,
        }
    }

    fn rerank(&mut self) {
        let frecency = &self.frecency;
        self.ranked = self.searcher.rank(&self.entries, &self.query, |i| frecency[i]);
        self.selected = 0;
    }

    fn poll_events(&mut self) {
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                Event::Unlocking => self.phase = Phase::Unlocking,
                Event::Loaded { client, entries, frecency } => {
                    self.client = Some(client);
                    self.entries = entries;
                    self.frecency = frecency;
                    self.phase = Phase::Ready;
                    self.rerank();
                }
                Event::Failed(e) => self.phase = Phase::Failed(e),
            }
        }
    }

    /// Run `field` on the selected entry. Copies close the window.
    fn act(&mut self, ctx: &egui::Context, field: Field) {
        let (Some(client), Some(&i)) = (&self.client, self.ranked.get(self.selected)) else { return };
        let uuid = self.entries[i].uuid.clone();
        let result = if field == Field::Url {
            client.call(&Request::Reveal { uuid, field }).and_then(|r| match r {
                Response::Value(url) => open_url(&url),
                other => Err(anyhow::anyhow!("unexpected reply {other:?}")),
            })
        } else {
            client.call(&Request::Copy { uuid, field }).map(|_| ())
        };
        match result {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(e) => self.note = Some(format!("{e:#}")),
        }
    }

    fn keys(&mut self, ctx: &egui::Context) {
        let consume = |m, k| ctx.input_mut(|i| i.consume_key(m, k));
        if consume(Modifiers::NONE, Key::Escape) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let last = self.ranked.len().saturating_sub(1);
        if consume(Modifiers::NONE, Key::ArrowDown) || consume(Modifiers::CTRL, Key::N) {
            self.selected = (self.selected + 1).min(last);
        }
        if consume(Modifiers::NONE, Key::ArrowUp) || consume(Modifiers::CTRL, Key::P) {
            self.selected = self.selected.saturating_sub(1);
        }
        if consume(Modifiers::NONE, Key::PageDown) {
            self.selected = (self.selected + 10).min(last);
        }
        if consume(Modifiers::NONE, Key::PageUp) {
            self.selected = self.selected.saturating_sub(10);
        }
        let action = [
            (Modifiers::NONE, Key::Enter, Field::Password),
            (Modifiers::CTRL, Key::U, Field::Username),
            (Modifiers::CTRL, Key::T, Field::Totp),
            (Modifiers::CTRL, Key::O, Field::Url),
        ]
        .into_iter()
        .find(|&(m, k, _)| consume(m, k));
        if let Some((_, _, field)) = action {
            self.act(ctx, field);
        }
    }

    fn list(&self, ui: &mut egui::Ui) {
        let height = ui.available_height() - 28.0;
        egui::ScrollArea::vertical().max_height(height).auto_shrink([false, false]).show(ui, |ui| {
            for (row, &i) in self.ranked.iter().take(MAX_ROWS).enumerate() {
                let e = &self.entries[i];
                let selected = row == self.selected;
                let frame = egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(8, 4))
                    .corner_radius(4)
                    .fill(if selected { ui.visuals().selection.bg_fill } else { egui::Color32::TRANSPARENT });
                let resp = frame
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let title = if e.title.is_empty() { "(untitled)" } else { &e.title };
                            ui.label(RichText::new(title).strong());
                            if !e.username.is_empty() {
                                ui.label(RichText::new(&e.username).weak());
                            }
                            if e.has_otp {
                                ui.label(RichText::new("TOTP").small().weak());
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let place = [e.host(), e.path.as_str()]
                                    .into_iter()
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                                    .join(" · ");
                                ui.label(RichText::new(place).small().weak());
                            });
                        });
                    })
                    .response;
                if selected {
                    resp.scroll_to_me(None);
                }
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events();
        let ctx = ui.ctx().clone();
        egui::CentralPanel::default_margins().show(ui, |ui| match &self.phase {
            Phase::Connecting => {
                ui.label("Starting…");
                if ctx.input(|i| i.key_pressed(Key::Escape)) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            Phase::Unlocking => {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.heading("Locked");
                    ui.label("Approve the request and touch the fingerprint sensor.");
                });
            }
            Phase::Failed(e) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
                if ctx.input(|i| i.key_pressed(Key::Escape)) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            Phase::Ready => {
                self.keys(&ctx);
                let search = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("Search…")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Heading),
                );
                search.request_focus();
                if search.changed() {
                    self.note = None;
                    self.rerank();
                }
                ui.separator();
                self.list(ui);
                ui.separator();
                let footer = self.note.clone().unwrap_or_else(|| {
                    format!(
                        "{} of {}   ↵ password · ^U username · ^T TOTP · ^O open URL · esc",
                        self.ranked.len(),
                        self.entries.len()
                    )
                });
                ui.label(RichText::new(footer).small().weak());
            }
        });
    }
}

/// Connect (starting the agent if needed), unlock if locked, fetch entries.
fn load(db: &std::path::Path, unlocking: impl FnOnce()) -> Result<(Client, Vec<EntryMeta>, Vec<f64>)> {
    let client = Client::connect_or_spawn(db)?;
    if let Response::Status { unlocked: false } = client.call(&Request::Status)? {
        unlocking();
        client.call(&Request::Unlock)?;
    }
    match client.call(&Request::Entries)? {
        Response::Entries { entries, frecency } => Ok((client, entries, frecency)),
        other => anyhow::bail!("unexpected reply {other:?}"),
    }
}

fn open_url(url: &str) -> Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}
