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
        theme(&cc.egui_ctx);
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
        let height = ui.available_height() - FOOTER_HEIGHT;
        egui::ScrollArea::vertical().max_height(height).auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (row, &i) in self.ranked.iter().take(MAX_ROWS).enumerate() {
                let e = &self.entries[i];
                let (rect, resp) =
                    ui.allocate_exact_size(egui::vec2(ui.available_width(), ROW_HEIGHT), egui::Sense::hover());
                let painter = ui.painter_at(rect);
                if row == self.selected {
                    // gitkay's selection: translucent mauve, plus an accent bar.
                    painter.rect_filled(rect, 0.0, egui::Color32::from_rgba_unmultiplied(203, 166, 247, 40));
                    painter.rect_filled(egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())), 0.0, MAUVE);
                    resp.scroll_to_me(None);
                }
                let y = rect.center().y;
                let mut x = rect.left() + 12.0;
                let text = |s: &str, font: egui::FontId, color, x: &mut f32| {
                    let g = painter.layout_no_wrap(s.to_owned(), font, color);
                    painter.galley(egui::pos2(*x, y - g.size().y / 2.0), g.clone(), color);
                    *x += g.size().x + 12.0;
                };
                let title = if e.title.is_empty() { "(untitled)" } else { &e.title };
                text(title, egui::FontId::monospace(14.0), TEXT, &mut x);
                if !e.username.is_empty() {
                    text(&e.username, egui::FontId::monospace(12.0), SUBTEXT, &mut x);
                }
                if e.has_otp {
                    text("TOTP", egui::FontId::monospace(10.0), GREEN, &mut x);
                }
                let place = [e.host(), e.path.as_str()]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · ");
                let g = painter.layout_no_wrap(place, egui::FontId::monospace(11.0), SUBTEXT);
                // Right-aligned, unless the left side already reaches there.
                let px = (rect.right() - 12.0 - g.size().x).max(x);
                painter.galley(egui::pos2(px, y - g.size().y / 2.0), g, SUBTEXT);
            }
        });
    }

    /// gitkay-style search row: magnifier, frameless monospace field, match
    /// count. Laid out by hand so the field (one text row tall) sits exactly on
    /// the bar's vertical centre; the icon is painted, not a font glyph.
    fn search_bar(&mut self, ui: &mut egui::Ui) {
        let font = egui::FontId::monospace(15.0);
        let (bar, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), SEARCH_HEIGHT), egui::Sense::hover());
        let painter = ui.painter_at(bar);
        painter.rect_filled(bar, 6.0, SURFACE0);
        let mid = bar.center().y;

        // Magnifier: lens plus handle, centred as a whole on `mid`.
        let lens = egui::pos2(bar.left() + 18.0, mid - 1.5);
        let stroke = egui::Stroke::new(1.6, SUBTEXT);
        painter.circle_stroke(lens, 5.0, stroke);
        painter.line_segment([lens + egui::vec2(3.7, 3.7), lens + egui::vec2(7.5, 7.5)], egui::Stroke::new(2.0, SUBTEXT));

        let count = painter.layout_no_wrap(
            format!("{}/{}", self.ranked.len(), self.entries.len()),
            egui::FontId::monospace(12.0),
            SUBTEXT,
        );
        let count_w = count.size().x;
        painter.galley(egui::pos2(bar.right() - 12.0 - count_w, mid - count.size().y / 2.0), count, SUBTEXT);

        let row = ui.fonts_mut(|f| f.row_height(&font));
        let field = egui::Rect::from_min_max(
            egui::pos2(bar.left() + 34.0, mid - row / 2.0),
            egui::pos2(bar.right() - 24.0 - count_w, mid + row / 2.0),
        );
        let search = ui.put(
            field,
            egui::TextEdit::singleline(&mut self.query)
                .frame(egui::Frame::NONE)
                .margin(egui::Margin::ZERO)
                .desired_width(field.width())
                .hint_text(RichText::new("Search title, user, URL, group…").font(font.clone()).color(SUBTEXT))
                .font(font)
                .text_color(TEXT),
        );
        search.request_focus();
        if search.changed() {
            self.note = None;
            self.rerank();
        }
    }
}

/// Catppuccin Mocha, as in gitkay.
const BG: egui::Color32 = egui::Color32::from_rgb(30, 30, 46);
const SURFACE0: egui::Color32 = egui::Color32::from_rgb(49, 50, 68);
const TEXT: egui::Color32 = egui::Color32::from_rgb(205, 214, 244);
const SUBTEXT: egui::Color32 = egui::Color32::from_rgb(108, 112, 134);
const MAUVE: egui::Color32 = egui::Color32::from_rgb(203, 166, 247);
const GREEN: egui::Color32 = egui::Color32::from_rgb(166, 227, 161);
const RED: egui::Color32 = egui::Color32::from_rgb(243, 139, 168);

const SEARCH_HEIGHT: f32 = 36.0;
const ROW_HEIGHT: f32 = 30.0;
const FOOTER_HEIGHT: f32 = 26.0;

fn theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.extreme_bg_color = BG;
    visuals.faint_bg_color = SURFACE0;
    visuals.override_text_color = Some(TEXT);
    visuals.text_cursor.stroke.color = MAUVE;
    visuals.selection.bg_fill = MAUVE.gamma_multiply(0.4);
    ctx.set_visuals(visuals);
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events();
        let ctx = ui.ctx().clone();
        let close_on_esc = |ctx: &egui::Context| {
            if ctx.input(|i| i.key_pressed(Key::Escape)) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        };
        let panel = egui::Frame::NONE.fill(BG).inner_margin(egui::Margin::same(10));
        egui::CentralPanel::default_margins().frame(panel).show(ui, |ui| match &self.phase {
            Phase::Connecting => close_on_esc(&ctx),
            Phase::Unlocking => {
                close_on_esc(&ctx);
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.label(RichText::new("Locked").size(18.0).color(TEXT));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Approve the request and touch the fingerprint sensor.").color(SUBTEXT));
                });
            }
            Phase::Failed(e) => {
                close_on_esc(&ctx);
                ui.label(RichText::new(e).color(RED).monospace());
            }
            Phase::Ready => {
                self.keys(&ctx);
                self.search_bar(ui);
                ui.add_space(6.0);
                self.list(ui);
                let footer = match &self.note {
                    Some(note) => RichText::new(note).color(RED),
                    None => RichText::new("↵ password   ^U username   ^T TOTP   ^O open URL   esc close").color(SUBTEXT),
                };
                ui.add_space(4.0);
                ui.label(footer.size(11.0).monospace());
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
