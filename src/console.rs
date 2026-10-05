//! What the long-running tools print while they run.
//!
//! At an interactive prompt the default is a panel redrawn in place: current
//! rates and running totals, the warnings that hold right now, and the last
//! few one-off events under it. With `--show-logging`, or whenever stdout is
//! not a terminal, every line is printed and scrolls instead, which is what a
//! file, a service log or anything scraping the output needs.
//!
//! The mode is process-wide because stdout is: a stray `println!` in panel
//! mode would be overdrawn, so everything goes through here.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write, stdout};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crossterm::{cursor, queue, style::Print, terminal};

/// Events kept under the panel.
const RECENT: usize = 6;

static CONSOLE: Mutex<Option<Panel>> = Mutex::new(None);

struct Panel {
    started: Instant,
    body: Vec<String>,
    recent: VecDeque<String>,
    /// Lines on screen from the last draw, which the next one moves back over.
    drawn: u16,
}

/// Choose the mode. Call once, before anything is printed through here.
pub fn init(show_logging: bool) {
    if show_logging || !stdout().is_terminal() {
        return;
    }
    *lock() = Some(Panel {
        started: Instant::now(),
        body: Vec::new(),
        recent: VecDeque::new(),
        drawn: 0,
    });
}

/// Whether the panel is showing, so a caller can skip building log lines.
pub fn panel() -> bool {
    lock().is_some()
}

/// A line of the running log. The panel has its own view of the same state,
/// so this prints only when logging.
pub fn log(line: impl AsRef<str>) {
    if lock().is_none() {
        println!("{}", line.as_ref());
    }
}

/// Something that happened once. Printed when logging; listed under the
/// panel, with how long into the run it happened, otherwise.
pub fn event(line: impl AsRef<str>) {
    let mut guard = lock();
    let Some(panel) = guard.as_mut() else {
        println!("{}", line.as_ref());
        return;
    };
    let at = clock(panel.started.elapsed());
    panel.recent.push_back(format!("  {at}  {}", line.as_ref()));
    while panel.recent.len() > RECENT {
        panel.recent.pop_front();
    }
    panel.redraw();
}

/// Replace the panel's body. Does nothing when logging.
pub fn draw(body: Vec<String>) {
    if let Some(panel) = lock().as_mut() {
        panel.body = body;
        panel.redraw();
    }
}

/// How long the run has been going, for a panel's header.
pub fn uptime() -> Duration {
    lock()
        .as_ref()
        .map_or(Duration::ZERO, |p| p.started.elapsed())
}

/// `hh:mm:ss`.
pub fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// A count with thousands separated, so a total can be read at a glance.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn lock() -> std::sync::MutexGuard<'static, Option<Panel>> {
    // A panic elsewhere while printing leaves nothing here half-written that
    // matters, so a poisoned lock is still usable.
    CONSOLE.lock().unwrap_or_else(|e| e.into_inner())
}

impl Panel {
    fn redraw(&mut self) {
        let (width, height) = terminal::size().unwrap_or((120, 40));
        let mut lines: Vec<&str> = self.body.iter().map(String::as_str).collect();
        if !self.recent.is_empty() {
            lines.push("");
            lines.push("recent");
            lines.extend(self.recent.iter().map(String::as_str));
        }
        // A line that wraps, or a panel taller than the window, leaves rows the
        // next draw cannot move back over, so both are cut to fit.
        lines.truncate(usize::from(height.saturating_sub(1)));
        let width = usize::from(width.saturating_sub(1));

        let mut out = stdout().lock();
        let drawn = self.drawn;
        let result = (|| -> std::io::Result<()> {
            if drawn > 0 {
                queue!(out, cursor::MoveToPreviousLine(drawn))?;
            }
            queue!(out, terminal::Clear(terminal::ClearType::FromCursorDown))?;
            for line in &lines {
                let fitted: String = line.chars().take(width).collect();
                queue!(out, Print(fitted), Print("\n"))?;
            }
            out.flush()
        })();
        // A failed draw is not worth stopping the relay over; the next one
        // starts from wherever the cursor was left.
        if result.is_ok() {
            self.drawn = lines.len() as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_grouped_in_thousands() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(412_880), "412,880");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn the_clock_rolls_over_minutes_and_hours() {
        assert_eq!(clock(Duration::from_secs(59)), "00:00:59");
        assert_eq!(clock(Duration::from_secs(3_661)), "01:01:01");
        assert_eq!(clock(Duration::from_secs(100 * 3600)), "100:00:00");
    }
}
