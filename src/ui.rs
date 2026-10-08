//! Output protocol + rendering. The daemon and the direct path emit the **same** lines; the client draws them.
//!
//! Line protocol (daemon -> client, one message per line):
//!   plain text              printed as-is
//!   \u{2}<text>             start of a progress line, no newline (the next plain line continues it)
//!   \u{3}ok <text>          check mark, magenta - successful finish
//!   \u{3}warn <text>        ! yellow
//!   \u{3}fail <text>        cross, red
//!   \u{3}hint <text>        indented dim - what to type next
//!   \u{3}h <text>           subheading (dim)
//!   \u{1}done <rc>          end of stream
use std::io::Write;

pub const P_PARTIAL: char = '\u{2}';
pub const P_STYLE: char = '\u{3}';
pub const P_DONE: &str = "\u{1}done ";

// Palette: dark background, magenta accent, lots of whitespace (matches the panel)
const MAGENTA: &str = "\x1b[38;5;205m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub fn is_tty() -> bool {
    unsafe { libc::isatty(1) == 1 }
}

/// Render one protocol line to stdout. Returns Some(rc) if this was the end line.
pub fn render(line: &str, color: bool) -> Option<i32> {
    let mut out = std::io::stdout().lock();
    if let Some(rc) = line.strip_prefix(P_DONE) {
        return Some(rc.trim().parse().unwrap_or(1));
    }
    if let Some(rest) = line.strip_prefix(P_PARTIAL) {
        let _ = write!(out, "{}", rest);
        let _ = out.flush();
        return None;
    }
    if let Some(rest) = line.strip_prefix(P_STYLE) {
        let (kind, text) = rest.split_once(' ').unwrap_or((rest, ""));
        let s = match (kind, color) {
            ("ok", true) => format!("{}{}✓{} {}", BOLD, MAGENTA, RESET, text),
            ("ok", false) => format!("✓ {}", text),
            ("warn", true) => format!("{}!{} {}", YELLOW, RESET, text),
            ("warn", false) => format!("! {}", text),
            ("fail", true) => format!("{}✗{} {}", RED, RESET, text),
            ("fail", false) => format!("✗ {}", text),
            ("hint", true) => format!("    {}{}{}", DIM, text, RESET),
            ("hint", false) => format!("    {}", text),
            ("h", true) => format!("{}{}{}", DIM, text, RESET),
            ("h", false) => text.to_string(),
            _ => text.to_string(),
        };
        let _ = writeln!(out, "{}", s);
        return None;
    }
    let _ = writeln!(out, "{}", line);
    None
}

/// One row of the status screen: label + value (fixed-width label).
pub fn kv(label: &str, value: &str) -> String {
    // Align by display width: wide (CJK) characters take two columns.
    let w: usize = label.chars().map(|c| if (c as u32) > 0x2E7F { 2 } else { 1 }).sum();
    format!("{}{}{}", label, " ".repeat(9usize.saturating_sub(w)), value)
}
