//! Flow tracking and bandwidth accounting.

pub mod key;
pub mod rate;
pub mod stats;
pub mod table;

use std::time::Duration;

pub use key::{Aggregate, FlowKey};
pub use rate::RateWindow;
pub use stats::{Direction, FlowStats, TcpCounters};
pub use table::{FlowTable, Globals, Snapshot, SortBy};

#[must_use]
pub fn format_rate(bytes_per_sec: f64) -> String {
    format_rate_units(bytes_per_sec, false)
}

#[must_use]
pub fn format_rate_units(bytes_per_sec: f64, use_bytes: bool) -> String {
    if use_bytes {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes_per_sec;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 {
            format!("{value:.0} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        } else if value >= 10.0 {
            format!("{value:.1} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        } else {
            format!("{value:.2} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        }
    } else {
        const UNITS: &[&str] = &["b", "Kb", "Mb", "Gb", "Tb"];
        let mut value = bytes_per_sec * 8.0;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 {
            format!("{value:.0} {}", UNITS.get(unit).copied().unwrap_or(""))
        } else if value >= 10.0 {
            format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or(""))
        } else {
            format!("{value:.2} {}", UNITS.get(unit).copied().unwrap_or(""))
        }
    }
}

#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS.get(unit).copied().unwrap_or(""))
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or(""))
    } else {
        format!("{value:.2} {}", UNITS.get(unit).copied().unwrap_or(""))
    }
}

#[must_use]
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[must_use]
pub fn rate_bar(rate: f64, max_rate: f64, width: usize) -> String {
    if width == 0 || max_rate <= 0.0 || rate <= 0.0 {
        return " ".repeat(width);
    }
    let frac = (rate / max_rate).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = ((frac * width as f64).round() as usize).min(width);
    format!("{}{}", "#".repeat(filled), " ".repeat(width - filled))
}
