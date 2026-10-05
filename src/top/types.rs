use crate::flow::{format_bytes, format_rate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    #[default]
    Flows,
    Hosts,
    Ports,
    Protocols,
}

impl ViewMode {
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Flows => "Top flows",
            Self::Hosts => "Top hosts",
            Self::Ports => "Top ports",
            Self::Protocols => "Top protocols",
        }
    }

    #[must_use]
    pub const fn cycle(self) -> Self {
        match self {
            Self::Flows => Self::Hosts,
            Self::Hosts => Self::Ports,
            Self::Ports => Self::Protocols,
            Self::Protocols => Self::Flows,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopRow {
    pub label: String,
    pub bytes: u64,
    pub rate_2s: f64,
    pub rate_10s: f64,
    pub rate_40s: f64,
}

pub fn rank<K, F>(
    map: std::collections::HashMap<K, (u64, f64, f64, f64)>,
    n: usize,
    label: F,
) -> Vec<TopRow>
where
    F: Fn(K) -> String,
{
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    v.into_iter()
        .take(n)
        .map(|(k, (bytes, r2, r10, r40))| TopRow {
            label: label(k),
            bytes,
            rate_2s: r2,
            rate_10s: r10,
            rate_40s: r40,
        })
        .collect()
}

#[must_use]
pub fn format_top_row(row: &TopRow) -> (String, String, String, String, String) {
    (
        row.label.clone(),
        format_rate(row.rate_2s),
        format_rate(row.rate_10s),
        format_rate(row.rate_40s),
        format_bytes(row.bytes),
    )
}
