use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::alerts::AlertEngine;
use crate::capture::SharedFlows;
use crate::dns::DnsCache;
use crate::filters::ScreenFilter;
use crate::flow::{Aggregate, SortBy};
use crate::top::ViewMode;

pub struct App {
    pub flows: SharedFlows,
    pub dns: Arc<DnsCache>,
    pub interface: String,
    pub show_ports: bool,
    pub no_port_resolution: bool,
    pub use_bytes: bool,
    pub no_bars: bool,
    pub enable_dns: bool,
    pub max_lines: usize,
    pub should_quit: bool,
    pub aggregate: Aggregate,
    pub sort: SortBy,
    pub screen_filter: ScreenFilter,
    pub capture_filter: Option<String>,
    pub offline: bool,
    pub view: ViewMode,
    pub dropped: Option<Arc<AtomicU64>>,
    pub alerts: Option<AlertEngine>,
}

impl App {
    #[must_use]
    pub fn new(
        flows: SharedFlows,
        dns: Arc<DnsCache>,
        interface: String,
        show_ports: bool,
        enable_dns: bool,
        max_lines: usize,
    ) -> Self {
        Self {
            flows,
            dns,
            interface,
            show_ports,
            no_port_resolution: false,
            use_bytes: false,
            no_bars: false,
            enable_dns,
            max_lines,
            should_quit: false,
            aggregate: Aggregate::Pair,
            sort: SortBy::Rate10s,
            screen_filter: ScreenFilter::default(),
            capture_filter: None,
            offline: false,
            view: ViewMode::Flows,
            dropped: None,
            alerts: None,
        }
    }
}
