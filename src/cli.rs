//! Command-line interface (replaces options.c / getopt).

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "riftop",
    version,
    about = "Display bandwidth usage on an interface by host",
    long_about = None
)]
pub struct Args {
    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short = 'f', long = "filter-code")]
    pub filter: Option<String>,

    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,

    #[arg(short = 'N', long = "no-port-resolution")]
    pub no_port_resolution: bool,

    #[arg(short = 'P', long = "ports")]
    pub ports: bool,

    #[arg(short, long)]
    pub promiscuous: bool,

    #[arg(short = 'B', long = "bytes")]
    pub use_bytes: bool,

    #[arg(short = 'b', long = "no-bars")]
    pub no_bars: bool,

    #[arg(short = 'l', long = "link-local")]
    pub link_local: bool,

    #[arg(short = 'F', long = "net-filter")]
    pub net_filter: Option<String>,

    #[arg(short = 'G', long = "net-filter6")]
    pub net_filter6: Option<String>,

    #[arg(long = "screen-filter")]
    pub screen_filter: Option<String>,

    #[arg(short = 't', long)]
    pub interval_ms: Option<u64>,

    #[arg(long)]
    pub lines: Option<usize>,

    #[arg(long, value_enum)]
    pub sort: Option<SortColumn>,

    #[arg(long = "pcap")]
    pub pcap_file: Option<String>,

    #[arg(long = "output")]
    pub output: Option<String>,

    #[arg(long = "aggregate")]
    pub aggregate: Option<String>,

    #[arg(long = "config")]
    pub config: Option<String>,

    #[arg(long = "alert-rate-bps")]
    pub alert_rate_bps: Option<f64>,

    #[arg(long = "alert-pps")]
    pub alert_pps: Option<f64>,

    /// List interfaces (kind, addrs) and netns, then exit
    #[arg(long = "list-interfaces")]
    pub list_interfaces: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortColumn {
    #[value(name = "2s")]
    Rate2s,
    #[value(name = "10s")]
    Rate10s,
    #[value(name = "40s")]
    Rate40s,
    Source,
    Destination,
}
