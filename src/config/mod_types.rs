use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    pub interface: Option<String>,
    #[serde(alias = "bpf")]
    pub filter: Option<String>,
    #[serde(alias = "net-filter")]
    pub net_filter: Option<String>,
    #[serde(alias = "net-filter6")]
    pub net_filter6: Option<String>,
    #[serde(alias = "screen-filter")]
    pub screen_filter: Option<String>,
    #[serde(alias = "no-dns")]
    pub no_dns: bool,
    #[serde(alias = "no-port-resolution")]
    pub no_port_resolution: bool,
    pub ports: bool,
    #[serde(alias = "use-bytes", alias = "bytes")]
    pub use_bytes: bool,
    #[serde(alias = "no-bars")]
    pub no_bars: bool,
    #[serde(alias = "link-local")]
    pub link_local: bool,
    pub promiscuous: bool,
    #[serde(alias = "interval-ms")]
    pub interval_ms: Option<u64>,
    pub lines: Option<usize>,
    pub aggregate: Option<String>,
    pub sort: Option<String>,
    pub output: Option<String>,
    /// Alert when any flow rate_10s exceeds this many bytes/sec (bits if use_bits).
    #[serde(alias = "alert-rate-bps")]
    pub alert_rate_bps: Option<f64>,
    /// Alert when global accepted packets/sec exceeds this.
    #[serde(alias = "alert-pps")]
    pub alert_pps: Option<f64>,
}
