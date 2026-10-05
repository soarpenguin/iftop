use crate::config::mod_types::Config;

impl Config {
    /// Merge CLI non-default values over config (CLI wins).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        &mut self,
        interface: &Option<String>,
        filter: &Option<String>,
        net_filter: &Option<String>,
        net_filter6: &Option<String>,
        screen_filter: &Option<String>,
        no_dns: bool,
        no_port_resolution: bool,
        ports: bool,
        use_bytes: bool,
        no_bars: bool,
        link_local: bool,
        promiscuous: bool,
        interval_ms: Option<u64>,
        lines: Option<usize>,
        aggregate: Option<&str>,
        sort: Option<&str>,
        output: Option<&str>,
        alert_rate: Option<f64>,
        alert_pps: Option<f64>,
    ) {
        if interface.is_some() {
            self.interface = interface.clone();
        }
        if filter.is_some() {
            self.filter = filter.clone();
        }
        if net_filter.is_some() {
            self.net_filter = net_filter.clone();
        }
        if net_filter6.is_some() {
            self.net_filter6 = net_filter6.clone();
        }
        if screen_filter.is_some() {
            self.screen_filter = screen_filter.clone();
        }
        if no_dns {
            self.no_dns = true;
        }
        if no_port_resolution {
            self.no_port_resolution = true;
        }
        if ports {
            self.ports = true;
        }
        if use_bytes {
            self.use_bytes = true;
        }
        if no_bars {
            self.no_bars = true;
        }
        if link_local {
            self.link_local = true;
        }
        if promiscuous {
            self.promiscuous = true;
        }
        if let Some(v) = interval_ms {
            self.interval_ms = Some(v);
        }
        if let Some(v) = lines {
            self.lines = Some(v);
        }
        if let Some(v) = aggregate {
            self.aggregate = Some(v.to_string());
        }
        if let Some(v) = sort {
            self.sort = Some(v.to_string());
        }
        if let Some(v) = output {
            self.output = Some(v.to_string());
        }
        if alert_rate.is_some() {
            self.alert_rate_bps = alert_rate;
        }
        if alert_pps.is_some() {
            self.alert_pps = alert_pps;
        }
    }

    #[must_use]
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.unwrap_or(1000)
    }

    #[must_use]
    pub fn lines(&self) -> usize {
        self.lines.unwrap_or(20)
    }

    #[must_use]
    pub fn aggregate(&self) -> &str {
        self.aggregate.as_deref().unwrap_or("pair")
    }

    #[must_use]
    pub fn output(&self) -> &str {
        self.output.as_deref().unwrap_or("tui")
    }
}
