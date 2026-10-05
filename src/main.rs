//! Riftop — modern iftop-style bandwidth monitor (Rust rewrite of legacy C).

use riftop::alerts;
use riftop::cli;
use riftop::config;
use riftop::interfaces;
use riftop::privileges;
use riftop::ui;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use parking_lot::Mutex;

use alerts::{AlertConfig, AlertEngine};
use cli::Args;
use config::Config;
use interfaces::{current_netns_id, format_iface_table, list_interfaces, pick_default_interface};
use privileges::warn_if_root;
use riftop::capture::{
    local_addresses, open_device, process_pcap_file_filtered, set_filter, spawn_capture_to_engine,
    SharedFlows,
};
use riftop::dns::DnsCache;
use riftop::engine::spawn_engine;
use riftop::export::{write_csv, write_json, write_text, OutputFormat};
use riftop::filters::{PacketFilter, ScreenFilter};
use riftop::flow::{Aggregate, FlowTable, SortBy};
use ui::{init_terminal, restore_terminal, run_ui, App};

fn parse_aggregate(s: &str) -> Aggregate {
    match s.to_ascii_lowercase().as_str() {
        "src" | "source" => Aggregate::Source,
        "dst" | "destination" => Aggregate::Destination,
        _ => Aggregate::Pair,
    }
}

fn main() -> anyhow::Result<()> {
    let _ = warn_if_root(&mut std::io::stderr());

    let args = Args::parse();

    if args.list_interfaces {
        let ifaces = list_interfaces(true).context("list interfaces")?;
        let ns = current_netns_id();
        print!("{}", format_iface_table(&ifaces, ns.as_deref()));
        return Ok(());
    }

    let mut cfg = Config::load(args.config.as_deref().map(Path::new)).context("config")?;
    let sort_str = args.sort.map(|s| match s {
        cli::SortColumn::Rate2s => "2s",
        cli::SortColumn::Rate10s => "10s",
        cli::SortColumn::Rate40s => "40s",
        cli::SortColumn::Source => "source",
        cli::SortColumn::Destination => "destination",
    });

    cfg.apply_cli(
        &args.interface,
        &args.filter,
        &args.net_filter,
        &args.net_filter6,
        &args.screen_filter,
        args.no_dns,
        args.no_port_resolution,
        args.ports,
        args.use_bytes,
        args.no_bars,
        args.link_local,
        args.promiscuous,
        args.interval_ms,
        args.lines,
        args.aggregate.as_deref(),
        sort_str,
        args.output.as_deref(),
        args.alert_rate_bps,
        args.alert_pps,
    );

    let output = OutputFormat::parse(cfg.output());
    let aggregate = parse_aggregate(cfg.aggregate());
    let interval_ms = cfg.interval_ms();
    let lines = cfg.lines();
    let ports = cfg.ports;
    let enable_dns = !cfg.no_dns;

    let alert_engine = AlertEngine::new(AlertConfig {
        rate_bps: cfg.alert_rate_bps,
        pps: cfg.alert_pps,
    });

    let sort_mode = SortBy::parse(cfg.sort.as_deref().unwrap_or("10s"));

    let packet_filter = PacketFilter::from_options(
        cfg.net_filter.as_deref(),
        cfg.net_filter6.as_deref(),
        cfg.link_local,
    )
    .context("invalid net filter")?;

    if let Some(ref path) = args.pcap_file {
        let local_addrs = cfg
            .interface
            .as_deref()
            .map(local_addresses)
            .unwrap_or_default();
        let table = process_pcap_file_filtered(
            path,
            &local_addrs,
            &packet_filter,
            aggregate,
            ports,
            cfg.filter.as_deref(),
        )
        .context("offline PCAP")?;
        let now = table
            .top(1, std::time::Instant::now())
            .first()
            .map(|s| s.last_seen)
            .unwrap_or_else(std::time::Instant::now);

        match output {
            OutputFormat::Json => {
                write_json(&mut std::io::stdout(), &table, now, lines, path, sort_mode)?;
                return Ok(());
            }
            OutputFormat::Text => {
                write_text(
                    &mut std::io::stdout(),
                    &table,
                    now,
                    lines,
                    sort_mode,
                    cfg.use_bytes,
                )?;
                return Ok(());
            }
            OutputFormat::Csv => {
                write_csv(
                    &mut std::io::stdout(),
                    &table,
                    now,
                    lines,
                    sort_mode,
                    cfg.use_bytes,
                )?;
                return Ok(());
            }
            OutputFormat::Tui => {
                let flows: SharedFlows = Arc::new(Mutex::new(table));
                let dns = Arc::new(DnsCache::new());
                let mut terminal = init_terminal().context("terminal")?;
                let mut app = App::new(flows, dns, path.clone(), ports, enable_dns, lines);
                app.offline = true;
                app.aggregate = aggregate;
                app.sort = sort_mode;
                app.use_bytes = cfg.use_bytes;
                app.no_bars = cfg.no_bars;
                app.no_port_resolution = cfg.no_port_resolution;
                app.screen_filter = ScreenFilter::new(cfg.screen_filter.clone());
                app.capture_filter = cfg.filter.clone();
                app.alerts = Some(alert_engine);
                let result = run_ui(&mut app, &mut terminal, interval_ms);
                restore_terminal(&mut terminal)?;
                result.context("UI error")?;
                return Ok(());
            }
        }
    }

    let iface_name = cfg
        .interface
        .clone()
        .or_else(|| pick_default_interface().ok())
        .unwrap_or_else(|| "unknown".into());

    let mut cap = open_device(Some(&iface_name), cfg.promiscuous)
        .context("failed to open capture device (try setcap or root)")?;

    set_filter(&mut cap, cfg.filter.as_deref()).context("invalid BPF filter")?;

    let packet_filter = PacketFilter::from_options(
        cfg.net_filter.as_deref(),
        cfg.net_filter6.as_deref(),
        cfg.link_local,
    )
    .context("invalid net filter")?;

    let local_addrs = local_addresses(&iface_name);
    let mut table = FlowTable::new();
    table.set_aggregate(aggregate);
    table.set_show_ports(ports);
    let flows: SharedFlows = Arc::new(Mutex::new(table));
    let dns = Arc::new(DnsCache::new());

    let engine = spawn_engine(Arc::clone(&flows), local_addrs, packet_filter, None);
    let dropped = Arc::clone(&engine.queue_full_drops);
    let _cap_handle = spawn_capture_to_engine(cap, engine);

    if matches!(
        output,
        OutputFormat::Json | OutputFormat::Text | OutputFormat::Csv
    ) {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let mut table = flows.lock();
        let now = std::time::Instant::now();
        table.expire(now, std::time::Duration::from_secs(60));
        match output {
            OutputFormat::Json => {
                write_json(
                    &mut std::io::stdout(),
                    &table,
                    now,
                    lines,
                    &iface_name,
                    sort_mode,
                )?;
            }
            OutputFormat::Text => write_text(
                &mut std::io::stdout(),
                &table,
                now,
                lines,
                sort_mode,
                cfg.use_bytes,
            )?,
            OutputFormat::Csv => write_csv(
                &mut std::io::stdout(),
                &table,
                now,
                lines,
                sort_mode,
                cfg.use_bytes,
            )?,
            OutputFormat::Tui => {}
        }
        return Ok(());
    }

    let mut terminal = init_terminal().context("failed to initialize terminal")?;
    let mut app = App::new(flows, dns, iface_name, ports, enable_dns, lines);
    app.aggregate = aggregate;
    app.sort = sort_mode;
    app.use_bytes = cfg.use_bytes;
    app.no_bars = cfg.no_bars;
    app.no_port_resolution = cfg.no_port_resolution;
    app.screen_filter = ScreenFilter::new(cfg.screen_filter);
    app.capture_filter = cfg.filter;
    app.dropped = Some(dropped);
    app.alerts = Some(alert_engine);

    let result = run_ui(&mut app, &mut terminal, interval_ms);
    restore_terminal(&mut terminal)?;
    result.context("UI error")?;
    Ok(())
}
