use std::sync::atomic::Ordering;
use std::time::Instant;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::flow::{format_bytes, Aggregate, Snapshot};
use crate::top::{format_top_row, top_hosts, top_ports, top_protocols, ViewMode};
use crate::ui::app::App;

pub fn draw(f: &mut Frame<'_>, app: &App) {
    let has_alerts = app
        .alerts
        .as_ref()
        .map(|a| a.recent().next().is_some())
        .unwrap_or(false);
    let header_h = if has_alerts { 6 } else { 5 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_h),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(f.area());

    if let Some(chunk) = chunks.first() {
        draw_header(f, *chunk, app);
    }
    if let Some(chunk) = chunks.get(1) {
        draw_table(f, *chunk, app);
    }
    if let Some(chunk) = chunks.get(2) {
        draw_footer(f, *chunk);
    }
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let now = Instant::now();
    let snap = app
        .flows
        .lock()
        .snapshot_sorted(app.max_lines, now, app.sort);
    let g = &snap.globals;
    let drop_n = app
        .dropped
        .as_ref()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(0);

    let agg = match app.aggregate {
        Aggregate::Pair => "pair",
        Aggregate::Source => "src",
        Aggregate::Destination => "dst",
    };
    let mode = if app.offline { "PCAP" } else { "LIVE" };
    let bpf = app.capture_filter.as_deref().unwrap_or("(none)");

    let line1 = format!(
        " {mode}  iface: {}  |  view: {}  |  agg: {agg}  |  DNS: {} ",
        app.interface,
        app.view.title(),
        if app.enable_dns { "on" } else { "off" },
    );
    let line2 = format!(" CAPTURE FILTER: {bpf}");
    let line3 = format!(
        " CAPTURED: {} pkts / {}   VISIBLE: {}   TX {}  RX {}   DROP {} ",
        g.packets_accepted,
        format_bytes(g.bytes_total),
        snap.flows.len().min(app.max_lines),
        format_bytes(g.bytes_sent),
        format_bytes(g.bytes_recv),
        drop_n,
    );

    let mut text = vec![
        Line::from(Span::styled(
            line1,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(line2, Style::default().fg(Color::Yellow))),
        Line::from(Span::styled(line3, Style::default().fg(Color::Green))),
    ];

    if let Some(ae) = &app.alerts {
        if let Some(msg) = ae.latest_messages(1).into_iter().next() {
            text.push(Line::from(Span::styled(
                format!(" ALERT: {msg} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )));
        }
    }

    let header = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Riftop — realtime bandwidth"),
    );
    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame<'_>, area: Rect, app: &App) {
    let now = Instant::now();
    let snap = app.flows.lock().snapshot_sorted(256, now, app.sort);

    if app.enable_dns {
        for stats in &snap.flows {
            app.dns.resolve_async(stats.key.a);
            app.dns.resolve_async(stats.key.b);
        }
    }

    match app.view {
        ViewMode::Flows => draw_flows(f, area, app, &snap, now),
        ViewMode::Hosts => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_hosts(&snap, now, app.max_lines),
        ),
        ViewMode::Ports => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_ports(&snap, now, app.max_lines),
        ),
        ViewMode::Protocols => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_protocols(&snap, now, app.max_lines),
        ),
    }
}

fn draw_flows(f: &mut Frame<'_>, area: Rect, app: &App, snap: &Snapshot, now: Instant) {
    let header_cells = ["#", "Host pair", "2s", "10s", "40s", "Total", "TCP"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows = snap
        .flows
        .iter()
        .filter(|stats| {
            let a = app.dns.display(&stats.key.a, app.enable_dns);
            let b = app.dns.display(&stats.key.b, app.enable_dns);
            app.screen_filter.matches(&a, &b)
        })
        .take(app.max_lines)
        .enumerate()
        .map(|(i, stats)| {
            let a = app.dns.display(&stats.key.a, app.enable_dns);
            let b = app.dns.display(&stats.key.b, app.enable_dns);
            let port_a_str = if app.no_port_resolution {
                stats.key.port_a.to_string()
            } else {
                crate::services::service_name(stats.key.port_a, stats.key.protocol)
                    .map_or_else(|| stats.key.port_a.to_string(), ToString::to_string)
            };
            let port_b_str = if app.no_port_resolution {
                stats.key.port_b.to_string()
            } else {
                crate::services::service_name(stats.key.port_b, stats.key.protocol)
                    .map_or_else(|| stats.key.port_b.to_string(), ToString::to_string)
            };
            let pair = if app.show_ports {
                format!("{a}:{port_a_str} \u{2194} {b}:{port_b_str}")
            } else {
                format!("{a} \u{2194} {b}")
            };
            Row::new([
                Cell::from((i + 1).to_string()),
                Cell::from(pair),
                Cell::from(crate::flow::format_rate_units(
                    stats.rate_2s(now),
                    app.use_bytes,
                )),
                Cell::from(crate::flow::format_rate_units(
                    stats.rate_10s(now),
                    app.use_bytes,
                )),
                Cell::from(crate::flow::format_rate_units(
                    stats.rate_40s(now),
                    app.use_bytes,
                )),
                Cell::from(format_bytes(stats.total_bytes)),
                Cell::from(stats.tcp.summary()),
            ])
        });

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(40),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(14),
    ];
    let t = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top flows"));
    f.render_widget(t, area);
}

fn draw_top_rows(f: &mut Frame<'_>, area: Rect, title: &str, rows_data: &[crate::top::TopRow]) {
    let header_cells = ["#", "Name", "2s", "10s", "40s", "Total"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows = rows_data.iter().enumerate().map(|(i, row)| {
        let (label, r2, r10, r40, tot) = format_top_row(row);
        Row::new([
            Cell::from((i + 1).to_string()),
            Cell::from(label),
            Cell::from(r2),
            Cell::from(r10),
            Cell::from(r40),
            Cell::from(tot),
        ])
    });

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(45),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
    ];
    let t = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(t, area);
}

fn draw_footer(f: &mut Frame<'_>, area: Rect) {
    let help = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("quit  "),
        Span::styled(" 1-4 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("views  "),
        Span::styled(" Tab ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("cycle  "),
        Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("ports"),
    ]);
    let footer = Paragraph::new(help).block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, area);
}
