//! Port → service name resolution (replaces serv_hash.c).

use std::collections::HashMap;
use std::sync::OnceLock;

fn table() -> &'static HashMap<(u16, u8), &'static str> {
    static T: OnceLock<HashMap<(u16, u8), &'static str>> = OnceLock::new();
    T.get_or_init(|| {
        let mut m = HashMap::new();
        for (port, name) in [
            (20u16, "ftp-data"),
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "domain"),
            (67, "bootps"),
            (68, "bootpc"),
            (80, "http"),
            (110, "pop3"),
            (123, "ntp"),
            (143, "imap"),
            (443, "https"),
            (465, "smtps"),
            (587, "submission"),
            (993, "imaps"),
            (995, "pop3s"),
            (3306, "mysql"),
            (5432, "postgresql"),
            (6379, "redis"),
            (8080, "http-alt"),
            (8443, "https-alt"),
        ] {
            m.insert((port, 6), name);
            m.insert((port, 17), name);
            m.insert((port, 0), name);
        }
        m
    })
}

pub fn service_name(port: u16, protocol: u8) -> Option<&'static str> {
    let t = table();
    t.get(&(port, protocol))
        .or_else(|| t.get(&(port, 0)))
        .copied()
}

pub fn format_endpoint(host: &str, port: u16, protocol: u8, resolve: bool) -> String {
    if port == 0 {
        return host.to_string();
    }
    if resolve {
        if let Some(name) = service_name(port, protocol) {
            return format!("{host}:{name}");
        }
    }
    format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports() {
        assert_eq!(service_name(443, 6), Some("https"));
        assert_eq!(service_name(22, 6), Some("ssh"));
        assert_eq!(service_name(9999, 6), None);
    }
}
