//! Flow engine: bounded channel between capture and aggregation.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crate::capture::SharedFlows;
use crate::filters::PacketFilter;
use crate::protocols::TcpFlags;

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub bytes: u64,
    pub when: Instant,
    pub tcp: Option<TcpFlags>,
}

pub struct EngineHandle {
    pub tx: SyncSender<PacketEvent>,
    pub queue_full_drops: Arc<AtomicU64>,
    pub queue_disconnected_drops: Arc<AtomicU64>,
    _join: thread::JoinHandle<()>,
}

impl EngineHandle {
    pub fn try_send(&self, ev: PacketEvent) {
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queue_full_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queue_disconnected_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.queue_full_drops.load(Ordering::Relaxed)
            + self.queue_disconnected_drops.load(Ordering::Relaxed)
    }
}

const DEFAULT_CAPACITY: usize = 8192;

pub fn spawn_engine(
    flows: SharedFlows,
    local_addrs: Vec<IpAddr>,
    filter: PacketFilter,
    capacity: Option<usize>,
) -> EngineHandle {
    let cap = capacity.unwrap_or(DEFAULT_CAPACITY);
    let (tx, rx) = sync_channel::<PacketEvent>(cap);
    let queue_full_drops = Arc::new(AtomicU64::new(0));
    let queue_disconnected_drops = Arc::new(AtomicU64::new(0));
    let full_c = Arc::clone(&queue_full_drops);
    let disc_c = Arc::clone(&queue_disconnected_drops);

    let join = thread::spawn(move || engine_loop(rx, flows, local_addrs, filter));

    EngineHandle {
        tx,
        queue_full_drops: full_c,
        queue_disconnected_drops: disc_c,
        _join: join,
    }
}

fn engine_loop(
    rx: Receiver<PacketEvent>,
    flows: SharedFlows,
    local_addrs: Vec<IpAddr>,
    filter: PacketFilter,
) {
    while let Ok(ev) = rx.recv() {
        flows.lock().record_filtered(
            ev.src,
            ev.dst,
            ev.sport,
            ev.dport,
            ev.protocol,
            ev.bytes,
            &local_addrs,
            ev.when,
            &filter,
            ev.tcp,
        );
    }
}
