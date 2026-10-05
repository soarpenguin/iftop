use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use parking_lot::Mutex;

pub type WorkerMessage = (IpAddr, Arc<crate::dns::cache::DnsCache>);

#[derive(Debug)]
pub struct WorkerPool {
    pub tx: Mutex<SyncSender<WorkerMessage>>,
}

impl WorkerPool {
    #[must_use]
    pub fn new(worker_count: usize, queue_capacity: usize) -> Self {
        let (tx, rx) = sync_channel::<WorkerMessage>(queue_capacity);
        let rx = Arc::new(Mutex::new(rx));

        for _ in 0..worker_count {
            let rx_clone = Arc::clone(&rx);
            thread::spawn(move || worker_loop(&rx_clone));
        }

        Self { tx: Mutex::new(tx) }
    }

    pub fn send(
        &self,
        msg: WorkerMessage,
    ) -> Result<(), std::sync::mpsc::TrySendError<WorkerMessage>> {
        self.tx.lock().try_send(msg)
    }
}

fn worker_loop(rx: &Arc<Mutex<Receiver<WorkerMessage>>>) {
    loop {
        let (ip, cache) = {
            let guard = rx.lock();
            match guard.recv() {
                Ok(item) => item,
                Err(_) => break,
            }
        };
        let name = dns_lookup::lookup_addr(&ip).ok();
        cache.insert(ip, name);
    }
}
