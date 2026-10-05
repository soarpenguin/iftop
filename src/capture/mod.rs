//! Packet capture: live device and offline PCAP.

pub mod live;
pub mod pcap;
mod pcap_file;

use std::sync::Arc;

use parking_lot::Mutex;

use crate::flow::FlowTable;

pub use live::{
    local_addresses, open_device, set_filter, spawn_capture_thread, spawn_capture_to_engine,
};
pub use pcap::{process_pcap_file, process_pcap_file_filtered};
pub use pcap_file::open_pcap_file;

pub type SharedFlows = Arc<Mutex<FlowTable>>;
