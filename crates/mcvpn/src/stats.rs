use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Stats {
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    pub up_packets: AtomicU64,
    pub down_packets: AtomicU64,
    /// Last measured round-trip in ms (0 = unknown).
    pub rtt_ms: AtomicU32,
    /// Set when the OS actually routed our route-probe datagram into the
    /// tunnel device (proves the routing table sends traffic into the VPN).
    pub probe_seen: std::sync::atomic::AtomicBool,
    /// Tunnel packets dropped at a full per-client queue (drop-tail: loss
    /// makes the TCP flows inside the tunnel back off instead of piling up
    /// queue delay).
    pub dropped: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSnapshot {
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub up_packets: u64,
    pub down_packets: u64,
    pub rtt_ms: u32,
    pub probe_seen: bool,
    pub dropped: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            up_bytes: self.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.down_bytes.load(Ordering::Relaxed),
            up_packets: self.up_packets.load(Ordering::Relaxed),
            down_packets: self.down_packets.load(Ordering::Relaxed),
            rtt_ms: self.rtt_ms.load(Ordering::Relaxed),
            probe_seen: self.probe_seen.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    pub fn add_up(&self, bytes: u64) {
        self.up_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.up_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.down_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.down_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_rtt(&self, ms: u32) {
        self.rtt_ms.store(ms, Ordering::Relaxed);
    }

    pub fn add_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

pub type SharedStats = Arc<Stats>;
