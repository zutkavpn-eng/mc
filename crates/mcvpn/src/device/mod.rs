//! IP device abstraction: a pair of channels plus a background thread
//! shuttling packets to/from the OS device (TUN / wintun / Android fd).

use std::time::Instant;
use tokio::sync::mpsc;

/// A device packet with its enqueue time. The AQM (CoDel-style sojourn
/// limit, see `tunnel::MAX_QUEUED_MS`) drops packets that have waited in a
/// backed-up link's queue too long instead of letting a slow radio
/// accumulate seconds of standing queue — loss the inner TCP flows read as
/// congestion, which is exactly the signal they need to converge on the
/// link's real rate.
pub struct TimedPkt {
    pub pkt: Vec<u8>,
    pub ts: Instant,
}

impl TimedPkt {
    pub fn now(pkt: Vec<u8>) -> Self {
        Self {
            pkt,
            ts: Instant::now(),
        }
    }
}

pub struct DeviceHandle {
    /// Packets read from the device (ready to be sent into the tunnel).
    pub inbox: mpsc::Receiver<TimedPkt>,
    /// Packets from the tunnel, to be written into the device.
    pub outbox: mpsc::Sender<Vec<u8>>,
    pub name: String,
    pub(crate) stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Platform cleanup (e.g. Windows route removal) run when the handle drops.
    pub(crate) cleanup: Option<Box<dyn FnOnce() + Send>>,
}

#[cfg(unix)]
pub mod fd;
pub mod mock;

#[cfg(target_os = "linux")]
pub mod tun;

pub mod winroute;

#[cfg(target_os = "windows")]
pub mod wintun;

impl DeviceHandle {
    pub async fn write_packet(&self, pkt: &[u8]) -> crate::error::VpnResult<()> {
        self.outbox
            .send(pkt.to_vec())
            .await
            .map_err(|_| crate::error::VpnError::Device("device closed".into()))
    }

    /// Stop background device threads promptly.
    pub fn stop_device(&self) {
        if let Some(s) = &self.stop {
            s.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Register platform cleanup (e.g. Linux route removal) run on drop.
    pub fn set_cleanup(&mut self, f: Box<dyn FnOnce() + Send>) {
        self.cleanup = Some(f);
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.stop_device();
        if let Some(c) = self.cleanup.take() {
            c();
        }
    }
}
