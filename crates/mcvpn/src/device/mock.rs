//! In-memory device pair for tests: whatever one side writes to its device
//! appears in the other side's inbox.

use super::{DeviceHandle, TimedPkt};
use tokio::sync::mpsc;

pub fn mock_pair() -> (DeviceHandle, DeviceHandle) {
    // Both sides keep the plain Vec<u8> outbox API (tests, harness and the
    // GUI push plain packets); stamping bridges feed each inbox, exactly
    // like the TUN reader threads do on real devices.
    fn bridge(mut from: mpsc::Receiver<Vec<u8>>, to: mpsc::Sender<TimedPkt>, name: &'static str) {
        // A plain thread (not tokio::spawn): mock_pair is also called
        // outside async contexts (CLI smoke paths).
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                while let Some(p) = from.blocking_recv() {
                    if to.blocking_send(TimedPkt::now(p)).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn mock bridge");
    }
    let (a_out_tx, a_out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (b_in_tx, b_inbox) = mpsc::channel::<TimedPkt>(256);
    bridge(a_out_rx, b_in_tx, "mock-bridge-a");
    let (b_out_tx, b_out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (a_in_tx, a_inbox) = mpsc::channel::<TimedPkt>(256);
    bridge(b_out_rx, a_in_tx, "mock-bridge-b");
    let a = DeviceHandle {
        inbox: a_inbox,
        outbox: a_out_tx,
        name: "mock-a".into(),
        stop: None,
        cleanup: None,
    };
    let b = DeviceHandle {
        inbox: b_inbox,
        outbox: b_out_tx,
        name: "mock-b".into(),
        stop: None,
        cleanup: None,
    };
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_cross_sides() {
        let (mut a, mut b) = mock_pair();
        a.outbox.send(vec![1, 2, 3]).await.unwrap();
        let got = b.inbox.recv().await.unwrap();
        assert_eq!(got.pkt, vec![1, 2, 3]);
        b.outbox.send(vec![4]).await.unwrap();
        assert_eq!(a.inbox.recv().await.unwrap().pkt, vec![4]);
    }
}
