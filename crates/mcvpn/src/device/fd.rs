//! Raw fd device (Android VpnService ParcelFileDescriptor, or tests).
//! Two OS threads shuttle packets; the reader polls so shutdown is prompt.

use super::{DeviceHandle, TimedPkt};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn from_raw_fd(name: &str, fd: RawFd) -> DeviceHandle {
    let name = name.to_string();
    let rd_name = format!("{name}-rd");
    let wr_name = format!("{name}-wr");
    let dev_name = name.clone();
    let (inbox_tx, inbox_rx) = mpsc::channel::<TimedPkt>(512);
    let (outbox_tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(512);

    let read_fd = unsafe { libc::dup(fd) };
    let write_fd = unsafe { libc::dup(fd) };
    unsafe { libc::close(fd) };
    // Reader polls with O_NONBLOCK so the stop flag is honored promptly.
    unsafe {
        let flags = libc::fcntl(read_fd, libc::F_GETFL);
        libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let reader_name = name.clone();
    let stop_reader = Arc::clone(&stop);
    let stop_writer = Arc::clone(&stop);

    std::thread::Builder::new()
        .name(rd_name)
        .spawn(move || {
            let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            use std::io::Read;
            let mut buf = vec![0u8; 65536];
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                if stop_reader.load(Ordering::Relaxed) {
                    break;
                }
                let r = unsafe { libc::poll(&mut pollfd, 1, 200) };
                if r == -1 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue; // EINTR must not kill the data plane
                    }
                    tracing::warn!(device = %reader_name, error = %err, "device reader poll failed");
                    break;
                }
                if r == 0 {
                    continue;
                }
                loop {
                    match read_file.read(&mut buf) {
                        Ok(0) => {
                            stop_reader.store(true, Ordering::Relaxed);
                            break;
                        }
                        Ok(n) => {
                            if inbox_tx
                                .blocking_send(TimedPkt::now(buf[..n].to_vec()))
                                .is_err()
                            {
                                stop_reader.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            stop_reader.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                if stop_reader.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
        .expect("spawn device reader");

    std::thread::Builder::new()
        .name(wr_name)
        .spawn(move || {
            let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            use std::io::Write;
            while let Some(pkt) = outbox_rx.blocking_recv() {
                if stop_writer.load(Ordering::Relaxed) {
                    break;
                }
                // dup()'d descriptors SHARE the open file description, so the
                // O_NONBLOCK we set for the reader applies to this writer too:
                // a full TUN queue yields EAGAIN. That used to end the writer
                // thread for good (downstream silently dead). Wait for
                // POLLOUT and retry instead; only real errors stop it.
                let mut off = 0;
                while off < pkt.len() {
                    match write_file.write(&pkt[off..]) {
                        Ok(0) => break,
                        Ok(n) => off += n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            let mut pfd = libc::pollfd {
                                fd: write_fd,
                                events: libc::POLLOUT,
                                revents: 0,
                            };
                            unsafe { libc::poll(&mut pfd, 1, 100) };
                            if stop_writer.load(Ordering::Relaxed) {
                                return;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            tracing::warn!(error = %e, "device writer stopped");
                            return;
                        }
                    }
                }
            }
        })
        .expect("spawn device writer");

    let mut handle = DeviceHandle {
        inbox: inbox_rx,
        outbox: outbox_tx,
        name: dev_name,
        stop: None,
        cleanup: None,
    };
    handle.stop = Some(stop);
    handle
}
