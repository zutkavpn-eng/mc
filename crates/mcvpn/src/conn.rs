//! One Minecraft connection: framing, encryption and compression state on
//! top of a TCP stream. The socket's read and write sides are SEPARATE: a
//! dedicated task owns writes, and play-state sessions pump reads through
//! their own task — a session must never stop reading the socket while
//! blocked writing it (TCP is full-duplex), or two saturated endpoints
//! deadlock each other through their kernel buffers.

use crate::error::{VpnError, VpnResult};
use mc_protocol::cipher::{McCipher, SHARED_SECRET_LEN};
use mc_protocol::frame::FrameParser;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Bounded queue of framed+encrypted buffers toward the socket writer task.
/// Backpressure is preserved (senders wait), but reading the socket never
/// stops: with a dedicated writer, a session blocked writing to a slow peer
/// keeps draining the peer's traffic instead of deadlocking two saturated
/// endpoints against each other through their kernel buffers.
const WRITER_QUEUE: usize = 32;
/// Bounded queue of received packet bodies from a session's reader pump.
pub const READER_QUEUE: usize = 64;

pub struct ConnReader {
    read: OwnedReadHalf,
    parser: FrameParser,
    dec: Option<McCipher>,
    threshold: Option<u32>,
}

pub struct ConnSender {
    peer: SocketAddr,
    writer: mpsc::Sender<Vec<u8>>,
    enc: Option<McCipher>,
    threshold: Option<u32>,
}

/// Login-phase composite: sequential handshake flows use it unchanged.
pub struct Conn {
    rd: ConnReader,
    wr: ConnSender,
}

impl Conn {
    pub async fn connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        Ok(Self::from_stream(stream))
    }

    /// Connect by hostname (or IP) + port; hostnames resolve through the
    /// system resolver, like every real VPN client ("vpn.example.com").
    pub async fn connect_host(host: &str, port: u16, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await??;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self::apply_socket_opts(&stream);
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid addr"));
        let (read, mut write) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        // The socket's write side lives in its own task: the session loops
        // must never stop READING the socket while blocked WRITING it (TCP is
        // full-duplex) — two saturated endpoints that alternate read/write in
        // one select loop deadlock each other through their kernel buffers.
        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if write.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });
        Conn {
            rd: ConnReader {
                read,
                parser: FrameParser::new(),
                dec: None,
                threshold: None,
            },
            wr: ConnSender {
                peer,
                writer: tx,
                enc: None,
                threshold: None,
            },
        }
    }

    fn apply_socket_opts(stream: &TcpStream) {
        let _ = stream.set_nodelay(true);
        let sock = SockRef::from(stream);
        // OS-level keepalive as a backstop for dead peers.
        let _ = sock.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(5)),
        );
        // One TCP stream carries interactive and bulk traffic together, so a
        // large send queue turns a bulk transfer into seconds of added delay
        // for everything behind it (bufferbloat). Keep the unsent queue short:
        // writers then wait for the socket instead of piling data into it.
        // Linux/Android only; other platforms have no equivalent knob.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let lowat: libc::c_uint = 32 * 1024;
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_NOTSENT_LOWAT,
                    &lowat as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
        }
    }

    pub fn seed(&mut self, bytes: &[u8]) {
        self.rd.parser.push(bytes);
    }

    pub fn enable_encryption(&mut self, secret: &[u8; SHARED_SECRET_LEN]) {
        self.rd.dec = Some(McCipher::new(secret, false));
        self.wr.enc = Some(McCipher::new(secret, true));
    }

    pub fn set_compression(&mut self, threshold: i32) {
        let t = if threshold >= 0 {
            Some(threshold as u32)
        } else {
            None
        };
        self.rd.threshold = t;
        self.wr.threshold = t;
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.wr.peer)
    }

    /// Read exactly one raw (decrypted, decompressed) packet body.
    pub async fn recv(&mut self) -> VpnResult<Vec<u8>> {
        self.rd.recv().await
    }

    /// Frame + compress + encrypt + write one packet body.
    pub async fn send(&mut self, body: &[u8]) -> VpnResult<()> {
        self.wr.send(body).await
    }

    /// Same as `send` with an explicit zlib level (wire-invisible: the
    /// compressed payload lives inside the CFB8 stream).
    pub async fn send_lvl(&mut self, body: &[u8], level: u8) -> VpnResult<()> {
        self.wr.send_lvl(body, level).await
    }

    /// Coalesce several packet bodies into a single TCP write.
    pub async fn send_batch<I: IntoIterator<Item = Vec<u8>>>(
        &mut self,
        bodies: I,
    ) -> VpnResult<()> {
        self.wr.send_batch(bodies).await
    }

    /// Raw write used for legacy ping responses (no framing).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> VpnResult<()> {
        self.wr.send_raw(bytes).await
    }

    /// Raw read of a few bytes (legacy probe detection only).
    pub async fn read_raw_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rd.read_raw_exact(buf).await
    }

    /// Split into the two halves for a play-state session: the session loop
    /// sends through `ConnSender` and receives through a reader pump that
    /// owns `ConnReader` (see `spawn_reader_pump`).
    pub fn into_parts(self) -> (ConnReader, ConnSender) {
        (self.rd, self.wr)
    }
}

impl ConnReader {
    /// Read exactly one raw (decrypted, decompressed) packet body.
    pub async fn recv(&mut self) -> VpnResult<Vec<u8>> {
        loop {
            if let Some(body) = self.parser.next_packet(self.threshold)? {
                return Ok(body);
            }
            // 64 KiB per syscall instead of 16 KiB: at bulk rates the read
            // loop, not the cipher, is what limits the downlink.
            let mut chunk = [0u8; 65536];
            let n = self.read.read(&mut chunk).await?;
            if n == 0 {
                return Err(eof());
            }
            let data = &mut chunk[..n];
            if let Some(d) = self.dec.as_mut() {
                d.process(data);
            }
            self.parser.push(data);
        }
    }

    /// Raw read of a few bytes (legacy probe detection only).
    pub async fn read_raw_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read_exact(buf).await.map(|_| buf.len())
    }
}

impl ConnSender {
    fn encode_into(&mut self, body: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        mc_protocol::frame::encode_frame_into(body, self.threshold, out);
        if let Some(e) = self.enc.as_mut() {
            e.process(&mut out[start..]);
        }
    }

    fn encode_into_lvl(&mut self, body: &[u8], out: &mut Vec<u8>, level: u8) {
        let start = out.len();
        mc_protocol::frame::encode_frame_into_lvl(body, self.threshold, level, out);
        if let Some(e) = self.enc.as_mut() {
            e.process(&mut out[start..]);
        }
    }

    /// Frame + compress + encrypt + write one packet body.
    pub async fn send(&mut self, body: &[u8]) -> VpnResult<()> {
        self.send_lvl(body, 6).await
    }

    /// Same as `send` with an explicit zlib level (wire-invisible: the
    /// compressed payload lives inside the CFB8 stream).
    pub async fn send_lvl(&mut self, body: &[u8], level: u8) -> VpnResult<()> {
        let mut frame = Vec::with_capacity(body.len() + 8);
        self.encode_into_lvl(body, &mut frame, level);
        self.writer.send(frame).await.map_err(|_| eof())?;
        Ok(())
    }

    /// Coalesce several packet bodies into a single TCP write.
    pub async fn send_batch<I: IntoIterator<Item = Vec<u8>>>(
        &mut self,
        bodies: I,
    ) -> VpnResult<()> {
        let mut out = Vec::new();
        for body in bodies {
            self.encode_into(&body, &mut out);
        }
        if out.is_empty() {
            return Ok(());
        }
        self.writer.send(out).await.map_err(|_| eof())?;
        Ok(())
    }

    /// Raw write used for legacy ping responses (no framing).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> VpnResult<()> {
        self.writer.send(bytes.to_vec()).await.map_err(|_| eof())?;
        Ok(())
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.peer)
    }
}

/// Pump a session's socket reads into a bounded channel: the session loop
/// must NEVER stop draining the socket, even while its send arm is blocked
/// on a slow peer — otherwise two saturated endpoints that alternate
/// read/write deadlock through their kernel buffers.
pub async fn spawn_reader_pump(mut rd: ConnReader) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(READER_QUEUE);
    tokio::spawn(async move {
        while let Ok(b) = rd.recv().await {
            if tx.send(b).await.is_err() {
                break;
            }
        }
    });
    rx
}

fn eof() -> VpnError {
    VpnError::Io(std::io::ErrorKind::UnexpectedEof.into())
}
