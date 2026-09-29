//! One Minecraft connection: framing, encryption and compression state on
//! top of a TCP stream. `recv`/`send` keep all live state in `self` (plus
//! the OS socket buffer), so the play-state `select!` loops can await
//! `recv` cancel-safely.

use crate::error::{VpnError, VpnResult};
use mc_protocol::cipher::{McCipher, SHARED_SECRET_LEN};
use mc_protocol::frame::FrameParser;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Conn {
    stream: TcpStream,
    parser: FrameParser,
    dec: Option<McCipher>,
    enc: Option<McCipher>,
    threshold: Option<u32>,
}

impl Conn {
    pub async fn connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        Self::apply_socket_opts(&stream);
        Ok(Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
        })
    }

    /// Connect by hostname (or IP) + port; hostnames resolve through the
    /// system resolver, like every real VPN client ("vpn.example.com").
    pub async fn connect_host(host: &str, port: u16, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await??;
        Self::apply_socket_opts(&stream);
        Ok(Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
        })
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self::apply_socket_opts(&stream);
        Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
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
        self.parser.push(bytes);
    }

    pub fn enable_encryption(&mut self, secret: &[u8; SHARED_SECRET_LEN]) {
        self.dec = Some(McCipher::new(secret, false));
        self.enc = Some(McCipher::new(secret, true));
    }

    pub fn set_compression(&mut self, threshold: i32) {
        self.threshold = if threshold >= 0 {
            Some(threshold as u32)
        } else {
            None
        };
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Read exactly one raw (decrypted, decompressed) packet body.
    pub async fn recv(&mut self) -> VpnResult<Vec<u8>> {
        loop {
            if let Some(body) = self.parser.next_packet(self.threshold)? {
                return Ok(body);
            }
            // 64 KiB per syscall instead of 16 KiB: at bulk rates the read
            // loop, not the cipher, is what limits the downlink.
            let mut chunk = [0u8; 65536];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(VpnError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            let data = &mut chunk[..n];
            if let Some(d) = self.dec.as_mut() {
                d.process(data);
            }
            self.parser.push(data);
        }
    }

    /// Append the framed + encrypted packet to `out` (for batched writes).
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
        self.stream.write_all(&frame).await?;
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
        self.stream.write_all(&out).await?;
        Ok(())
    }

    /// Raw write used for legacy ping responses (no framing).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> VpnResult<()> {
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    /// Raw read of a few bytes (legacy probe detection only).
    pub async fn read_raw_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read_exact(buf).await.map(|_| buf.len())
    }
}
