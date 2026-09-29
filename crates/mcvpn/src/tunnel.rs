//! Inner tunnel protocol carried inside MW|Tunnel custom payload packets.
//!
//! Outer stream = byte-exact Minecraft 1.8.9 (login encryption: RSA +
//! AES/CFB8, exactly BungeeCord's stack). Inside, every DATA message is
//! additionally sealed with AES-256-GCM using per-direction keys derived
//! via HKDF-SHA256 from the Minecraft shared secret and a per-session
//! nonce, so IP packets get strong integrity (CFB8 alone is malleable).

use crate::error::{VpnError, VpnResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;

type Nonce = GenericArray<u8, U12>;

pub const VER: u8 = 1;
pub const MSG_AUTH: u8 = 0x01;
pub const MSG_AUTH_OK: u8 = 0x02;
pub const MSG_DATA: u8 = 0x03;
pub const MSG_PING: u8 = 0x04;
pub const MSG_PONG: u8 = 0x05;
pub const MSG_CLOSE: u8 = 0x06;
pub const MSG_DATA_BATCH: u8 = 0x07;
pub const MSG_CAPS: u8 = 0x08;
pub const MSG_CAPS_ACK: u8 = 0x09;

/// Capability flags carried by MSG_CAPS / MSG_CAPS_ACK. A pre-0.1.6 peer
/// rejects unknown tunnel messages, so a client only batches once the
/// server has acknowledged this flag, and the server only batches a client
/// that announced it: old clients never see a batched frame on the wire.
pub const CAPS_BATCH: u8 = 0x01;

/// Coalesced-payload limits: a batch holds at most 255 sealed packets and
/// 32 KiB of plaintext. 32 KiB keeps the serverbound custom payload under
/// vanilla's hard 32767-byte plugin-message limit — a bigger batch would be
/// kicked as "Payload may not be larger than 32767 bytes" by our own decoder
/// (and by any vanilla-shaped one) — and it also bounds the zlib pass.
pub const MAX_BATCH_PKTS: usize = 255;
pub const MAX_BATCH_BYTES: usize = 32_000;
/// Client→server batch cap. A real 1.8.9 client almost never sends large
/// serverbound frames, while a server legitimately streams big clientbound
/// chunk frames: the downlink may batch up to MAX_BATCH_BYTES (chunk-shaped),
/// the uplink stays small so a frame-size observer sees client-like traffic.
pub const MAX_UPLINK_BYTES: usize = 8_000;
/// CoDel-style sojourn limit: a packet that has waited this long in a
/// device/router queue behind a backed-up link is dropped before it is
/// sealed. Caps loaded latency at ~this value per hop instead of letting a
/// slow radio (5G upload) pile up seconds of standing queue, which both
/// destroys interactive latency and collapses throughput (inflated RTT
/// shrinks the outer TCP's effective window).
pub const MAX_QUEUED_MS: u64 = 150;

/// A/B switch for the AQM (default on). `MCVPN_AQM=off` restores the old
/// drop-only-when-full behavior for comparison runs.
pub fn aqm_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("MCVPN_AQM")
            .map(|v| !matches!(v.as_str(), "off" | "0" | "false"))
            .unwrap_or(true)
    })
}
/// zlib level for coalesced tunnel payloads. Invisible on the wire (inside
/// the CFB8 stream): level 0 (stored) skips deflating data that is already
/// high-entropy ciphertext, at the same framing and the same size. Genuine
/// Minecraft-shaped packets keep the Java-default level 6.
pub const BATCH_DEFLATE_LEVEL: u8 = 0;

/// Anti-replay window: how many counters ahead of the acknowledged base the
/// receiver tolerates. Needed because the router now drops under load (rather
/// than buffering without bound), and a dropped packet must not desync the
/// strict counter — IPsec-style sliding window, replays still rejected.
const RECV_WINDOW: u128 = 128;

const HKDF_INFO: &[u8] = b"mcvpn/tunnel/v1";

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mtu: u16,
    pub dns: Vec<[u8; 4]>,
}

#[derive(Debug)]
pub enum TunnelMsg {
    Auth {
        nonce: [u8; 16],
        token: Vec<u8>,
    },
    AuthOk(TunnelInfo),
    Data(Vec<u8>),
    /// Coalesced DATA: the payload is one sealed batch (see `seal_batch`).
    DataBatch(Vec<u8>),
    /// Capability announcement (client → server).
    Caps(u8),
    /// Capability acknowledgment (server → client).
    CapsAck(u8),
    Ping(u64),
    Pong(u64),
    Close(u8),
    /// A message type this version does not know: ignored, like a real
    /// server ignoring unknown plugin-channel payloads (forward compat).
    Unknown,
}

pub fn encode_auth(nonce: &[u8; 16], token: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(3 + token.len());
    m.push(MSG_AUTH);
    m.push(VER);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&(token.len() as u16).to_be_bytes());
    m.extend_from_slice(token);
    m
}

pub fn encode_auth_ok(info: &TunnelInfo) -> Vec<u8> {
    let mut m = Vec::with_capacity(2 + 15 + info.dns.len() * 4);
    m.push(MSG_AUTH_OK);
    m.extend_from_slice(&info.ip);
    m.extend_from_slice(&info.netmask);
    m.extend_from_slice(&info.gateway);
    m.extend_from_slice(&info.mtu.to_be_bytes());
    m.push(info.dns.len() as u8);
    for d in &info.dns {
        m.extend_from_slice(d);
    }
    m
}

pub fn encode_data(sealed: Vec<u8>) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + sealed.len());
    m.push(MSG_DATA);
    m.extend_from_slice(&sealed);
    m
}

pub fn encode_data_batch(sealed: Vec<u8>) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + sealed.len());
    m.push(MSG_DATA_BATCH);
    m.extend_from_slice(&sealed);
    m
}

pub fn encode_ping(v: u64) -> Vec<u8> {
    let mut m = vec![MSG_PING];
    m.extend_from_slice(&v.to_be_bytes());
    m
}

pub fn encode_pong(v: u64) -> Vec<u8> {
    let mut m = vec![MSG_PONG];
    m.extend_from_slice(&v.to_be_bytes());
    m
}

pub fn encode_close(reason: u8) -> Vec<u8> {
    vec![MSG_CLOSE, reason]
}

pub fn encode_caps(flags: u8) -> Vec<u8> {
    vec![MSG_CAPS, flags]
}

pub fn encode_caps_ack(flags: u8) -> Vec<u8> {
    vec![MSG_CAPS_ACK, flags]
}

pub fn decode(msg: &[u8]) -> VpnResult<TunnelMsg> {
    let bad = || VpnError::Crypto("malformed tunnel message".into());
    let mut r = msg;
    let t = r.first().copied().ok_or_else(bad)?;
    r = &r[1..];
    Ok(match t {
        MSG_AUTH => {
            // 1 version + 16 nonce + 2 length + token; a short payload from any
            // peer (this runs server-side on client input) must be an error,
            // never a slice panic.
            if r.len() < 19 || r[0] != VER {
                return Err(bad());
            }
            let nonce: [u8; 16] = r[1..17].try_into().map_err(|_| bad())?;
            let tlen = u16::from_be_bytes([r[17], r[18]]) as usize;
            let rest = &r[19..];
            if rest.len() != tlen || tlen > 4096 {
                return Err(bad());
            }
            TunnelMsg::Auth {
                nonce,
                token: rest.to_vec(),
            }
        }
        MSG_AUTH_OK => {
            if r.len() < 15 {
                return Err(bad());
            }
            let ip: [u8; 4] = r[0..4].try_into().unwrap();
            let netmask: [u8; 4] = r[4..8].try_into().unwrap();
            let gateway: [u8; 4] = r[8..12].try_into().unwrap();
            let mtu = u16::from_be_bytes([r[12], r[13]]);
            let n = r[14] as usize;
            let rest = &r[15..];
            if rest.len() != n * 4 || n > 8 || !(576..=32000).contains(&mtu) {
                return Err(bad());
            }
            TunnelMsg::AuthOk(TunnelInfo {
                ip,
                netmask,
                gateway,
                mtu,
                dns: rest.as_chunks::<4>().0.to_vec(),
            })
        }
        MSG_DATA => TunnelMsg::Data(r.to_vec()),
        MSG_DATA_BATCH => TunnelMsg::DataBatch(r.to_vec()),
        MSG_PING if r.len() == 8 => TunnelMsg::Ping(u64::from_be_bytes(r.try_into().unwrap())),
        MSG_PONG if r.len() == 8 => TunnelMsg::Pong(u64::from_be_bytes(r.try_into().unwrap())),
        MSG_CLOSE if r.len() == 1 => TunnelMsg::Close(r[0]),
        MSG_CAPS if r.len() == 1 => TunnelMsg::Caps(r[0]),
        MSG_CAPS_ACK if r.len() == 1 => TunnelMsg::CapsAck(r[0]),
        // A known type with a malformed payload is an error; only genuinely
        // unknown types are ignored (forward compatibility).
        MSG_PING | MSG_PONG | MSG_CLOSE | MSG_CAPS | MSG_CAPS_ACK => return Err(bad()),
        _ => TunnelMsg::Unknown,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Per-direction AES-256-GCM keys derived from the Minecraft shared secret.
pub struct TunnelCrypto {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_ctr: u128,
    recv_base: u128,
    recv_window: u128,
}

impl TunnelCrypto {
    pub fn derive(shared_secret: &[u8; 16], nonce: &[u8; 16], role: Role) -> VpnResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
        let mut okm = [0u8; 64];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| VpnError::Crypto("hkdf failed".into()))?;
        let (client_key, server_key) = okm.split_at(32);
        let (send, recv) = match role {
            Role::Client => (client_key, server_key),
            Role::Server => (server_key, client_key),
        };
        Ok(TunnelCrypto {
            send: Aes256Gcm::new_from_slice(send).expect("32 byte key"),
            recv: Aes256Gcm::new_from_slice(recv).expect("32 byte key"),
            send_ctr: 0,
            recv_base: 0,
            recv_window: 0,
        })
    }

    fn nonce(ctr: u128) -> Nonce {
        GenericArray::clone_from_slice(&ctr.to_be_bytes()[4..])
    }

    fn seal_inner(&mut self, plaintext: &[u8]) -> VpnResult<Vec<u8>> {
        if self.send_ctr == u128::MAX {
            return Err(VpnError::Crypto("nonce space exhausted".into()));
        }
        let ctr = self.send_ctr;
        self.send_ctr += 1;
        let n = Self::nonce(ctr);
        let ct = self
            .send
            .encrypt(&n, plaintext)
            .map_err(|_| VpnError::Crypto("aes-gcm seal failed".into()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&n);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Seal an IP packet: 12-byte counter nonce + ciphertext+tag.
    pub fn seal(&mut self, ip_packet: &[u8]) -> VpnResult<Vec<u8>> {
        self.seal_inner(ip_packet)
    }

    /// Seal a coalesced batch: ONE GCM message over
    /// `[count][len u16][packet]...`, one counter step for the whole batch.
    pub fn seal_batch(&mut self, pkts: &[Vec<u8>]) -> VpnResult<Vec<u8>> {
        if pkts.is_empty() || pkts.len() > MAX_BATCH_PKTS {
            return Err(VpnError::Crypto("invalid batch size".into()));
        }
        let plain_len = pkts.iter().map(|p| p.len()).sum::<usize>();
        let mut inner = Vec::with_capacity(1 + pkts.len() * 2 + plain_len);
        inner.push(pkts.len() as u8);
        for p in pkts {
            let len = u16::try_from(p.len())
                .map_err(|_| VpnError::Crypto("packet too large for batch".into()))?;
            inner.extend_from_slice(&len.to_be_bytes());
            inner.extend_from_slice(p);
        }
        self.seal_inner(&inner)
    }

    /// Open a sealed DATA blob. Counters must arrive in strict order
    /// (anti-replay); duplicates are rejected, gaps within the window are
    /// tolerated (upstream drops), far-ahead counters jump the window.
    pub fn open(&mut self, blob: &[u8]) -> VpnResult<Vec<u8>> {
        self.open_inner(blob)
    }

    /// Open a sealed batch produced by `seal_batch`.
    pub fn open_batch(&mut self, blob: &[u8]) -> VpnResult<Vec<Vec<u8>>> {
        let inner = self.open_inner(blob)?;
        let bad = || VpnError::Crypto("malformed batch payload".into());
        if inner.is_empty() {
            return Err(bad());
        }
        let count = inner[0] as usize;
        let mut r = &inner[1..];
        let mut out = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            if r.len() < 2 {
                return Err(bad());
            }
            let len = u16::from_be_bytes([r[0], r[1]]) as usize;
            r = &r[2..];
            if r.len() < len {
                return Err(bad());
            }
            total += len;
            if total > MAX_BATCH_BYTES {
                return Err(bad());
            }
            out.push(r[..len].to_vec());
            r = &r[len..];
        }
        if !r.is_empty() {
            return Err(bad());
        }
        Ok(out)
    }

    fn open_inner(&mut self, blob: &[u8]) -> VpnResult<Vec<u8>> {
        if blob.len() < 12 + 16 {
            return Err(VpnError::Crypto("sealed blob too short".into()));
        }
        let (n, ct) = blob.split_at(12);
        let ctr = {
            let mut b = [0u8; 16];
            b[4..].copy_from_slice(n);
            u128::from_be_bytes(b)
        };
        if ctr < self.recv_base {
            return Err(VpnError::Crypto("replayed or reordered counter".into()));
        }
        let offset = ctr - self.recv_base;
        // Compute the next window state, but commit it only after the tag
        // verifies: an unauthenticated blob with a far-ahead counter must not
        // be able to retire the counters below it (the IPsec rule).
        let (next_base, next_window) = if offset >= RECV_WINDOW {
            // Far ahead of the window: everything before it was dropped
            // upstream, so jump the window forward.
            (ctr + 1, 0)
        } else {
            let bit = 1u128 << offset;
            if self.recv_window & bit != 0 {
                return Err(VpnError::Crypto("replayed or reordered counter".into()));
            }
            let mut w = self.recv_window | bit;
            let mut b = self.recv_base;
            while w & 1 != 0 {
                w >>= 1;
                b += 1;
            }
            (b, w)
        };
        let pt = self
            .recv
            .decrypt(&Self::nonce(ctr), ct)
            .map_err(|_| VpnError::Crypto("aes-gcm open failed".into()))?;
        self.recv_base = next_base;
        self.recv_window = next_window;
        Ok(pt)
    }
}

/// Constant-time token comparison.
pub fn token_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TunnelInfo {
        TunnelInfo {
            ip: [100, 64, 0, 2],
            netmask: [255, 192, 0, 0],
            gateway: [100, 64, 0, 1],
            mtu: 1400,
            dns: vec![[1, 1, 1, 1]],
        }
    }

    #[test]
    fn tunnel_msg_roundtrip() {
        let auth = encode_auth(&[7u8; 16], b"tok");
        assert!(matches!(decode(&auth).unwrap(), TunnelMsg::Auth { .. }));
        let ok = encode_auth_ok(&info());
        let TunnelMsg::AuthOk(i) = decode(&ok).unwrap() else {
            panic!()
        };
        assert_eq!(i.ip, [100, 64, 0, 2]);
        assert_eq!(i.mtu, 1400);
        assert_eq!(i.dns, vec![[1, 1, 1, 1]]);
        let ping = encode_ping(42);
        assert!(matches!(decode(&ping).unwrap(), TunnelMsg::Ping(42)));
        assert!(decode(&[MSG_PING, 1, 2]).is_err());
    }

    #[test]
    fn crypto_seal_open_and_replay() {
        let secret = [9u8; 16];
        let nonce = [3u8; 16];
        let mut client = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
        let mut server = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();

        let p1 = vec![0x45, 1, 2, 3, 4, 5, 6, 7, 8];
        let p2 = vec![0x45, 9, 9, 9];
        let s1 = client.seal(&p1).unwrap();
        let s2 = client.seal(&p2).unwrap();
        assert_eq!(server.open(&s1).unwrap(), p1);
        assert_eq!(server.open(&s2).unwrap(), p2);

        // Replay is rejected.
        assert!(server.open(&s1).is_err());
        // A late packet inside the window is accepted (upstream drops must
        // not desync the stream), but the duplicate of it is not.
        let s3 = client.seal(&p1).unwrap();
        let s4 = client.seal(&p2).unwrap();
        assert_eq!(server.open(&s4).unwrap(), p2);
        assert_eq!(server.open(&s3).unwrap(), p1);
        assert!(server.open(&s4).is_err());

        // Tampering is rejected.
        let mut t = client.seal(&p1).unwrap();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(server.open(&t).is_err());

        // Wrong keys (different nonce) cannot open.
        let mut other = TunnelCrypto::derive(&secret, &[4u8; 16], Role::Server).unwrap();
        let s = client.seal(&p1).unwrap();
        assert!(other.open(&s).is_err());
    }

    #[test]
    fn batch_roundtrip_replay_and_tamper() {
        let secret = [5u8; 16];
        let nonce = [8u8; 16];
        let mut client = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
        let mut server = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();

        let pkts: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i; 40 + i as usize]).collect();
        let sealed = client.seal_batch(&pkts).unwrap();
        let opened = server.open_batch(&sealed).unwrap();
        assert_eq!(opened, pkts);

        // Replay of the whole batch is rejected.
        assert!(server.open_batch(&sealed).is_err());
        // Tampering is rejected.
        let mut t = sealed.clone();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(server.open_batch(&t).is_err());

        // Limits: too many packets / a packet too large for u16 framing.
        let many: Vec<Vec<u8>> = (0..MAX_BATCH_PKTS + 1)
            .map(|i| vec![0u8; 10 + i % 5])
            .collect();
        assert!(client.seal_batch(&many).is_err());
        let big = vec![0u8; u16::MAX as usize + 1];
        assert!(client.seal_batch(&[big]).is_err());
    }

    #[test]
    fn counter_gap_from_dropped_packet_is_tolerated() {
        let secret = [7u8; 16];
        let nonce = [2u8; 16];
        let mut client = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
        let mut server = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();

        let a = client.seal(&[1]).unwrap();
        let dropped = client.seal(&[2]).unwrap(); // lost in a full queue
        let c = client.seal(&[3]).unwrap();
        assert_eq!(server.open(&a).unwrap(), vec![1]);
        assert_eq!(server.open(&c).unwrap(), vec![3]);
        // The stream heals: the next fresh packet is still accepted.
        let d = client.seal(&[4]).unwrap();
        assert_eq!(server.open(&d).unwrap(), vec![4]);
        // A late packet still inside the window is accepted once (it may have
        // been delayed, not replayed) — and only once.
        assert_eq!(server.open(&dropped).unwrap(), vec![2]);
        assert!(server.open(&dropped).is_err());
    }

    #[test]
    fn unknown_message_type_is_ignored() {
        assert!(matches!(
            decode(&[0xEE, 1, 2, 3]).unwrap(),
            TunnelMsg::Unknown
        ));
    }

    #[test]
    fn caps_roundtrip_and_malformed() {
        assert!(matches!(
            decode(&encode_caps(CAPS_BATCH)).unwrap(),
            TunnelMsg::Caps(CAPS_BATCH)
        ));
        assert!(matches!(
            decode(&encode_caps_ack(CAPS_BATCH)).unwrap(),
            TunnelMsg::CapsAck(CAPS_BATCH)
        ));
        // Known type, malformed payload: an error, never a panic.
        assert!(decode(&[MSG_CAPS]).is_err());
        assert!(decode(&[MSG_CAPS_ACK, 1, 2]).is_err());
    }
}
