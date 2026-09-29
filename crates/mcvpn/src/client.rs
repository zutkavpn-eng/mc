//! Client session: connect, Minecraft login, tunnel auth, then the pump
//! loop that moves IP packets between the device and the MW|Tunnel channel.

use crate::config::ClientConfig;
use crate::conn::{spawn_reader_pump, Conn, ConnSender};
use crate::device::{DeviceHandle, TimedPkt};
use crate::error::{VpnError, VpnResult};
use crate::stats::{SharedStats, Stats};
use crate::tunnel::{self, Role, TunnelCrypto, TunnelInfo};
use mc_protocol::packets::{self, play_id, CustomPayload, Handshake};
use mc_protocol::{login_crypto, PROTOCOL_VERSION};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Set when a server kicked us for announcing caps (a pre-0.1.6 server kicks
/// on unknown tunnel messages): stops announcing for the rest of this
/// process, so auto-reconnect cannot loop on the kick. Older servers then
/// get plain single-packet DATA frames only, which they fully understand.
static CAPS_SUPPRESSED: AtomicBool = AtomicBool::new(false);
use tokio::sync::watch;

/// TEST-NET-2 (RFC 5737) address used only to prove routing: never routed on
/// the internet, sits in 128.0.0.0/1 so a working full tunnel MUST capture it.
pub const PROBE_ADDR: [u8; 4] = [198, 51, 100, 77];

/// Send one tiny UDP datagram to [`PROBE_ADDR`] from a normal OS socket. If the
/// routing table really sends traffic into the tunnel device, the pump sees
/// it and sets `Stats::probe_seen`. Do NOT use where the app itself is
/// excluded from the VPN (Android excludes its own package).
pub fn send_route_probe() {
    if let Ok(sock) = std::net::UdpSocket::bind(("0.0.0.0", 0)) {
        let _ = sock.send_to(
            b"mcvpn-route-probe",
            (std::net::Ipv4Addr::from(PROBE_ADDR), 9),
        );
    }
}

pub struct Connected {
    conn: Conn,
    server_ip: Option<std::net::IpAddr>,
    crypto: TunnelCrypto,
    pub info: TunnelInfo,
    pub stats: SharedStats,
    cfg: ClientConfig,
    /// MSG_CAPS was sent on this connection.
    announced_caps: bool,
    /// The server acknowledged CAPS_BATCH (uplink batching is allowed).
    caps_acked: bool,
}

async fn recv_timeout(conn: &mut Conn, d: Duration) -> VpnResult<Vec<u8>> {
    tokio::time::timeout(d, conn.recv())
        .await
        .map_err(|_| VpnError::Timeout)?
}

/// Coalesce one burst of device packets into a single MW|Tunnel payload: one
/// frame/compress/encrypt pass per burst instead of one per packet. The payload
/// lives inside the CFB8 stream, so this is invisible on the wire.
///
/// A packet that does not fit the batch is stored in `held` and sent by the
/// next call — the old `try_recv` drain dropped it, costing one IP packet per
/// batch boundary (retransmits inside the tunnel). Building one batch per call,
/// rather than draining the whole queue, keeps keep-alive, ping and server
/// packets responsive while a bulk transfer is running.
async fn send_one_batch(
    conn: &mut ConnSender,
    crypto: &mut TunnelCrypto,
    device: &mut DeviceHandle,
    stats: &Stats,
    first: TimedPkt,
    held: &mut Option<TimedPkt>,
    allow_batch: bool,
) -> VpnResult<()> {
    let mut batch = vec![first];
    let mut bytes = batch[0].pkt.len();
    while allow_batch && batch.len() < tunnel::MAX_BATCH_PKTS {
        match device.inbox.try_recv() {
            Ok(p) if bytes + p.pkt.len() <= tunnel::MAX_UPLINK_BYTES => {
                bytes += p.pkt.len();
                batch.push(p);
            }
            Ok(p) => {
                *held = Some(p);
                break;
            }
            Err(_) => break,
        }
    }
    // AQM: drop packets that waited too long in a backed-up uplink queue;
    // the inner TCP flows read that loss as congestion and back off to the
    // radio's real rate (CoDel-style), instead of the queue growing without
    // bound and inflating every flow's RTT through it.
    let mut kept: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
    for tp in batch.drain(..) {
        if tunnel::aqm_enabled() && tp.ts.elapsed().as_millis() as u64 > tunnel::MAX_QUEUED_MS {
            stats.add_drop();
        } else {
            kept.push(tp.pkt);
        }
    }
    if kept.is_empty() {
        return Ok(());
    }
    for ip_packet in &kept {
        if ip_packet.len() >= 20 && ip_packet[16..20] == PROBE_ADDR {
            stats
                .probe_seen
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        stats.add_up(ip_packet.len() as u64);
    }
    let sealed = if kept.len() == 1 {
        crypto.seal(&kept[0]).map(tunnel::encode_data)
    } else {
        crypto.seal_batch(&kept).map(tunnel::encode_data_batch)
    }?;
    let cp = CustomPayload {
        channel: packets::CHANNEL_TUNNEL.into(),
        data: sealed,
    };
    conn.send_lvl(&cp.encode_sb(), tunnel::BATCH_DEFLATE_LEVEL)
        .await
}

/// Flatten a JSON chat component reason for display.
pub fn plain_reason(json: &str) -> String {
    let mut s = json.to_string();
    for key in ["text", "translate"] {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
            if let Some(t) = v.get(key).and_then(|t| t.as_str()) {
                s = t.to_string();
                break;
            }
        }
    }
    s
}

/// Perform the full Minecraft login + tunnel auth. On success the caller
/// creates the local device using `info` and calls `attach_device`.
pub async fn connect(cfg: &ClientConfig) -> VpnResult<Connected> {
    connect_impl(
        cfg,
        Arc::new(Stats::default()),
        !CAPS_SUPPRESSED.load(Ordering::Relaxed),
    )
    .await
}

/// Same as [`connect`], but emulates a pre-0.1.6 client on the wire: no caps
/// announcement, so the server must never batch toward it (compat test).
pub async fn connect_no_caps(cfg: &ClientConfig) -> VpnResult<Connected> {
    connect_impl(cfg, Arc::new(Stats::default()), false).await
}

/// Same as [`connect`] but reports into a caller-provided stats holder
/// (GUIs and drivers observe live numbers).
pub async fn connect_with_stats(cfg: &ClientConfig, stats: SharedStats) -> VpnResult<Connected> {
    connect_impl(cfg, stats, !CAPS_SUPPRESSED.load(Ordering::Relaxed)).await
}

async fn connect_impl(
    cfg: &ClientConfig,
    stats: SharedStats,
    announce_caps: bool,
) -> VpnResult<Connected> {
    // Forgiving input: pasted tokens routinely carry invisible whitespace,
    // and people type "ip:port" into the server field.
    let cfg = &cfg.normalized();
    if cfg.server.is_empty() {
        return Err(VpnError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server address is empty",
        )));
    }
    if cfg.token.is_empty() {
        return Err(VpnError::Kick(
            "token is empty — paste the token (or the mcvpn:// link) from the server install output"
                .into(),
        ));
    }
    tracing::info!(server = %cfg.server, port = cfg.port, "connecting (TCP)");
    let mut conn = match format!("{}:{}", cfg.server, cfg.port).parse::<SocketAddr>() {
        Ok(addr) => Conn::connect(addr, Duration::from_secs(10)).await,
        Err(_) => Conn::connect_host(&cfg.server, cfg.port, Duration::from_secs(10)).await,
    }
    .map_err(|e| {
        tracing::warn!(error = %e, "TCP connect failed");
        e
    })?;
    tracing::info!("TCP connected; Minecraft handshake + login");

    // Handshake (host = the hostname we're connecting to, like a real client).
    let hs = Handshake {
        protocol_version: PROTOCOL_VERSION,
        host: cfg.server.clone(),
        port: cfg.port,
        next_state: 2,
    };
    conn.send(&hs.encode()).await?;
    conn.send(
        &packets::LoginStart {
            name: crate::random_username(),
        }
        .encode(),
    )
    .await?;

    // Encryption request (like a vanilla client talking to an online-mode server).
    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    if body[0] == mc_protocol::packets::login_id::CB_DISCONNECT {
        let dc = packets::LoginDisconnect::decode(&body)?;
        return Err(VpnError::Kick(plain_reason(&dc.reason)));
    }
    let enc_req = packets::EncryptionRequest::decode(&body)
        .map_err(|_| VpnError::Mc(mc_protocol::McError::new("expected encryption request")))?;
    tracing::info!(
        pubkey_bytes = enc_req.public_key.len(),
        "login: encryption request received"
    );

    let mut secret = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let (enc_s, enc_t) = login_crypto::client_encrypt_response(
        &enc_req.public_key,
        &secret,
        &enc_req.verify_token,
        &mut rand::rngs::OsRng,
    )?;
    conn.send(
        &packets::EncryptionResponse {
            shared_secret: enc_s,
            verify_token: enc_t,
        }
        .encode(),
    )
    .await?;
    conn.enable_encryption(&secret);
    tracing::info!("login: encryption enabled");

    // From here everything is encrypted: Set Compression, Login Success.
    let mut got_compression = false;
    let mut got_success = false;
    while !(got_compression && got_success) {
        let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
        match body[0] {
            mc_protocol::packets::login_id::CB_SET_COMPRESSION => {
                let sc = packets::SetCompression::decode(&body)?;
                conn.set_compression(sc.threshold);
                got_compression = true;
            }
            mc_protocol::packets::login_id::CB_LOGIN_SUCCESS => {
                let _ = packets::LoginSuccess::decode(&body)?;
                got_success = true;
            }
            mc_protocol::packets::login_id::CB_DISCONNECT => {
                let dc = packets::LoginDisconnect::decode(&body)?;
                return Err(VpnError::Kick(plain_reason(&dc.reason)));
            }
            _ => {
                return Err(VpnError::Mc(mc_protocol::McError::new(
                    "unexpected login packet",
                )))
            }
        }
    }

    // Play-state hello, exactly the burst a vanilla client sends.
    conn.send(&packets::ClientSettings::default().encode())
        .await?;
    let brand = CustomPayload {
        channel: packets::CHANNEL_BRAND.into(),
        data: b"vanilla".to_vec(),
    };
    conn.send(&brand.encode_sb()).await?;
    let register = CustomPayload {
        channel: packets::CHANNEL_REGISTER.into(),
        data: packets::CHANNEL_TUNNEL.as_bytes().to_vec(),
    };
    conn.send(&register.encode_sb()).await?;

    // Tunnel auth inside the encrypted channel.
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let auth = CustomPayload {
        channel: packets::CHANNEL_TUNNEL.into(),
        data: tunnel::encode_auth(&nonce, cfg.token.as_bytes()),
    };
    conn.send(&auth.encode_sb()).await?;

    // Capability announcement right after AUTH: a 0.1.6+ server acknowledges
    // it and both sides may batch; a 0.1.5 server ignores it (Unknown); a
    // 0.1.4 server kicks, which trips CAPS_SUPPRESSED on reconnect.
    if announce_caps {
        let caps = CustomPayload {
            channel: packets::CHANNEL_TUNNEL.into(),
            data: tunnel::encode_caps(tunnel::CAPS_BATCH),
        };
        conn.send(&caps.encode_sb()).await?;
    }

    let deadline = Duration::from_secs(10);
    let start = Instant::now();
    tracing::info!("login: success; play state, authenticating tunnel");
    let (crypto, info) = loop {
        if start.elapsed() > deadline {
            return Err(VpnError::Timeout);
        }
        let body = recv_timeout(&mut conn, deadline).await?;
        match body[0] {
            play_id::CB_JOIN_GAME => {
                let _ = packets::JoinGame::decode(&body)?;
            }
            play_id::CB_CUSTOM_PAYLOAD => {
                let cp = CustomPayload::decode_cb(&body)?;
                if cp.channel == packets::CHANNEL_TUNNEL {
                    match tunnel::decode(&cp.data)? {
                        tunnel::TunnelMsg::AuthOk(info) => {
                            tracing::info!(
                                ip = ?info.ip, mtu = info.mtu, dns = info.dns.len(),
                                "tunnel authenticated"
                            );
                            break (TunnelCrypto::derive(&secret, &nonce, Role::Client)?, info);
                        }
                        _ => return Err(VpnError::Auth),
                    }
                }
            }
            play_id::CB_DISCONNECT => {
                let dc = packets::PlayDisconnect::decode(&body)?;
                return Err(VpnError::Kick(plain_reason(&dc.reason)));
            }
            _ if play_id::cb_known_1_8(body[0]) => {}
            _ => {}
        }
    };

    let server_ip = conn.peer_addr().ok().map(|a| a.ip());
    Ok(Connected {
        conn,
        server_ip,
        crypto,
        info,
        stats,
        cfg: cfg.clone(),
        announced_caps: announce_caps,
        caps_acked: false,
    })
}

impl Connected {
    /// The exact address the TCP connection is using. Desktop clients must
    /// exempt it from the tunnel routes (routing-loop protection).
    pub fn server_ip(&self) -> Option<std::net::IpAddr> {
        self.server_ip
    }

    pub fn info(&self) -> &TunnelInfo {
        &self.info
    }

    pub fn stats(&self) -> SharedStats {
        Arc::clone(&self.stats)
    }

    /// Run the session: device <-> tunnel packet pumps until error/shutdown.
    pub async fn attach_device(
        mut self,
        mut device: DeviceHandle,
        mut shutdown: watch::Receiver<bool>,
    ) -> VpnResult<()> {
        // Split the connection: sends go through the sender, receives come
        // from a reader pump that owns the socket's read side and NEVER
        // stops draining it (see conn.rs).
        let (rd, mut conn_tx) = self.conn.into_parts();
        let mut body_rx = spawn_reader_pump(rd).await;
        let tick_period = Duration::from_millis(50);
        let mut tick = tokio::time::interval(tick_period);
        let ping_period = Duration::from_secs(self.cfg.ping_interval_secs.max(1));
        let mut ping = tokio::time::interval(ping_period);
        ping.reset();
        let mut pending_ping: Option<Instant> = None;
        let mut crypto = self.crypto;
        let stats = Arc::clone(&self.stats);
        let mut held: Option<TimedPkt> = None;
        let mut batch_ok = false;

        loop {
            // A packet held back from a full batch goes first: it has already
            // left the device queue and must not wait for new traffic.
            if let Some(first) = held.take() {
                send_one_batch(
                    &mut conn_tx,
                    &mut crypto,
                    &mut device,
                    &stats,
                    first,
                    &mut held,
                    batch_ok,
                )
                .await?;
                continue;
            }
            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        let close = CustomPayload {
                            channel: packets::CHANNEL_TUNNEL.into(),
                            data: tunnel::encode_close(0),
                        };
                        let _ = conn_tx.send(&close.encode_sb()).await;
                        device.stop_device();
                        return Ok(());
                    }
                }
                pkt = device.inbox.recv() => {
                    let Some(ip_packet) = pkt else {
                        device.stop_device();
                        return Err(VpnError::Device("device closed".into()));
                    };
                    send_one_batch(
                        &mut conn_tx,
                        &mut crypto,
                        &mut device,
                        &stats,
                        ip_packet,
                        &mut held,
                        batch_ok,
                    )
                    .await?;
                }
                _ = tick.tick(), if self.cfg.stealth_tick => {
                    conn_tx.send(&packets::PlayerTick { on_ground: true }.encode()).await?;
                }
                _ = ping.tick() => {
                    if let Some(sent) = pending_ping {
                        if sent.elapsed() > Duration::from_secs(10) {
                            device.stop_device();
                            return Err(VpnError::Timeout);
                        }
                    }
                    let v = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
                    pending_ping = Some(Instant::now());
                    let cp = CustomPayload {
                        channel: packets::CHANNEL_TUNNEL.into(),
                        data: tunnel::encode_ping(v),
                    };
                    conn_tx.send(&cp.encode_sb()).await?;
                }
                body = body_rx.recv() => {
                    let Some(body) = body else {
                        device.stop_device();
                        return Err(VpnError::Kick("closed by server".into()));
                    };
                    match body[0] {
                        play_id::CB_KEEP_ALIVE => {
                            let ka = packets::PlayKeepAlive::decode(&body)?;
                            conn_tx.send(&packets::PlayKeepAlive { id: ka.id }.encode()).await?;
                        }
                        play_id::CB_CUSTOM_PAYLOAD => {
                            let cp = CustomPayload::decode_cb(&body)?;
                            if cp.channel == packets::CHANNEL_TUNNEL {
                                match tunnel::decode(&cp.data)? {
                                    tunnel::TunnelMsg::Data(sealed) => {
                                        let ip_packet = crypto.open(&sealed)?;
                                        stats.add_down(ip_packet.len() as u64);
                                        if device.outbox.send(ip_packet).await.is_err() {
                                            device.stop_device();
                                            return Err(VpnError::Device("device closed".into()));
                                        }
                                    }
                                    tunnel::TunnelMsg::DataBatch(sealed) => {
                                        if !self.announced_caps {
                                            // A server batching toward a
                                            // client that never announced
                                            // caps is mismatched: die exactly
                                            // like a pre-0.1.6 client would.
                                            device.stop_device();
                                            return Err(VpnError::Kick(
                                                "batched data without caps".into(),
                                            ));
                                        }
                                        for ip_packet in crypto.open_batch(&sealed)? {
                                            stats.add_down(ip_packet.len() as u64);
                                            if device.outbox.send(ip_packet).await.is_err() {
                                                device.stop_device();
                                                return Err(VpnError::Device("device closed".into()));
                                            }
                                        }
                                    }
                                    tunnel::TunnelMsg::Pong(_) => {
                                        if let Some(sent) = pending_ping.take() {
                                            let rtt = sent.elapsed();
                                            stats.set_rtt(rtt.as_millis() as u32);
                                        }
                                    }
                                    tunnel::TunnelMsg::CapsAck(flags) => {
                                        if flags & tunnel::CAPS_BATCH != 0 {
                                            batch_ok = true;
                                        }
                                    }
                                    tunnel::TunnelMsg::Caps(_) => {}
                                    tunnel::TunnelMsg::Close(_) => {
                                        device.stop_device();
                                        self.caps_acked = batch_ok;
                                        if self.announced_caps && !batch_ok {
                                            CAPS_SUPPRESSED.store(true, Ordering::Relaxed);
                                            tracing::info!(
                                                "server closed us before acknowledging caps; \
                                                 disabling caps for this process"
                                            );
                                        }
                                        return Err(VpnError::Kick("closed by server".into()));
                                    }
                                    tunnel::TunnelMsg::Unknown => {}
                                    _ => {}
                                }
                            }
                        }
                        play_id::CB_DISCONNECT => {
                            let dc = packets::PlayDisconnect::decode(&body)?;
                            device.stop_device();
                            self.caps_acked = batch_ok;
                            if self.announced_caps && !batch_ok {
                                CAPS_SUPPRESSED.store(true, Ordering::Relaxed);
                                tracing::info!(
                                    "kicked before caps acknowledgment; \
                                     disabling caps for this process"
                                );
                            }
                            return Err(VpnError::Kick(plain_reason(&dc.reason)));
                        }
                        id if play_id::cb_known_1_8(id) => {}
                        _ => {
                            tracing::debug!(packet = body[0], "ignoring unknown clientbound packet");
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientState {
    Connecting,
    Connected,
    Disconnected,
    Error(String),
    Waiting(Duration),
}

/// Continuous client with backoff reconnect (CLI/GUI driver).
pub async fn run_client(
    cfg: ClientConfig,
    stats: SharedStats,
    device_factory: impl Fn(&TunnelInfo, Option<std::net::IpAddr>) -> VpnResult<DeviceHandle>
        + Send
        + Sync
        + 'static,
    mut shutdown: watch::Receiver<bool>,
    on_state: impl Fn(ClientState),
) {
    let mut backoff = Duration::from_millis(500);
    let device_factory = Arc::new(device_factory);
    loop {
        on_state(ClientState::Connecting);
        // Cancelable: pressing Disconnect while "connecting" must not wait
        // out a 10-20 s handshake timeout (or leave a zombie session).
        let attempt = tokio::select! {
            r = connect_with_stats(&cfg, Arc::clone(&stats)) => r,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    on_state(ClientState::Disconnected);
                    return;
                }
                continue;
            }
        };
        match attempt {
            Ok(sess) => {
                backoff = Duration::from_millis(500);
                let info = sess.info().clone();
                let (tx, rx) = watch::channel(false);
                let child_shutdown = rx;
                let mut fwd_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    loop {
                        if fwd_shutdown.changed().await.is_err() {
                            break;
                        }
                        if *fwd_shutdown.borrow() {
                            let _ = tx.send(true);
                            break;
                        }
                    }
                });
                tracing::info!("creating the network device");
                let device = match device_factory(&info, sess.server_ip()) {
                    Ok(d) => d,
                    Err(e) => {
                        // Local network setup failed (adapter/routes/permissions).
                        // Retrying cannot fix it: report and stop, with the reason.
                        tracing::error!(error = %e, "device setup failed");
                        on_state(ClientState::Error(e.to_string()));
                        return;
                    }
                };
                // Only NOW is the VPN actually up: tunnel authenticated AND the
                // OS device/routes configured. (Reporting "connected" before the
                // device existed made the UI green while setup was still failing.)
                tracing::info!("VPN is up");
                on_state(ClientState::Connected);
                match sess.attach_device(device, child_shutdown).await {
                    Ok(()) => {
                        on_state(ClientState::Disconnected);
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "session ended");
                        on_state(ClientState::Error(e.to_string()));
                        if !e.is_retryable() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "connect failed");
                on_state(ClientState::Error(e.to_string()));
                if !e.is_retryable() || *shutdown.borrow() {
                    return;
                }
            }
        }
        on_state(ClientState::Waiting(backoff));
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
