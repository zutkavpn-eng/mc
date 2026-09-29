//! Minecraft-facing server: status ping decoy, login with real encryption,
//! and the play-state session that carries the tunnel.

use crate::config::ServerConfig;
use crate::conn::Conn;
use crate::error::{VpnError, VpnResult};
use crate::ip_pool::IpPool;
use crate::stats::{SharedStats, Stats};
use crate::tunnel::{self, Role, TunnelCrypto, TunnelInfo};
use mc_protocol::packets::{self, kick, play_id, CustomPayload, Handshake};
use mc_protocol::{McError, PROTOCOL_VERSION};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};

pub struct Router {
    /// Client tunnel IP -> per-connection deliver channel (TUN -> client).
    by_ip: Mutex<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>,
    /// Packets from clients -> TUN write side.
    tun_out: mpsc::Sender<Vec<u8>>,
    stats: SharedStats,
}

impl Router {
    async fn deliver_batch(&self, batches: &mut HashMap<Ipv4Addr, Vec<Vec<u8>>>) {
        for (ip, pkts) in batches.drain() {
            let tx = self.by_ip.lock().unwrap().get(&ip).cloned();
            if let Some(tx) = tx {
                // Drop-tail at the per-client queue: a backed-up client gets
                // packet loss (which its TCP flows read as congestion) instead
                // of ever-growing bufferbloat delay. The receiver's
                // anti-replay window tolerates the resulting counter gaps.
                for pkt in pkts {
                    let len = pkt.len() as u64;
                    if tx.try_send(pkt).is_ok() {
                        self.stats.add_up(len);
                    } else {
                        self.stats.add_drop();
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn deliver(&self, ip: Ipv4Addr, pkt: Vec<u8>) {
        let tx = self.by_ip.lock().unwrap().get(&ip).cloned();
        if let Some(tx) = tx {
            if tx.try_send(pkt).is_err() {
                self.stats.add_drop();
            }
        }
    }
    fn register(&self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        self.by_ip.lock().unwrap().insert(ip, tx);
    }
    fn unregister(&self, ip: Ipv4Addr) {
        self.by_ip.lock().unwrap().remove(&ip);
    }
}

pub struct ServerShared {
    pub cfg: ServerConfig,
    pub rsa: mc_protocol::login_crypto::ServerRsaKey,
    pub pool: Mutex<IpPool>,
    pub stats: SharedStats,
    pub router: Arc<Router>,
    pub pending: AtomicU32,
    pub active_sessions: AtomicU32,
    pub per_ip: Mutex<HashMap<IpAddr, Instant>>,
    /// Live connection tasks (aborted together on shutdown so peers see a
    /// real disconnect instead of a half-open session).
    pub conn_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Copy of the tunnel network, so the per-packet source check does not
    /// take the pool mutex (that would serialize every session's uplink).
    pool_base: u32,
    pool_mask: u32,
    pool_gateway: Ipv4Addr,
    /// Usernames of authenticated sessions: the SLP player sample shows the
    /// real roster, like a real server's list.
    usernames: Mutex<Vec<String>>,
    /// Per-boot decoy names, used only while nothing is connected and the
    /// config fakes an online count.
    fake_names: Vec<String>,
}

impl ServerShared {
    fn pool_contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.pool_mask == self.pool_base
    }
}

pub async fn run(
    cfg: ServerConfig,
    device: crate::device::DeviceHandle,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let pool = IpPool::new(&cfg.tunnel_cidr)?;
    let gw = pool.gateway();
    let prefix = pool.prefix();
    let stats: SharedStats = Arc::new(Stats::default());
    let (tun_out_tx, tun_out_rx) = mpsc::channel::<Vec<u8>>(1024);
    let router = Arc::new(Router {
        by_ip: Mutex::new(HashMap::new()),
        tun_out: tun_out_tx,
        stats: Arc::clone(&stats),
    });

    let mut dev = device;
    // TUN data-plane self-test: ping our own gateway address through the TUN
    // and wait for the kernel's echo reply to come back through it. This
    // exercises the exact path client packets take (fd writer -> kernel ->
    // fd reader) BEFORE any client connects, so a broken kernel/container
    // setup is loud in the logs instead of showing up as "connected but no
    // internet".
    if !cfg.mock_device {
        let gw = pool.gateway();
        // Source must look like a client: a packet whose source equals a
        // local address is a martian, and the kernel drops it silently.
        let src = Ipv4Addr::from(u32::from(gw) + 1);
        let probe = crate::probe::icmp_echo_request(src.octets(), gw.octets(), 0x6D63, 1);
        let _ = dev.outbox.send(probe).await;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut ok = false;
        let mut noise = 0u32;
        let mut detail = "timeout: no ICMP echo reply via TUN within 3s".to_string();
        while let Some(remain) = deadline.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(remain, dev.inbox.recv()).await {
                // Accept only OUR IPv4 ICMP echo reply; skip other traffic
                // (IPv6/martian noise, a reconnecting client's packets).
                Ok(Some(pkt))
                    if pkt.len() > 28
                        && pkt[0] >> 4 == 4
                        && pkt[20] == 0
                        && pkt[24] == 0x6D
                        && pkt[25] == 0x63 =>
                {
                    ok = true;
                    break;
                }
                Ok(Some(_)) => {
                    noise += 1;
                    continue;
                }
                Ok(None) => {
                    detail = "device closed".into();
                    break;
                }
                Err(_) => {
                    detail = format!(
                        "timeout: no ICMP echo reply via TUN within 3s ({noise} other packets seen)"
                    );
                    break;
                }
            }
        }
        if ok {
            tracing::info!("TUN self-test: OK (kernel answered our probe via the TUN)");
        } else {
            let iface = dev_name(&cfg);
            tracing::error!(
                "TUN self-test FAILED ({detail}). Packets written to the TUN are not \
                 answered by the kernel: clients will connect but have no internet. Check \
                 `ip addr show {iface}` and `ip link show {iface}`, and whether this VPS \
                 fully supports TUN networking (containers/OpenVZ often do not)."
            );
        }
    }
    let router_task = tokio::spawn({
        let router = Arc::clone(&router);
        let mut inbox = std::mem::replace(&mut dev.inbox, mpsc::channel(1).1);
        async move {
            // Drain bursts per wake and group by destination client.
            let mut batches: HashMap<Ipv4Addr, Vec<Vec<u8>>> = HashMap::new();
            while let Some(first) = inbox.recv().await {
                let mut batch = vec![first];
                while batch.len() < 256 {
                    match inbox.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for pkt in batch {
                    if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
                        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                        batches.entry(dst).or_default().push(pkt);
                    }
                }
                router.deliver_batch(&mut batches).await;
            }
        }
    });

    let rsa =
        mc_protocol::login_crypto::ServerRsaKey::generate(cfg.rsa_bits, &mut rand::rngs::OsRng)?;
    let pool_base = pool.base_u32();
    let pool_mask = pool.mask_u32();
    let pool_gateway = pool.gateway();
    let fake_names = decoy_names(cfg.fake_online);
    let shared = Arc::new(ServerShared {
        cfg,
        rsa,
        pool: Mutex::new(pool),
        stats,
        router,
        pending: AtomicU32::new(0),
        active_sessions: AtomicU32::new(0),
        per_ip: Mutex::new(HashMap::new()),
        conn_tasks: Mutex::new(Vec::new()),
        pool_base,
        pool_mask,
        pool_gateway,
        usernames: Mutex::new(Vec::new()),
        fake_names,
    });

    let bind_addr: SocketAddr = format!("{}:{}", shared.cfg.bind, shared.cfg.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(
        "mcvpn server listening on {} (tunnel gw {} mtu {}, cidr {}/{})",
        bind_addr,
        gw,
        shared.cfg.mtu,
        gw,
        prefix
    );

    // device write pump: tunnel -> TUN
    let write_pump = tokio::spawn(async move {
        let outbox = dev.outbox.clone();
        let mut rx = tun_out_rx;
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            while batch.len() < 256 {
                match rx.try_recv() {
                    Ok(p) => batch.push(p),
                    Err(_) => break,
                }
            }
            for pkt in batch.drain(..) {
                let _ = outbox.send(pkt).await;
            }
        }
        dev.stop_device();
    });

    // Cap concurrent connections (live sessions plus in-flight handshakes): a
    // flood of half-open connections must not spawn unbounded tasks, each with
    // a frame parser that can hold up to 2 MiB.
    let conn_sem = Arc::new(Semaphore::new(
        (shared.cfg.max_clients + shared.cfg.max_pending) as usize,
    ));

    loop {
        tokio::select! {
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    tracing::info!("server shutting down");
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    // EMFILE/ENOBUFS under a connection flood must not take the
                    // whole server down (systemd would restart it into a crash
                    // loop that the flood sustains).
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed, continuing");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if !throttle_ok(&shared, peer.ip()) {
                    drop(stream);
                    continue;
                }
                let permit = match Arc::clone(&conn_sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::debug!(%peer, "connection cap reached, dropping");
                        drop(stream);
                        continue;
                    }
                };
                let conn_shared = Arc::clone(&shared);
                let task = tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_conn(stream, conn_shared).await {
                        tracing::debug!("connection ended: {e}");
                    }
                });
                {
                    let mut tasks = shared.conn_tasks.lock().unwrap();
                    tasks.retain(|t| !t.is_finished());
                    tasks.push(task);
                }
            }
        }
    }
    // Shutdown must reach live sessions too: the accept loop dying alone
    // would leave half-open connections that clients never notice.
    for t in shared.conn_tasks.lock().unwrap().drain(..) {
        t.abort();
    }
    write_pump.abort();
    router_task.abort();
    Ok(())
}

fn dev_name(_cfg: &ServerConfig) -> &'static str {
    "mcvpn0"
}

fn throttle_ok(shared: &ServerShared, ip: IpAddr) -> bool {
    let min = Duration::from_millis(shared.cfg.per_ip_min_interval_ms);
    if min.is_zero() {
        return true;
    }
    let mut map = shared.per_ip.lock().unwrap();
    // Bound the map so a flood of source IPs cannot grow it forever.
    if map.len() > 16_384 {
        let window = min * 8;
        map.retain(|_, t| t.elapsed() < window);
    }
    match map.get(&ip) {
        Some(t) if t.elapsed() < min => false,
        _ => {
            map.insert(ip, Instant::now());
            true
        }
    }
}

/// SLP player sample: the live roster when clients are connected, otherwise
/// per-boot decoys (only if the config fakes an online count).
fn sample_names(shared: &ServerShared) -> Vec<String> {
    let live = shared.usernames.lock().unwrap().clone();
    if !live.is_empty() {
        return live;
    }
    if shared.cfg.fake_online == 0 {
        return Vec::new();
    }
    shared.fake_names.clone()
}

/// Decoy player names for the fake online count. Distinct every boot: a fixed
/// list would be identical on every deployment (a cross-server fingerprint).
fn decoy_names(n: u32) -> Vec<String> {
    const FIRST: [&str; 10] = [
        "Silent", "Swift", "Crimson", "Frost", "Nova", "Ember", "Onyx", "Lunar", "Rusty", "Pixel",
    ];
    const SECOND: [&str; 10] = [
        "Fox", "Wolf", "Crow", "Lynx", "Bear", "Hawk", "Moth", "Otter", "Raven", "Koala",
    ];
    let mut rng = rand::rngs::OsRng;
    (0..n.min(12) as usize)
        .map(|_| {
            let a = FIRST[(rng.next_u32() % FIRST.len() as u32) as usize];
            let b = SECOND[(rng.next_u32() % SECOND.len() as u32) as usize];
            format!("{a}{b}{:02}", rng.next_u32() % 100)
        })
        .collect()
}

fn online_count(shared: &ServerShared) -> u32 {
    let raw = shared
        .active_sessions
        .load(Ordering::Relaxed)
        .max(shared.cfg.fake_online)
    // A real server never shows more players than its max slots (a scanner
    // probing a loaded VPN would otherwise flag "online > max").
    ;
    raw.min(shared.cfg.max_players)
}

/// Forward one authenticated client IP packet toward the TUN (internet side).
/// Returns false only when the data plane is shutting down.
fn route_client_packet(shared: &Arc<ServerShared>, ip_packet: Vec<u8>) -> bool {
    if ip_packet.len() < 20 || ip_packet[0] >> 4 != 4 {
        return true;
    }
    let src = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
    if !shared.pool_contains(src) {
        return true;
    }
    // Client isolation: one client must not reach another client's tunnel
    // address through the server (the gateway stays reachable).
    let dst = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
    if shared.pool_contains(dst) && dst != shared.pool_gateway {
        shared.stats.add_drop();
        return true;
    }
    shared.stats.add_down(ip_packet.len() as u64);
    // A full queue is momentary congestion, not a dead data plane: drop this
    // packet (loss, not latency) and keep the session alive. Only a closed
    // queue ends it.
    match shared.router.tun_out.try_send(ip_packet) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            shared.stats.add_drop();
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

async fn handle_conn(stream: TcpStream, shared: Arc<ServerShared>) -> VpnResult<()> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let mut conn = Conn::from_stream(stream);

    // --- Legacy probe detection (before any framing), like BungeeCord ---
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), conn.read_raw_exact(&mut first))
        .await
        .map_err(|_| VpnError::Timeout)?
        .map_err(VpnError::Io)?;
    if n == 0 {
        return Ok(());
    }
    if let Some(probe) = mc_protocol::legacy::detect(first[0], None) {
        let probe = match probe {
            mc_protocol::legacy::LegacyProbe::Ping(_) => {
                let mut second = [0u8; 1];
                // Bounded: a peer that sends the first 0xFE byte and then
                // stalls must not park a task forever.
                let has_second =
                    tokio::time::timeout(Duration::from_secs(5), conn.read_raw_exact(&mut second))
                        .await
                        .unwrap_or(Ok(0))
                        .unwrap_or(0);
                let second = if has_second == 1 {
                    Some(second[0])
                } else {
                    None
                };
                mc_protocol::legacy::detect(first[0], second).unwrap()
            }
            p => p,
        };
        return respond_legacy(conn, probe, &shared).await;
    }
    conn.seed(&first);

    // --- Handshake ---
    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    let handshake = Handshake::decode(&body)?;
    match handshake.next_state {
        1 => status_flow(conn, &shared).await,
        2 => {
            let r = login_flow(conn, &shared, handshake).await;
            // Real clients that got as far as the login stage: say why they
            // ended (scanners never reach here). This is what you need when a
            // user reports "it doesn't connect".
            match &r {
                Err(e) => tracing::info!(%peer, error = %e, "client session ended with error"),
                Ok(()) => tracing::debug!(%peer, "client session ended"),
            }
            r
        }
        _ => Ok(()), // decode() already rejects other states
    }
}

async fn respond_legacy(
    mut conn: Conn,
    probe: mc_protocol::legacy::LegacyProbe,
    shared: &ServerShared,
) -> VpnResult<()> {
    let online = online_count(shared);
    let bytes = match probe {
        mc_protocol::legacy::LegacyProbe::Ping(true) => {
            mc_protocol::legacy::ping_response_v15(&shared.cfg.motd, online, shared.cfg.max_players)
        }
        mc_protocol::legacy::LegacyProbe::Ping(false) => mc_protocol::legacy::ping_response_beta(
            &shared.cfg.motd,
            online,
            shared.cfg.max_players,
        ),
        mc_protocol::legacy::LegacyProbe::Handshake => mc_protocol::legacy::handshake_response(),
    };
    conn.send_raw(&bytes).await?;
    Ok(())
}

async fn recv_timeout(conn: &mut Conn, d: Duration) -> VpnResult<Vec<u8>> {
    tokio::time::timeout(d, conn.recv())
        .await
        .map_err(|_| VpnError::Timeout)?
}

/// Server List Ping: handshake already parsed; answer status/ping and close.
async fn status_flow(mut conn: Conn, shared: &Arc<ServerShared>) -> VpnResult<()> {
    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    use mc_protocol::packets::status_id;
    if body[0] == status_id::SB_REQUEST {
        let json = mc_protocol::slp::status_json(
            &shared.cfg.motd,
            online_count(shared),
            shared.cfg.max_players,
            &sample_names(shared),
        );
        let resp = packets::StatusResponse { json }.encode();
        conn.send(&resp).await?;
        // Vanilla waits up to 30s for the ping request before closing.
        let ping_body = recv_timeout(&mut conn, Duration::from_secs(30)).await?;
        if ping_body[0] == status_id::SB_PING {
            let ping = packets::Ping::decode(&ping_body)?;
            conn.send(&packets::Pong { time: ping.time }.encode())
                .await?;
        }
    } else if body[0] == status_id::SB_PING {
        let ping = packets::Ping::decode(&body)?;
        conn.send(&packets::Pong { time: ping.time }.encode())
            .await?;
    }
    Ok(())
}

/// Login -> encryption -> play -> tunnel session.
async fn login_flow(
    mut conn: Conn,
    shared: &Arc<ServerShared>,
    handshake: Handshake,
) -> VpnResult<()> {
    use mc_protocol::packets::login_id;

    if !handshake.is_supported_version() {
        let reason = if handshake.protocol_version > PROTOCOL_VERSION {
            kick::outdated_server()
        } else {
            kick::outdated_client()
        };
        tracing::info!(
            protocol = handshake.protocol_version,
            "rejecting client: unsupported protocol version (server speaks 47)"
        );
        conn.send(&packets::LoginDisconnect { reason }.encode())
            .await?;
        return Ok(());
    }

    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    if body[0] != login_id::SB_LOGIN_START {
        return Err(VpnError::Mc(McError::new("expected login start")));
    }
    let login_start = packets::LoginStart::decode(&body)?;

    shared.pending.fetch_add(1, Ordering::Relaxed);
    struct PendingGuard<'a>(&'a AtomicU32);
    impl Drop for PendingGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let pending_guard = PendingGuard(&shared.pending);

    // Vanilla online-mode behavior: send the encryption request.
    let mut verify_token = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut verify_token);
    let enc_req = packets::EncryptionRequest {
        server_id: String::new(),
        public_key: shared.rsa.public_key_der().to_vec(),
        verify_token: verify_token.to_vec(),
    };
    conn.send(&enc_req.encode()).await?;

    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    if body[0] != login_id::SB_ENCRYPTION_RESPONSE {
        return Err(VpnError::Mc(McError::new("expected encryption response")));
    }
    let enc_resp = packets::EncryptionResponse::decode(&body)?;
    let (secret, token) = shared
        .rsa
        .decrypt_response(&enc_resp.shared_secret, &enc_resp.verify_token)?;
    if !tunnel::token_eq(&token, &verify_token) {
        let reason = kick::json("Failed to verify username!");
        conn.send(&packets::LoginDisconnect { reason }.encode())
            .await?;
        return Ok(());
    }
    conn.enable_encryption(&secret);

    // Vanilla order: Set Compression (sent uncompressed framing — the client
    // enables compression only after parsing this packet), then Login Success.
    conn.send(
        &packets::SetCompression {
            threshold: shared.cfg.compression_threshold as i32,
        }
        .encode(),
    )
    .await?;
    conn.set_compression(shared.cfg.compression_threshold as i32);
    let uuid = mc_protocol::login_crypto::offline_uuid_string(&login_start.name);
    conn.send(
        &packets::LoginSuccess {
            uuid,
            username: login_start.name.clone(),
        }
        .encode(),
    )
    .await?;

    // --- Play state ---
    // Vanilla hands out small positive entity ids in join order; a random full
    // i32 (negative half the time) is a client-visible tell.
    let entity_id: i32 = 1 + (rand::rngs::OsRng.next_u32() % 1_000_000) as i32;
    let join = packets::JoinGame {
        entity_id,
        ..Default::default()
    };
    conn.send(&join.encode()).await?;
    let brand = CustomPayload {
        channel: packets::CHANNEL_BRAND.into(),
        data: b"vanilla".to_vec(),
    };
    conn.send(&brand.encode_cb()).await?;

    // Login is complete: this connection no longer counts as "pending". The
    // guard used to live for the whole play session, which silently capped
    // concurrent clients at max_pending (64).
    drop(pending_guard);
    play_session(conn, shared, login_start.name, secret).await
}

/// Releases exactly what the session acquired. The old guard decremented
/// `active_sessions` unconditionally even though only authenticated sessions
/// incremented it: one wrong token / silent client underflowed the u32 to
/// 4294967295 and every later client was told "The server is full!".
struct SessionGuard<'a> {
    shared: &'a Arc<ServerShared>,
    /// Tunnel address taken from the pool (returned on drop).
    ip: Option<Ipv4Addr>,
    /// A `max_clients` slot is held (released on drop).
    counted: bool,
    /// Username advertised in the SLP player sample while this session lives.
    username: Option<String>,
}
impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            self.shared.router.unregister(ip);
            self.shared.pool.lock().unwrap().release(ip);
        }
        if self.counted {
            self.shared.active_sessions.fetch_sub(1, Ordering::AcqRel);
        }
        if let Some(u) = &self.username {
            self.shared.usernames.lock().unwrap().retain(|n| n != u);
        }
    }
}

/// Coalesce queued TUN packets into a single MW|Tunnel payload for one client:
/// one frame/compress/encrypt pass per burst (invisible inside CFB8). One batch
/// per call keeps keep-alive and uplink processing responsive while a bulk
/// transfer runs; a packet that does not fit is stored in `held`, never dropped.
async fn send_downlink_batch(
    conn: &mut Conn,
    crypto: &mut TunnelCrypto,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    first: Vec<u8>,
    held: &mut Option<Vec<u8>>,
) -> VpnResult<()> {
    let mut batch = vec![first];
    let mut bytes = batch[0].len();
    while batch.len() < tunnel::MAX_BATCH_PKTS {
        match rx.try_recv() {
            Ok(p) if bytes + p.len() <= tunnel::MAX_BATCH_BYTES => {
                bytes += p.len();
                batch.push(p);
            }
            Ok(p) => {
                *held = Some(p);
                break;
            }
            Err(_) => break,
        }
    }
    let sealed = if batch.len() == 1 {
        crypto.seal(&batch[0]).map(tunnel::encode_data)
    } else {
        crypto.seal_batch(&batch).map(tunnel::encode_data_batch)
    }?;
    let cp = CustomPayload {
        channel: packets::CHANNEL_TUNNEL.into(),
        data: sealed,
    };
    conn.send_lvl(&cp.encode_cb(), tunnel::BATCH_DEFLATE_LEVEL)
        .await
}

async fn play_session(
    mut conn: Conn,
    shared: &Arc<ServerShared>,
    username: String,
    secret: [u8; 16],
) -> VpnResult<()> {
    use mc_protocol::packets::play_id::{SB_CLIENT_SETTINGS, SB_CUSTOM_PAYLOAD, SB_KEEP_ALIVE};

    let keepalive_interval = Duration::from_secs(shared.cfg.keepalive_secs);
    let mut keepalive_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + keepalive_interval,
        keepalive_interval,
    );
    // Vanilla 1.8.9 kicks a client that stops answering within 30 s; the
    // default 15 s cadence means two missed keep-alives.
    let keepalive_timeout = keepalive_interval.saturating_mul(2);
    let mut pending_keepalive: Option<(u32, Instant)> = None;

    let mut session = SessionGuard {
        shared,
        ip: None,
        counted: false,
        username: None,
    };
    let mut crypto: Option<TunnelCrypto> = None;
    let mut to_client_rx: Option<mpsc::Receiver<Vec<u8>>> = None;
    // A packet held back from a full downlink batch (never dropped).
    let mut held_client: Option<Vec<u8>> = None;
    let mut auth_deadline =
        Some(Instant::now() + Duration::from_secs(shared.cfg.auth_timeout_secs));

    loop {
        // A held-back packet goes first: it has already left the router queue
        // and must not wait for new traffic.
        if let Some(first) = held_client.take() {
            if let Some(c) = crypto.as_mut() {
                if send_downlink_batch(
                    &mut conn,
                    c,
                    to_client_rx.as_mut().expect("rx exists once crypto does"),
                    first,
                    &mut held_client,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            continue;
        }
        let auth_wait = match (auth_deadline, crypto.is_none()) {
            (Some(d), true) => d.saturating_duration_since(Instant::now()),
            _ => Duration::MAX,
        };
        let body = tokio::select! {
            b = conn.recv() => b?,
            _ = tokio::time::sleep(auth_wait), if crypto.is_none() => {
                let reason = kick::not_whitelisted();
                conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                break;
            }
            _ = keepalive_tick.tick() => {
                if let Some((_, sent)) = pending_keepalive {
                    if sent.elapsed() > keepalive_timeout {
                        let reason = kick::timed_out();
                        let _ = conn.send(&packets::PlayDisconnect { reason }.encode()).await;
                        break;
                    }
                }
                // Vanilla derives the id from the system clock; a small random
                // number is something no 1.8.9 server ever sends.
                let id: u32 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u32)
                    .unwrap_or_else(|_| rand::rngs::OsRng.next_u32());
                pending_keepalive = Some((id, Instant::now()));
                conn.send(&packets::PlayKeepAlive { id }.encode()).await?;
                continue;
            }
            pkt = async {
                match to_client_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(pkt) = pkt else { break };
                if let Some(c) = crypto.as_mut() {
                    if send_downlink_batch(
                        &mut conn,
                        c,
                        to_client_rx.as_mut().expect("rx exists once crypto does"),
                        pkt,
                        &mut held_client,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                continue;
            }
        };

        let id = body[0];
        match id {
            SB_KEEP_ALIVE => {
                let ka = packets::PlayKeepAlive::decode(&body)?;
                if let Some((pid, _)) = pending_keepalive {
                    if ka.id == pid {
                        pending_keepalive = None;
                    }
                }
            }
            SB_CLIENT_SETTINGS => {
                let _ = packets::ClientSettings::decode(&body)?; // validated, ignored (vanilla stores it)
            }
            SB_CUSTOM_PAYLOAD => {
                let cp = CustomPayload::decode_sb(&body)?;
                match cp.channel.as_str() {
                    packets::CHANNEL_BRAND => {
                        tracing::debug!(brand = ?String::from_utf8_lossy(&cp.data), "client brand");
                    }
                    packets::CHANNEL_REGISTER | packets::CHANNEL_UNREGISTER => {
                        tracing::debug!(channels = ?String::from_utf8_lossy(&cp.data), "plugin channel registration");
                    }
                    packets::CHANNEL_TUNNEL => match tunnel::decode(&cp.data)? {
                        tunnel::TunnelMsg::Auth { nonce, token } => {
                            if crypto.is_some() {
                                let reason = kick::internal_error();
                                conn.send(&packets::PlayDisconnect { reason }.encode())
                                    .await?;
                                break;
                            }
                            if !tunnel::token_eq(&token, shared.cfg.token.as_bytes()) {
                                tracing::warn!(?username, "bad tunnel token, kicking");
                                let reason = kick::not_whitelisted();
                                conn.send(&packets::PlayDisconnect { reason }.encode())
                                    .await?;
                                break;
                            }
                            // Reserve a slot atomically: check-then-increment let
                            // concurrent logins overshoot max_clients.
                            let prev = shared.active_sessions.fetch_add(1, Ordering::AcqRel);
                            if prev >= shared.cfg.max_clients {
                                shared.active_sessions.fetch_sub(1, Ordering::AcqRel);
                                let reason = kick::server_full();
                                conn.send(&packets::PlayDisconnect { reason }.encode())
                                    .await?;
                                break;
                            }
                            session.counted = true;
                            let ip = shared.pool.lock().unwrap().allocate();
                            let Some(ip) = ip else {
                                let reason = kick::server_full();
                                conn.send(&packets::PlayDisconnect { reason }.encode())
                                    .await?;
                                break;
                            };
                            // The guard owns the address from here on, so a failed
                            // send below can no longer leak it from the pool.
                            session.ip = Some(ip);
                            // The SLP sample lists real players, like a real
                            // server's roster.
                            shared.usernames.lock().unwrap().push(username.clone());
                            session.username = Some(username.clone());
                            crypto = Some(TunnelCrypto::derive(&secret, &nonce, Role::Server)?);
                            let (netmask, gateway) = {
                                let pool = shared.pool.lock().unwrap();
                                (pool.netmask().octets(), pool.gateway().octets())
                            };
                            let info = TunnelInfo {
                                ip: ip.octets(),
                                netmask,
                                gateway,
                                mtu: shared.cfg.mtu,
                                dns: shared
                                    .cfg
                                    .dns
                                    .iter()
                                    .filter_map(|d| d.parse::<Ipv4Addr>().ok())
                                    .map(|d| d.octets())
                                    .collect(),
                            };
                            let ok = CustomPayload {
                                channel: packets::CHANNEL_TUNNEL.into(),
                                data: tunnel::encode_auth_ok(&info),
                            };
                            conn.send(&ok.encode_cb()).await?;
                            let (tx, rx) = mpsc::channel(1024);
                            shared.router.register(ip, tx);
                            to_client_rx = Some(rx);
                            auth_deadline = None;
                            tracing::info!(
                                ?username,
                                ip = %ip,
                                peer = ?conn.peer_addr().ok(),
                                "tunnel session established"
                            );
                        }
                        tunnel::TunnelMsg::Data(sealed) => {
                            let Some(c) = crypto.as_mut() else { continue };
                            match c.open(&sealed) {
                                Ok(ip_packet) => {
                                    if !route_client_packet(shared, ip_packet) {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(?username, error = %e, "bad DATA message, kicking");
                                    let reason = kick::internal_error();
                                    conn.send(&packets::PlayDisconnect { reason }.encode())
                                        .await?;
                                    break;
                                }
                            }
                        }
                        tunnel::TunnelMsg::DataBatch(sealed) => {
                            let Some(c) = crypto.as_mut() else { continue };
                            match c.open_batch(&sealed) {
                                Ok(pkts) => {
                                    for ip_packet in pkts {
                                        if !route_client_packet(shared, ip_packet) {
                                            return Ok(());
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(?username, error = %e, "bad DATA batch, kicking");
                                    let reason = kick::internal_error();
                                    conn.send(&packets::PlayDisconnect { reason }.encode())
                                        .await?;
                                    break;
                                }
                            }
                        }
                        tunnel::TunnelMsg::Ping(v) => {
                            if crypto.is_some() {
                                let pong = CustomPayload {
                                    channel: packets::CHANNEL_TUNNEL.into(),
                                    data: tunnel::encode_pong(v),
                                };
                                conn.send(&pong.encode_cb()).await?;
                            }
                        }
                        tunnel::TunnelMsg::Close(_) => {
                            tracing::info!(?username, "tunnel closed by client");
                            break;
                        }
                        tunnel::TunnelMsg::Unknown => {}
                        _ => {}
                    },
                    other => {
                        tracing::debug!(channel = other, "ignored plugin channel");
                    }
                }
            }
            _ if play_id::sb_known_1_8(id) => {
                // Valid 1.8 serverbound play packet we don't need: ignore
                // silently, like a vanilla server processing it without acting.
            }
            _ => {
                tracing::debug!(packet = id, "unknown serverbound play packet, kicking");
                let reason = kick::internal_error();
                conn.send(&packets::PlayDisconnect { reason }.encode())
                    .await?;
                break;
            }
        }
    }
    Ok(())
}
