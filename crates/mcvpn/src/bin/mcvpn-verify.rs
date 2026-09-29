//! End-to-end verification harness. Runs a REAL mcvpn server (mock TUN) and
//! REAL client sessions over TCP on the Minecraft port, through a recording
//! tee proxy that captures the exact bytes a wire observer (DPI) would see.
//!
//! The server's "internet side" is a user-space slirp: ICMP echoes answer
//! locally, UDP/53 queries are forwarded to the REAL 1.1.1.1 resolver, and
//! everything else is echoed back — so the full path (client -> login
//! encryption -> tunnel -> server routing -> back) is measured with real
//! traffic, without needing kernel TUN/NAT (unavailable in sandboxes).

use mcvpn::client::{self, ClientState};
use mcvpn::config::{ClientConfig, ServerConfig};
use mcvpn::device::mock::mock_pair;
use mcvpn::device::DeviceHandle;
use mcvpn::stats::{SharedStats, Stats};
use mcvpn::tunnel::TunnelInfo;
use rand::RngCore;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(clap::Parser, Debug)]
#[command(name = "mcvpn-verify", about = "End-to-end mcvpn verification harness")]
struct Args {
    /// Concurrent clients (same token unless --mixed)
    #[arg(long, default_value_t = 1)]
    clients: usize,
    /// Use two different tokens across the clients
    #[arg(long)]
    mixed: bool,
    /// Soak/throughput seconds
    #[arg(long, default_value_t = 20)]
    seconds: u64,
    /// Tee listen port (the Minecraft-facing port)
    #[arg(long, default_value_t = 25565)]
    port: u16,
    /// Run the kill-server reconnect test
    #[arg(long)]
    reconnect: bool,
    /// Skip the real-internet DNS-through-VPN test
    #[arg(long)]
    skip_dns: bool,
    /// Report JSON path
    #[arg(long, default_value = "verify-report.json")]
    report: String,
    /// pcap capture path (the DPI view)
    #[arg(long, default_value = "verify-capture.pcap")]
    pcap: String,
    /// Timing log path (tsv: ts_us dir conn len)
    #[arg(long, default_value = "verify-capture.tsv")]
    tsv: String,
    /// Remote mode: verify a LIVE server at this host (no local server,
    /// no tee capture; DNS/ICMP/soak run against the real deployment).
    #[arg(long)]
    host: Option<String>,
    /// Token to use (local mode uses its own; remote requires this).
    #[arg(long)]
    token: Option<String>,
    /// Emulate a slow link in the tee: cap throughput at KB/s (0 = off).
    /// Makes the outer TCP + our queues behave like a phone radio.
    #[arg(long, default_value_t = 0)]
    rate: u64,
    /// Emulated link RTT in ms (0 = off): per-direction chunk delay.
    #[arg(long, default_value_t = 0)]
    rtt: u64,
}

/// Token-bucket pacer: emulates a slow link inside the tee so the AQM can
/// be measured the way it behaves on a phone radio.
struct Pacer {
    rate_bps: f64,
    delay: Duration,
    next: Instant,
}

impl Pacer {
    fn new(rate_kbps: u64, rtt_ms: u64) -> Self {
        Self {
            rate_bps: rate_kbps as f64 * 1024.0,
            delay: Duration::from_millis(rtt_ms / 2),
            next: Instant::now(),
        }
    }
    async fn throttle(&mut self, n: usize) {
        if self.delay > Duration::ZERO {
            tokio::time::sleep(self.delay).await;
        }
        if self.rate_bps > 0.0 {
            let now = Instant::now();
            if self.next < now {
                self.next = now;
            }
            self.next += Duration::from_secs_f64(n as f64 / self.rate_bps);
            if self.next > now {
                tokio::time::sleep(self.next - now).await;
            }
        }
    }
}

#[derive(Clone)]
struct Chunk {
    ts_us: u64,
    bytes: Arc<Vec<u8>>, // capped payload (may be a truncated sample)
    full_len: usize,     // real on-wire chunk length
}

struct ConnCapture {
    client_port: u16,
    c2s: Vec<Chunk>,
    s2c: Vec<Chunk>,
}

#[derive(Default)]
struct Capture {
    conns: Mutex<Vec<ConnCapture>>,
}

const CAPTURE_BYTES_PER_DIR: usize = 2 * 1024 * 1024;

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

async fn run_tee(
    listen_port: u16,
    upstream_port: u16,
    cap: Arc<Capture>,
    rate_kbps: u64,
    rtt_ms: u64,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", listen_port)).await?;
    let conn_idx = AtomicU64::new(0);
    loop {
        let (client_sock, _) = listener.accept().await?;
        let idx = conn_idx.fetch_add(1, Ordering::Relaxed) as usize;
        let cap = Arc::clone(&cap);
        tokio::spawn(async move {
            let client_port = client_sock
                .peer_addr()
                .map(|a| a.port())
                .unwrap_or(40000 + idx as u16);
            cap.conns.lock().unwrap().push(ConnCapture {
                client_port,
                c2s: vec![],
                s2c: vec![],
            });
            let server_sock = match TcpStream::connect(("127.0.0.1", upstream_port)).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let (mut cr, mut cw) = client_sock.into_split();
            let (mut sr, mut sw) = server_sock.into_split();
            let mut c_pacer = Pacer::new(rate_kbps, rtt_ms);
            let mut s_pacer = Pacer::new(rate_kbps, rtt_ms);
            // One copy task per direction: a single select loop for both
            // directions head-of-line-blocks — a slow write in one direction
            // stops the reads of the other, which with bounded queues on the
            // endpoints deadlocks the whole chain.
            let cap_c = Arc::clone(&cap);
            let c2s = tokio::spawn(async move {
                let mut recorded = 0usize;
                let mut buf = [0u8; 16384];
                loop {
                    match cr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            c_pacer.throttle(n).await;
                            if sw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let keep = if recorded < CAPTURE_BYTES_PER_DIR {
                                let take = n.min(CAPTURE_BYTES_PER_DIR - recorded);
                                recorded += take;
                                buf[..take].to_vec()
                            } else if idx == 0 {
                                // steady-state sample for entropy analysis
                                buf[..n.min(48)].to_vec()
                            } else {
                                vec![]
                            };
                            cap_c.conns.lock().unwrap()[idx].c2s.push(Chunk {
                                ts_us: now_us(),
                                full_len: n,
                                bytes: Arc::new(keep),
                            });
                        }
                    }
                }
            });
            let cap_s = Arc::clone(&cap);
            let s2c = tokio::spawn(async move {
                let mut recorded = 0usize;
                let mut buf = [0u8; 16384];
                loop {
                    match sr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            s_pacer.throttle(n).await;
                            if cw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let keep = if recorded < CAPTURE_BYTES_PER_DIR {
                                let take = n.min(CAPTURE_BYTES_PER_DIR - recorded);
                                recorded += take;
                                buf[..take].to_vec()
                            } else if idx == 0 {
                                buf[..n.min(48)].to_vec()
                            } else {
                                vec![]
                            };
                            cap_s.conns.lock().unwrap()[idx].s2c.push(Chunk {
                                ts_us: now_us(),
                                full_len: n,
                                bytes: Arc::new(keep),
                            });
                        }
                    }
                }
            });
            let _ = c2s.await;
            let _ = s2c.await;
        });
    }
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn fix_ip(pkt: &mut [u8]) {
    let total = pkt.len();
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
}

fn icmp_reply(mut pkt: Vec<u8>) -> Vec<u8> {
    let (src, dst) = (pkt[12..16].to_vec(), pkt[16..20].to_vec());
    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);
    pkt[20] = 0; // echo reply
    pkt[22..24].copy_from_slice(&[0, 0]);
    let c = ip_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&c.to_be_bytes());
    fix_ip(&mut pkt);
    pkt
}

fn udp_reply(mut pkt: Vec<u8>, payload: Vec<u8>) -> Vec<u8> {
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let orig_sport = pkt[ihl..ihl + 2].to_vec();
    let (src_ip, dst_ip) = (pkt[12..16].to_vec(), pkt[16..20].to_vec());
    pkt[12..16].copy_from_slice(&dst_ip);
    pkt[16..20].copy_from_slice(&src_ip);
    pkt.truncate(ihl);
    // Reply: sport=53, dport=orig sport.
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&[0, 53]);
    udp[2..4].copy_from_slice(&orig_sport);
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&payload);
    // UDP checksum: pseudo-header + UDP.
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&pkt[12..16]);
    pseudo.extend_from_slice(&pkt[16..20]);
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let c = ip_checksum(&pseudo);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    pkt.extend_from_slice(&udp);
    fix_ip(&mut pkt);
    pkt
}

fn swap_echo(mut pkt: Vec<u8>) -> Vec<u8> {
    let (src, dst) = (pkt[12..16].to_vec(), pkt[16..20].to_vec());
    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);
    fix_ip(&mut pkt);
    pkt
}

async fn forward_dns(payload: &[u8]) -> Option<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect("1.1.1.1:53").await.ok()?;
    sock.send(payload).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

/// The "internet" behind the server's TUN: real DNS, local ICMP, echo rest.
async fn run_internet(internet: DeviceHandle) {
    let mut internet = internet;
    while let Some(tp) = internet.inbox.recv().await {
        let pkt = tp.pkt;
        if pkt.len() < 28 || pkt[0] >> 4 != 4 {
            continue;
        }
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        let proto = pkt[9];
        let reply = match proto {
            1 => Some(icmp_reply(pkt)),
            17 => {
                let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                if dst_port == 53 {
                    forward_dns(&pkt[ihl + 8..])
                        .await
                        .map(|answer| udp_reply(pkt, answer))
                } else {
                    Some(swap_echo(pkt))
                }
            }
            _ => Some(swap_echo(pkt)),
        };
        if let Some(r) = reply {
            let _ = internet.outbox.send(r).await;
        }
    }
}

fn server_cfg(port: u16, token: &str) -> ServerConfig {
    ServerConfig {
        bind: "127.0.0.1".into(),
        port,
        token: token.into(),
        motd: "A Minecraft Server".into(),
        compression_threshold: 256,
        rsa_bits: 1024,
        per_ip_min_interval_ms: 0,
        max_clients: 1024,
        keepalive_secs: 15,
        mock_device: true,
        ..Default::default()
    }
}

/// Returns the server task and its shutdown switch.
async fn start_server(
    port: u16,
    token: &str,
) -> (tokio::task::JoinHandle<()>, watch::Sender<bool>) {
    let (server_dev, internet) = mock_pair();
    let cfg = server_cfg(port, token);
    let (_tx, rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        if let Err(e) = mcvpn::server::run(cfg, server_dev, rx).await {
            eprintln!("server error: {e}");
        }
    });
    tokio::spawn(run_internet(internet));
    // Wait until the listener is actually up.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (handle, _tx)
}

fn fake_ip(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    let c = ip_checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

fn icmp_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    let mut pad = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut pad);
    icmp.extend_from_slice(&pad);
    let c = ip_checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    icmp
}

struct ClientRunner {
    os_side: DeviceHandle,
    stats: SharedStats,
    info: TunnelInfo,
}

async fn connect_client_host(host: &str, port: u16, token: &str) -> anyhow::Result<ClientRunner> {
    let cfg = ClientConfig {
        server: host.into(),
        port,
        token: token.into(),
        ping_interval_secs: 1,
        stealth_tick: true,
        auto_reconnect: false,
    };
    let stats: SharedStats = Arc::new(Stats::default());
    let sess = client::connect_with_stats(&cfg, Arc::clone(&stats)).await?;
    let info = sess.info().clone();
    let (dev, os_side) = mock_pair();
    let (_tx, rx) = watch::channel(false);
    std::mem::forget(_tx); // keep the session alive for the whole run
    tokio::spawn(async move {
        let _ = sess.attach_device(dev, rx).await;
    });
    Ok(ClientRunner {
        os_side,
        stats,
        info,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = clap::Parser::parse();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("mcvpn=debug"))
        .try_init();
    let cap = Arc::new(Capture::default());

    // Remote mode: everything runs against a LIVE server (their VPS).
    let remote_host = args.host.clone();
    let token_a = args
        .token
        .clone()
        .unwrap_or_else(|| "verify-token-alpha".into());
    let token_b = "verify-token-beta";
    let mut server_task = None;
    let mut server_switch = None;
    if remote_host.is_none() {
        // Tee on the Minecraft-facing port; real server behind it.
        tokio::spawn(run_tee(
            args.port,
            25566,
            Arc::clone(&cap),
            args.rate,
            args.rtt,
        ));
        let (task, switch) = start_server(25566, &token_a).await;
        server_task = Some(task);
        server_switch = Some(switch);
        // Wait until the tee listener is actually up.
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", args.port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    println!(
        "== mcvpn verification: {} client(s), {}s soak, target: {} ==",
        args.clients,
        args.seconds,
        remote_host.clone().unwrap_or_else(|| "local".into()),
    );

    let mut runners = Vec::new();
    let mut ips = Vec::new();
    for i in 0..args.clients {
        if i > 0 && remote_host.is_some() {
            // The server's per-IP connect throttle (BungeeCord-style, 1s
            // default) resets rapid sequential connects from one source IP;
            // real users never appear within the same second, so stagger.
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
        let token = if args.mixed && i % 2 == 1 {
            token_b
        } else {
            token_a.as_str()
        };
        let host = remote_host.clone().unwrap_or_else(|| "127.0.0.1".into());
        let r = connect_client_host(&host, args.port, token).await?;
        ips.push(Ipv4Addr::from(r.info.ip));
        runners.push(r);
    }
    println!(
        "connected {} client(s), tunnel IPs: {:?}",
        runners.len(),
        ips
    );
    assert!(
        ips.iter().collect::<std::collections::HashSet<_>>().len() == ips.len(),
        "clients must get unique tunnel IPs"
    );

    // DNS through the VPN (real 1.1.1.1 resolver), vs direct.
    let mut dns_result = serde_json::json!({"skipped": true});
    if !args.skip_dns {
        let r = runners.first_mut().unwrap();
        let mut query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec();
        let pkt = fake_ip(r.info.ip, [1, 1, 1, 1], 17, &{
            let mut udp = vec![0u8; 8];
            udp[0..2].copy_from_slice(&43210u16.to_be_bytes());
            udp[2..4].copy_from_slice(&53u16.to_be_bytes());
            udp[4..6].copy_from_slice(&((8 + query.len()) as u16).to_be_bytes());
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&r.info.ip);
            pseudo.extend_from_slice(&[1, 1, 1, 1]);
            pseudo.push(0);
            pseudo.push(17);
            pseudo.extend_from_slice(&((8 + query.len()) as u16).to_be_bytes());
            pseudo.extend_from_slice(&udp);
            let _ = &mut query;
            pseudo.extend_from_slice(&query);
            let c = ip_checksum(&pseudo);
            udp[6..8].copy_from_slice(&c.to_be_bytes());
            let mut full = udp;
            full.extend_from_slice(&query);
            full
        });
        let t0 = Instant::now();
        r.os_side.outbox.send(pkt).await?;
        let reply = match tokio::time::timeout(Duration::from_secs(5), r.os_side.inbox.recv()).await
        {
            Ok(Some(p)) => p.pkt,
            _ => anyhow::bail!("no DNS reply through the tunnel"),
        };
        let dns_rtt = t0.elapsed().as_millis() as u64;
        // count answers in the DNS reply (ANCOUNT at offset 6)
        let answers = u16::from_be_bytes([reply[34], reply[35]]);
        // direct baseline
        let t1 = Instant::now();
        let direct = forward_dns(&query).await;
        let direct_rtt = t1.elapsed().as_millis() as u64;
        dns_result = serde_json::json!({
            "ok": answers > 0,
            "answers": answers,
            "rtt_ms": dns_rtt,
            "direct_rtt_ms": direct_rtt,
            "direct_ok": direct.map(|d| !d.is_empty()).unwrap_or(false),
        });
        println!(
            "DNS through VPN (real 1.1.1.1): ok={} answers={} rtt={}ms (direct {}ms)",
            answers > 0,
            answers,
            dns_rtt,
            direct_rtt
        );
    }

    // ICMP full-path RTT per client.
    let mut icmp_rtts = Vec::new();
    let mut gw_rtts = Vec::new();
    for (i, r) in runners.iter_mut().enumerate() {
        let pkt = fake_ip(r.info.ip, [1, 1, 1, 1], 1, &icmp_echo_request(i as u16, 1));
        let t0 = Instant::now();
        r.os_side.outbox.send(pkt).await?;
        let reply = match tokio::time::timeout(Duration::from_secs(5), r.os_side.inbox.recv()).await
        {
            Ok(Some(p)) => p.pkt,
            _ => continue,
        };
        if reply.len() > 20 && reply[20] == 0 {
            icmp_rtts.push(t0.elapsed().as_millis() as u64);
        }
        // Gateway ping: answered by the server's own kernel (no NAT or
        // forwarding needed). If this answers but 1.1.1.1 doesn't, the
        // tunnel data plane is fine and the server's NAT/forwarding broke.
        let gw_pkt = fake_ip(r.info.ip, r.info.gateway, 1, &icmp_echo_request(0x0E0E, 1));
        let t1 = Instant::now();
        r.os_side.outbox.send(gw_pkt).await?;
        if let Ok(Some(reply)) =
            tokio::time::timeout(Duration::from_secs(5), r.os_side.inbox.recv()).await
        {
            if reply.pkt.len() > 20 && reply.pkt[20] == 0 {
                gw_rtts.push(t1.elapsed().as_millis() as u64);
            }
        }
    }
    println!("ICMP full-path RTT: {:?} ms", icmp_rtts);
    println!(
        "gateway ping RTT (kernel-local, no NAT): {:?} ms{}",
        gw_rtts,
        if gw_rtts.is_empty() {
            ""
        } else {
            "  => tunnel data plane OK"
        }
    );

    // Throughput + stability soak: all clients push 1300B packets continuously.
    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    #[derive(Default)]
    struct SoakShared {
        echoed: u64,
        probe_sent_at: Option<Instant>,
        loaded_rtts: Vec<u64>,
        dead: bool,
    }
    let mut tasks = Vec::new();
    let mut drains = Vec::new();
    let mut soak_shared = Vec::new();
    for (i, r) in runners.into_iter().enumerate() {
        let mut os_side = r.os_side;
        let stats = r.stats;
        let ip = ips[i];
        // Ookla-style loaded latency: ICMP probes sent DURING the bulk
        // transfer, their RTT is what a user feels as "ping jumps while
        // something loads". Probe id is unique per client so replies can be
        // told apart from echoed bulk traffic.
        let probe_id: u16 = 0xB000 + (i as u16 & 0x0FFF);
        let shared = Arc::new(std::sync::Mutex::new(SoakShared::default()));
        let drain_shared = Arc::clone(&shared);
        // Echoes (and probe replies) MUST be drained by a separate task that
        // never stops: when the link is paced, the uplink channel backpressures
        // the push loop, and a push loop that stops draining deadlocks the
        // client's bounded downlink queue against its single select loop.
        // DeviceHandle implements Drop (stop/cleanup): take the channel
        // endpoints out with mem::replace, then drop the husk. The mock has
        // no stop/cleanup, so this is purely a move-check workaround.
        let mut inbox = std::mem::replace(
            &mut os_side.inbox,
            tokio::sync::mpsc::channel::<mcvpn::device::TimedPkt>(1).1,
        );
        let drain_deadline = deadline + Duration::from_secs(3);
        drains.push(tokio::spawn(async move {
            loop {
                let remain = drain_deadline.saturating_duration_since(Instant::now());
                if remain.is_zero() {
                    break;
                }
                match tokio::time::timeout(remain, inbox.recv()).await {
                    Ok(Some(p)) => {
                        let pkt = p.pkt;
                        let mut g = drain_shared.lock().unwrap();
                        if let Some(t0) = g.probe_sent_at {
                            if pkt.len() > 28
                                && pkt[20] == 0
                                && u16::from_be_bytes([pkt[24], pkt[25]]) == probe_id
                            {
                                g.loaded_rtts.push(t0.elapsed().as_millis() as u64);
                                g.probe_sent_at = None;
                            }
                        }
                        g.echoed += pkt.len() as u64;
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }));
        soak_shared.push(Arc::clone(&shared));
        let outbox = std::mem::replace(
            &mut os_side.outbox,
            tokio::sync::mpsc::channel::<Vec<u8>>(1).0,
        );
        drop(os_side);
        let push_shared = Arc::clone(&shared);
        tasks.push(tokio::spawn(async move {
            let mut sent: u64 = 0;
            let payload = vec![0x42u8; 1280];
            let mut last_probe = Instant::now() - Duration::from_secs(10);
            while Instant::now() < deadline {
                if last_probe.elapsed() >= Duration::from_millis(700) {
                    last_probe = Instant::now();
                    let pkt = fake_ip(
                        ip.octets(),
                        [1, 1, 1, 1],
                        1,
                        &icmp_echo_request(probe_id, 1),
                    );
                    if outbox.send(pkt).await.is_ok() {
                        push_shared.lock().unwrap().probe_sent_at = Some(Instant::now());
                    }
                }
                for _ in 0..64 {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let pkt = fake_ip(ip.octets(), [9, 9, 9, 9], 6, &payload);
                    if outbox.send(pkt).await.is_err() {
                        push_shared.lock().unwrap().dead = true;
                        break;
                    }
                    sent += 1;
                }
                tokio::task::yield_now().await;
            }
            (sent, stats)
        }));
    }
    // Wait for the pushes, then the drains (they self-terminate at
    // deadline+3s so late echoes are still counted).
    let mut push_results = Vec::new();
    for t in tasks.into_iter() {
        push_results.push(t.await?);
    }
    for d in drains.into_iter() {
        let _ = d.await;
    }
    let mut per_client = Vec::new();
    let mut total_sent = 0u64;
    let mut total_echoed = 0u64;
    let mut any_dead = false;
    for (i, (sent, stats)) in push_results.into_iter().enumerate() {
        let g = soak_shared[i].lock().unwrap();
        any_dead |= g.dead;
        total_sent += sent;
        total_echoed += g.echoed;
        let loaded_rtts = g.loaded_rtts.clone();
        let echoed = g.echoed;
        drop(g);
        let snap = stats.snapshot();
        per_client.push(serde_json::json!({
            "ip": ips[i].to_string(),
            "packets_up": sent,
            "mb_up": sent as f64 * 1300.0 / 1048576.0,
            "mb_echoed_down": echoed as f64 / 1048576.0,
            "tunnel_up_bytes": snap.up_bytes,
            "tunnel_down_bytes": snap.down_bytes,
            "protocol_rtt_ms": snap.rtt_ms,
            "loaded_rtt_max_ms": loaded_rtts.iter().copied().max().unwrap_or(0),
            "loaded_rtt_avg_ms": if loaded_rtts.is_empty() {
                0
            } else {
                loaded_rtts.iter().sum::<u64>() / loaded_rtts.len() as u64
            },
        }));
    }
    let secs = args.seconds as f64;
    let up_mib_s = total_sent as f64 * 1300.0 / 1048576.0 / secs;
    let down_mib_s = total_echoed as f64 / 1048576.0 / secs;
    println!(
        "throughput: up {up_mib_s:.2} MiB/s, echoed-down {down_mib_s:.2} MiB/s across {} clients",
        args.clients
    );
    let loaded: Vec<u64> = per_client
        .iter()
        .filter_map(|c| c.get("loaded_rtt_max_ms").and_then(|v| v.as_u64()))
        .collect();
    if !loaded.is_empty() {
        println!(
            "loaded latency (probe during bulk): max {} ms, avg {} ms",
            loaded.iter().copied().max().unwrap_or(0),
            loaded.iter().sum::<u64>() / loaded.len() as u64
        );
    }
    println!("clients lost mid-soak: {}", any_dead as usize);

    // Reconnect test: kill the server, restart, expect the client to come back.
    let mut reconnect = serde_json::json!({"skipped": true});
    if args.reconnect && remote_host.is_some() {
        println!("reconnect: skipped in remote mode (needs control of the server)");
    } else if args.reconnect {
        let cfg = ClientConfig {
            server: "127.0.0.1".into(),
            port: args.port,
            token: token_a.clone(),
            ping_interval_secs: 1,
            stealth_tick: true,
            auto_reconnect: true,
        };
        let states: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let st = Arc::clone(&states);
        let (shut_tx, shut_rx) = watch::channel(false);
        let runner = tokio::spawn(client::run_client(
            cfg,
            Arc::new(Stats::default()),
            move |_info, _server_ip| {
                let (a, peer) = mock_pair();
                std::mem::forget(peer);
                Ok(a)
            },
            shut_rx,
            move |s| {
                let name = match s {
                    ClientState::Connecting => "connecting",
                    ClientState::Connected => "connected",
                    ClientState::Disconnected => "disconnected",
                    ClientState::Error(_) => "error",
                    ClientState::Waiting(_) => "waiting",
                };
                st.lock().unwrap().push(name.into());
            },
        ));
        tokio::time::sleep(Duration::from_secs(3)).await;
        server_switch.as_ref().unwrap().send(true).ok();
        // Give the server a moment to drain live sessions (graceful close),
        // so the client actually sees the disconnect instead of a half-open TCP.
        tokio::time::sleep(Duration::from_secs(1)).await;
        server_task.as_ref().unwrap().abort();
        println!("reconnect: server killed (graceful: sessions closed)");
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _server2 = start_server(25566, &token_a).await;
        let mut back = false;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if states
                .lock()
                .unwrap()
                .iter()
                .filter(|s| *s == "connected")
                .count()
                >= 2
            {
                back = true;
                break;
            }
        }
        let history = states.lock().unwrap().join(",");
        shut_tx.send(true).ok();
        runner.abort();
        reconnect = serde_json::json!({ "reconnected": back, "states": history });
        println!("reconnect: back={} states={}", back, history);
    }

    // Write capture artifacts + report.
    write_tsv(&args.tsv, &cap)?;
    write_pcap(&args.pcap, args.port, &cap)?;
    let report = serde_json::json!({
        "target": remote_host.clone().unwrap_or_else(|| "local".into()),
        "clients": args.clients,
        "tokens": if args.mixed { "mixed" } else { "same" },
        "soak_seconds": args.seconds,
        "throughput_up_mib_s": up_mib_s,
        "throughput_echo_down_mib_s": down_mib_s,
        "any_client_lost": any_dead,
        "icmp_rtt_ms": icmp_rtts,
        "dns_via_vpn": dns_result,
        "per_client": per_client,
        "reconnect_test": reconnect,
        "capture": { "pcap": args.pcap, "tsv": args.tsv },
    });
    std::fs::write(&args.report, serde_json::to_string_pretty(&report)?)?;
    println!(
        "report: {}  pcap: {}  tsv: {}",
        args.report, args.pcap, args.tsv
    );
    Ok(())
}

fn write_tsv(path: &str, cap: &Capture) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    for conn in cap.conns.lock().unwrap().iter() {
        for c in &conn.c2s {
            writeln!(f, "{}\tc2s\t{}\t{}", c.ts_us, conn.client_port, c.full_len)?;
        }
        for c in &conn.s2c {
            writeln!(f, "{}\ts2c\t{}\t{}", c.ts_us, conn.client_port, c.full_len)?;
        }
    }
    Ok(())
}

fn tcp_checksum(ip: &[u8; 20], tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&ip[12..16]);
    pseudo.extend_from_slice(&ip[16..20]);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    ip_checksum(&pseudo)
}

fn write_pcap(path: &str, listen_port: u16, cap: &Capture) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    // pcap global header, LINKTYPE_RAW (101): the DPI's view of the TCP stream.
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    f.write_all(&2u16.to_le_bytes())?;
    f.write_all(&4u16.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?; // thiszone
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&101u32.to_le_bytes())?; // LINKTYPE_RAW
    for conn in cap.conns.lock().unwrap().iter() {
        // merge both directions in ts order with per-direction seq tracking
        let mut c2s_iter = conn.c2s.iter().peekable();
        let mut s2c_iter = conn.s2c.iter().peekable();
        let mut c_seq: u32 = 1000;
        let mut s_seq: u32 = 2000;
        let mut ip_id: u16 = 1;
        while c2s_iter.peek().is_some() || s2c_iter.peek().is_some() {
            let take_c2s = match (c2s_iter.peek(), s2c_iter.peek()) {
                (Some(c), Some(s)) => c.ts_us <= s.ts_us,
                (Some(_), None) => true,
                _ => false,
            };
            let chunk = if take_c2s {
                c2s_iter.next().unwrap()
            } else {
                s2c_iter.next().unwrap()
            };
            let (sport, dport, seq, ack) = if take_c2s {
                let s = c_seq;
                c_seq = c_seq.wrapping_add(chunk.full_len as u32);
                (conn.client_port, listen_port, s, s_seq)
            } else {
                let s = s_seq;
                s_seq = s_seq.wrapping_add(chunk.full_len as u32);
                (listen_port, conn.client_port, s, c_seq)
            };
            let payload = &chunk.bytes[..];
            let tcp_len = 20 + payload.len();
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&sport.to_be_bytes());
            tcp[2..4].copy_from_slice(&dport.to_be_bytes());
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp[8..12].copy_from_slice(&ack.to_be_bytes());
            tcp[12] = 5 << 4;
            tcp[13] = 0x18; // PSH|ACK
            tcp[14..16].copy_from_slice(&0x2000u16.to_be_bytes());
            tcp.extend_from_slice(payload);
            let ip_hdr: [u8; 20] = {
                let mut h = [0u8; 20];
                h[0] = 0x45;
                h[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
                h[4..6].copy_from_slice(&ip_id.to_be_bytes());
                h[8] = 64;
                h[9] = 6;
                h[12..16].copy_from_slice(&[127, 0, 0, 1]);
                h[16..20].copy_from_slice(&[127, 0, 0, 1]);
                h
            };
            let c = tcp_checksum(&ip_hdr, &tcp);
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            let mut ip = ip_hdr.to_vec();
            ip[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
            ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
            let c = ip_checksum(&ip);
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&tcp);
            ip_id = ip_id.wrapping_add(1);
            let ts = chunk.ts_us / 1_000_000;
            let us = (chunk.ts_us % 1_000_000) as u32;
            f.write_all(&(ts as u32).to_le_bytes())?;
            f.write_all(&us.to_le_bytes())?;
            f.write_all(&((ip.len()) as u32).to_le_bytes())?;
            f.write_all(&(ip.len() as u32).to_le_bytes())?;
            f.write_all(&ip)?;
        }
    }
    Ok(())
}
