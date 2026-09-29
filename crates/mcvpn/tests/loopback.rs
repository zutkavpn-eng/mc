//! End-to-end loopback: a real server on 127.0.0.1 (mock device pair as the
//! "internet" side) and a real client, exercising the full Minecraft 1.8.9
//! flow over TCP: handshake, login encryption (RSA + AES/CFB8), set
//! compression, play state, plugin channel REGISTER, MW|Tunnel auth, and
//! bidirectional sealed IP packet transfer.

use mc_protocol::frame::encode_frame;
use mc_protocol::packets::{Handshake, Ping, StatusRequest};
use mcvpn::client;
use mcvpn::config::{ClientConfig, ServerConfig};
use mcvpn::device::mock::mock_pair;
use mcvpn::device::DeviceHandle;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

fn test_server_cfg(port: u16) -> ServerConfig {
    ServerConfig {
        bind: "127.0.0.1".into(),
        port,
        token: "test-token-123".into(),
        motd: "A Minecraft Server".into(),
        max_players: 20,
        fake_online: 0,
        compression_threshold: 256,
        keepalive_secs: 15,
        rsa_bits: 1024,
        tunnel_cidr: "100.64.0.0/10".into(),
        mtu: 1400,
        dns: vec!["1.1.1.1".into()],
        max_clients: 16,
        max_pending: 64,
        per_ip_min_interval_ms: 0,
        setup_nat: false,
        auth_timeout_secs: 10,
        mock_device: true,
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn spawn_server(cfg: ServerConfig) -> DeviceHandle {
    let (server_dev, internet_dev) = mock_pair();
    let (_tx, rx) = watch::channel(false);
    std::mem::forget(_tx); // keep the server alive for the whole test
    tokio::spawn(async move {
        if let Err(e) = mcvpn::server::run(cfg, server_dev, rx).await {
            panic!("server error: {e}");
        }
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;
    internet_dev
}

fn client_cfg(port: u16, token: &str) -> ClientConfig {
    ClientConfig {
        server: "127.0.0.1".into(),
        port,
        token: token.into(),
        stealth_tick: true,
        ping_interval_secs: 5,
        auto_reconnect: false,
    }
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("mcvpn=debug"))
        .try_init();
}

/// Minimal fake IPv4 packet; the tunnel only inspects src/dst.
fn fake_ip(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 0x11]);
    p.extend_from_slice(&[0x00, 0x00]); // checksum
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

#[tokio::test]
async fn full_loopback_bidirectional_transfer() {
    init_test_tracing();
    let port = free_port().await;
    let mut internet = spawn_server(test_server_cfg(port)).await;

    // Client #1: full login + tunnel session.
    let sess = match tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(&client_cfg(port, "test-token-123")),
    )
    .await
    {
        Ok(r) => r.expect("connect ok"),
        Err(_) => panic!("connect timed out"),
    };
    let info = sess.info().clone();
    assert_eq!(info.ip, [100, 64, 0, 2]);
    assert_eq!(info.gateway, [100, 64, 0, 1]);
    assert_eq!(info.netmask, [255, 192, 0, 0]);
    assert_eq!(info.mtu, 1400);
    assert_eq!(info.dns, vec![[1, 1, 1, 1]]);

    let (client_dev, mut client_os_side) = mock_pair();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let stats = sess.stats();
    let session_task =
        tokio::spawn(async move { sess.attach_device(client_dev, shutdown_rx).await });

    // Client -> tunnel -> server TUN ("internet").
    let out = fake_ip(info.ip, [1, 2, 3, 4], b"hello from client");
    client_os_side.outbox.send(out.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), internet.inbox.recv())
        .await
        .expect("packet arrived at server TUN")
        .expect("device alive");
    assert_eq!(got, out);

    // Internet -> server TUN -> tunnel -> client device.
    let back = fake_ip([1, 2, 3, 4], info.ip, b"reply from internet");
    internet.outbox.send(back.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), client_os_side.inbox.recv())
        .await
        .expect("reply arrived at client device")
        .expect("device alive");
    assert_eq!(got, back);

    // Stats reflect both directions.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let snap = stats.snapshot();
    assert!(snap.up_bytes >= out.len() as u64);
    assert!(snap.down_bytes >= back.len() as u64);

    // Clean shutdown propagates.
    drop(_shutdown_tx);
    let _ = session_task.await;

    // Client #2: client #1 released its IP on shutdown, so the pool
    // hands the lowest free address out again.
    let sess2 = client::connect(&client_cfg(port, "test-token-123"))
        .await
        .expect("second client");
    assert_eq!(sess2.info().ip, [100, 64, 0, 2]);
}

#[tokio::test]
async fn slp_status_ping_golden() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let hs = Handshake {
        protocol_version: 47,
        host: "127.0.0.1".into(),
        port,
        next_state: 1,
    };
    s.write_all(&encode_frame(&hs.encode(), None))
        .await
        .unwrap();
    s.write_all(&encode_frame(&StatusRequest.encode(), None))
        .await
        .unwrap();

    let expected_json = mc_protocol::slp::status_json("A Minecraft Server", 0, 20, &[]);
    let expected = mc_protocol::packets::StatusResponse {
        json: expected_json,
    }
    .encode();
    let got = read_frame(&mut s).await;
    assert_eq!(
        got, expected,
        "status response must match a vanilla 1.8.9 server byte-for-byte"
    );

    // Ping -> pong echo (i64 timestamp).
    let ping_time = 0x0123_4567_89AB_CDEFi64;
    s.write_all(&encode_frame(&Ping { time: ping_time }.encode(), None))
        .await
        .unwrap();
    let expected_pong = mc_protocol::packets::Pong { time: ping_time }.encode();
    let got = read_frame(&mut s).await;
    assert_eq!(got, expected_pong);
}

#[tokio::test]
async fn legacy_ping_golden() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&[0xFE, 0x01]).await.unwrap();
    let expected = mc_protocol::legacy::ping_response_v15("A Minecraft Server", 0, 20);
    let mut got = vec![0u8; expected.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(
        got, expected,
        "legacy ping response must match vanilla 1.8.9"
    );
}

#[tokio::test]
async fn wrong_token_is_kicked_like_whitelist() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;
    let err = match client::connect(&client_cfg(port, "wrong-token")).await {
        Ok(_) => panic!("must fail"),
        Err(e) => e,
    };
    assert!(
        matches!(&err, mcvpn::VpnError::Kick(r) if r.contains("whitelisted")),
        "expected whitelist-style kick, got {err:?}"
    );
}

#[tokio::test]
async fn oversized_frame_is_rejected() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // 4-byte varint length prefix: wider than the 21-bit limit.
    s.write_all(&[0x80, 0x80, 0x80, 0x80, 0x01, 0xAA])
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
        .await
        .expect("read timeout")
        .unwrap();
    assert_eq!(
        n, 0,
        "server must close on a wider-than-21-bit length varint"
    );
}

#[tokio::test]
async fn unknown_host_state_closed() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // Valid handshake frame but garbage body: server must close, not hang.
    s.write_all(&encode_frame(&[0x00, 0xFF, 0xFF], None))
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
        .await
        .expect("read timeout")
        .unwrap();
    assert_eq!(n, 0);
}

/// Read one VarInt-framed packet from a raw stream (status-state helper).
async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut len = 0u32;
    let mut shift = 0;
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        len |= ((b[0] & 0x7F) as u32) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    let mut body = vec![0u8; len as usize];
    s.read_exact(&mut body).await.unwrap();
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // manual throughput smoke: cargo test --release -p mcvpn -- --ignored
async fn throughput_smoke() {
    let port = free_port().await;
    let mut internet = spawn_server(test_server_cfg(port)).await;
    let sess = client::connect(&client_cfg(port, "test-token-123"))
        .await
        .unwrap();
    let info = sess.info().clone();
    let (client_dev, client_os_side) = mock_pair();
    let (_tx, shutdown_rx) = watch::channel(false);
    let stats = sess.stats();
    tokio::spawn(async move { sess.attach_device(client_dev, shutdown_rx).await });

    // Drain the internet side in parallel.
    let drain = tokio::spawn(async move {
        let mut count = 0u64;
        while let Some(_pkt) = internet.inbox.recv().await {
            count += 1;
            if count >= 2000 {
                break;
            }
        }
    });

    let payload = vec![0x42u8; 1300];
    let t0 = std::time::Instant::now();
    let mut sent = 0;
    while sent < 2000 {
        // Fill the inbox like a TUN reader thread would (burst, not tickle).
        while sent < 2000
            && client_os_side
                .outbox
                .try_send(fake_ip(info.ip, [8, 8, 8, 8], &payload))
                .is_ok()
        {
            sent += 1;
        }
        tokio::task::yield_now().await;
    }
    drain.await.unwrap();
    let dt = t0.elapsed();
    let mb = 2000.0 * 1320.0 / 1024.0 / 1024.0;
    println!(
        "throughput: {mb:.1} MiB in {dt:.2?} = {:.1} MiB/s (stats up {})",
        mb / dt.as_secs_f32(),
        stats.snapshot().up_bytes
    );
}

/// The GUI's "traffic is really routed into the tunnel" check: a packet the OS
/// hands to the tunnel device with the probe destination must flip
/// `probe_seen`; ordinary traffic must not.
#[tokio::test]
async fn route_probe_is_detected_at_the_tunnel_device() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;
    let stats: mcvpn::stats::SharedStats = std::sync::Arc::new(mcvpn::stats::Stats::default());
    let sess = client::connect_with_stats(&client_cfg(port, "test-token-123"), stats.clone())
        .await
        .expect("connect");
    let info = sess.info().clone();
    let (client_dev, client_os_side) = mock_pair();
    let (tx, rx) = watch::channel(false);
    std::mem::forget(tx);
    tokio::spawn(async move { sess.attach_device(client_dev, rx).await });

    client_os_side
        .outbox
        .send(fake_ip(info.ip, [8, 8, 8, 8], b"ordinary traffic"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !stats.snapshot().probe_seen,
        "ordinary traffic is not the probe"
    );

    client_os_side
        .outbox
        .send(fake_ip(info.ip, client::PROBE_ADDR, b"mcvpn-route-probe"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        stats.snapshot().probe_seen,
        "probe must be seen at the device"
    );
}

/// Users paste sloppy input; the client must still connect: trailing
/// whitespace/zero-width chars in the token, "ip:port" in the server field,
/// and a full mcvpn:// share link with no separate token.
#[tokio::test]
async fn sloppy_user_input_still_connects() {
    let port = free_port().await;
    let _internet = spawn_server(test_server_cfg(port)).await;

    let mut c = client_cfg(port, " test-token-123\u{200B}\n");
    c.server = format!(" 127.0.0.1:{port} ");
    assert!(
        client::connect(&c).await.is_ok(),
        "token/host junk must be tolerated"
    );

    let mut link = client_cfg(1, "");
    link.server = format!("mcvpn://test-token-123@127.0.0.1:{port}");
    assert!(
        client::connect(&link).await.is_ok(),
        "share link must connect"
    );

    let empty = client_cfg(port, "  ");
    match client::connect(&empty).await {
        Err(mcvpn::VpnError::Kick(m)) => assert!(m.contains("token"), "{m}"),
        Err(e) => panic!("empty token must give a clear error, got {e:?}"),
        Ok(_) => panic!("empty token must not connect"),
    }
}
