//! Windows device via WinTun (the same driver WireGuard-for-Windows uses).
//! Requires wintun.dll next to the exe and Administrator rights (the
//! embedded manifest auto-elevates; see mcvpn-gui/build.rs).
//!
//! Everything the OS needs is configured with hidden (CREATE_NO_WINDOW) and
//! CHECKED netsh/route calls, logged with their full output, so a failure is
//! visible in the app instead of silently leaving the user "connected"
//! without a working tunnel.
//!
//! ROUTING-LOOP PROTECTION (the reason for `protect_ip`): with the split
//! default routes 0.0.0.0/1 + 128.0.0.0/1 pointing into the tunnel, the
//! client's OWN TCP connection to the VPN server would be routed into the
//! tunnel it carries — the session dies within seconds. A host route for the
//! server via the original physical gateway is installed first (same as the
//! Linux client), and removed on disconnect.

use super::winroute::{choose_default_route, parse_default_routes, DefaultRoute};
use super::DeviceHandle;
use crate::error::{VpnError, VpnResult};
use crate::tunnel::TunnelInfo;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub const ADAPTER_NAME: &str = "mcvpn";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn dll_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"))
}

/// Run a command hidden; returns combined output on success, or an error
/// string containing the command line and its full output.
fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    #[cfg(target_os = "windows")]
    c.creation_flags(CREATE_NO_WINDOW);
    let out = c.output().map_err(|e| format!("{cmd}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let text = text.trim().to_string();
    if out.status.success() {
        tracing::info!(cmd = %format!("{cmd} {}", args.join(" ")), output = %text, "ok");
        Ok(text)
    } else {
        tracing::warn!(cmd = %format!("{cmd} {}", args.join(" ")), output = %text, "FAILED");
        Err(format!("`{cmd} {}` failed: {text}", args.join(" ")))
    }
}

fn run_quiet(cmd: &str, args: &[&str]) {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    #[cfg(target_os = "windows")]
    c.creation_flags(CREATE_NO_WINDOW);
    let _ = c.output();
}

/// Retry: right after the adapter is created the network stack may not know
/// it yet, and netsh answers "element not found" for a few hundred ms.
fn run_retry(cmd: &str, args: &[&str], attempts: u32) -> Result<String, String> {
    let mut last = String::new();
    for i in 0..attempts {
        match run(cmd, args) {
            Ok(o) => return Ok(o),
            Err(e) => {
                last = e;
                if i + 1 < attempts {
                    std::thread::sleep(Duration::from_millis(400));
                }
            }
        }
    }
    Err(last)
}

/// The local address the OS would use to reach `server` (before any VPN route).
fn local_ip_towards(server: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect((server, 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

struct Installed {
    tunnel_routes: bool,
    host_route: Option<Ipv4Addr>,
}

fn remove_routes(state: &Installed, tunnel_gw: &Ipv4Addr, own_ip: &Ipv4Addr) {
    if state.tunnel_routes {
        for net in ["0.0.0.0", "128.0.0.0"] {
            // Any of the three install paths may have won: delete the
            // gateway and own-address flavours, plus the bare on-link form
            // (netsh nexthop=0.0.0.0) that has no gateway at all. Deleting a
            // route that is not there is a no-op, so this is safe for all.
            run_quiet("route", &["delete", net, "mask", "128.0.0.0"]);
            run_quiet(
                "route",
                &["delete", net, "mask", "128.0.0.0", &tunnel_gw.to_string()],
            );
            run_quiet(
                "route",
                &["delete", net, "mask", "128.0.0.0", &own_ip.to_string()],
            );
        }
    }
    if let Some(server) = state.host_route {
        run_quiet(
            "route",
            &["delete", &server.to_string(), "mask", "255.255.255.255"],
        );
    }
}

/// Install the split default routes through the adapter. Tries, in order:
///   1. `route add ... <tunnel gateway> if <idx>` (canonical for L3 wintun)
///   2. `netsh interface ipv4 add route <prefix> <name>` (on-link)
///   3. `route add ... <own address>` (route.exe reads a local address as on-link)
/// Any success counts; all three failing is a hard error carrying every reason.
fn add_tunnel_routes(
    adapter_name: &str,
    if_index: Option<u32>,
    own_ip: &Ipv4Addr,
    tunnel_gw: &Ipv4Addr,
) -> Result<(), String> {
    let mut reasons: Vec<String> = Vec::new();
    for (net, prefix) in [("0.0.0.0", "0.0.0.0/1"), ("128.0.0.0", "128.0.0.0/1")] {
        // Stale routes from a crashed previous run would make `add` fail.
        run_quiet("route", &["delete", net, "mask", "128.0.0.0"]);
        let gw = tunnel_gw.to_string();
        let idx = if_index.map(|i| i.to_string());
        let mut s1: Vec<&str> = vec!["add", net, "mask", "128.0.0.0", &gw, "metric", "3"];
        if let Some(i) = idx.as_deref() {
            s1.push("if");
            s1.push(i);
        }
        let ok = match run("route", &s1) {
            Ok(_) => true,
            Err(e1) => {
                reasons.push(e1);
                let name_arg = format!("interface={adapter_name}");
                let prefix_arg = format!("prefix={prefix}");
                match run(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        &prefix_arg,
                        &name_arg,
                        "nexthop=0.0.0.0",
                        "metric=3",
                        "store=active",
                    ],
                ) {
                    Ok(_) => true,
                    Err(e2) => {
                        reasons.push(e2);
                        let own = own_ip.to_string();
                        match run(
                            "route",
                            &["add", net, "mask", "128.0.0.0", &own, "metric", "3"],
                        ) {
                            Ok(_) => true,
                            Err(e3) => {
                                reasons.push(e3);
                                false
                            }
                        }
                    }
                }
            }
        };
        if !ok {
            return Err(reasons.join(" | "));
        }
    }
    Ok(())
}

pub fn open(info: &TunnelInfo, protect_ip: Option<Ipv4Addr>) -> VpnResult<DeviceHandle> {
    let dev = |m: String| VpnError::Device(m);

    tracing::info!("wintun: loading driver library");
    let wintun = unsafe { wintun::load_from_path(dll_path()) }
        .or_else(|_| unsafe { wintun::load() })
        .map_err(|e| {
            dev(format!(
                "failed to load wintun.dll ({e}). Keep wintun.dll in the SAME folder as \
                 mcvpn.exe — extract the whole zip, do not run the exe from inside it"
            ))
        })?;
    let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => {
            tracing::info!("wintun: reusing existing adapter");
            a
        }
        Err(_) => {
            tracing::info!("wintun: creating adapter");
            wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None).map_err(|e| {
                dev(format!(
                    "wintun adapter create failed ({e}). Run mcvpn as Administrator"
                ))
            })?
        }
    };
    let adapter_name = adapter
        .get_name()
        .map_err(|e| dev(format!("wintun adapter name: {e}")))?;
    let if_index = adapter.get_adapter_index().ok();
    tracing::info!(name = %adapter_name, if_index = ?if_index, "wintun: adapter ready");

    let ip = Ipv4Addr::from(info.ip);
    let mask = Ipv4Addr::from(info.netmask);
    let tunnel_gw = Ipv4Addr::from(info.gateway);

    // 1. Address (required).
    run_retry(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={adapter_name}"),
            "source=static",
            &format!("address={ip}"),
            &format!("mask={mask}"),
        ],
        8,
    )
    .map_err(|e| dev(format!("cannot assign the tunnel address: {e}")))?;

    // 2. DNS through the tunnel (best effort; logged if it fails).
    let dns: Vec<IpAddr> = info
        .dns
        .iter()
        .map(|d| IpAddr::V4(Ipv4Addr::from(*d)))
        .collect();
    if !dns.is_empty() {
        if let Err(e) = adapter.set_dns_servers(&dns) {
            tracing::warn!(error = %e, "wintun: could not set DNS on the adapter (DNS may leak)");
        }
    }
    if let Err(e) = adapter.set_mtu(info.mtu as usize) {
        tracing::warn!(error = %e, "wintun: could not set MTU (default is used)");
    }
    // Prefer the tunnel for DNS/name resolution ordering (best effort).
    let _ = run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "interface",
            &format!("name={adapter_name}"),
            "metric=1",
        ],
    );

    // 3. Protect the VPN server itself from the tunnel routes (required
    //    whenever the server IP is known and not loopback).
    let mut state = Installed {
        tunnel_routes: false,
        host_route: None,
    };
    if let Some(server) = protect_ip.filter(|s| !s.is_loopback()) {
        let route_print = run("route", &["print", "-4", "0.0.0.0"]).unwrap_or_default();
        let routes = parse_default_routes(&route_print);
        let phys = local_ip_towards(server);
        // Never pick our own tunnel address as the "physical" route.
        let routes: Vec<DefaultRoute> = routes.into_iter().filter(|r| r.interface != ip).collect();
        let chosen = choose_default_route(&routes, phys);
        tracing::info!(server = %server, phys_ip = ?phys, chosen = ?chosen, "protecting the server route");
        let via: Option<String> = match &chosen {
            Some(r) => Some(
                r.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| r.interface.to_string()),
            ),
            None => phys.map(|p| p.to_string()),
        };
        let Some(via) = via else {
            return Err(dev(
                "cannot determine your normal (non-VPN) gateway to protect the VPN \
                 connection from a routing loop; check that this PC has internet access"
                    .into(),
            ));
        };
        run_quiet(
            "route",
            &["delete", &server.to_string(), "mask", "255.255.255.255"],
        );
        run(
            "route",
            &[
                "add",
                &server.to_string(),
                "mask",
                "255.255.255.255",
                &via,
                "metric",
                "1",
            ],
        )
        .map_err(|e| dev(format!("cannot protect the VPN server route: {e}")))?;
        state.host_route = Some(server);
    }

    // 4. Tunnel routes (required).
    if let Err(e) = add_tunnel_routes(&adapter_name, if_index, &ip, &tunnel_gw) {
        remove_routes(&state, &tunnel_gw, &ip);
        return Err(dev(format!(
            "routing failed — traffic would bypass the VPN: {e}"
        )));
    }
    state.tunnel_routes = true;

    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| {
                remove_routes(&state, &tunnel_gw, &ip);
                dev(format!("wintun session failed: {e}"))
            })?,
    );

    let (inbox_tx, inbox_rx) = mpsc::channel::<Vec<u8>>(512);
    let (outbox_tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(512);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stop);
    let stop_writer = Arc::clone(&stop);
    let reader_session = Arc::clone(&session);

    std::thread::Builder::new()
        .name("wintun-rd".into())
        .spawn(move || loop {
            if stop_reader.load(Ordering::Relaxed) {
                break;
            }
            match reader_session.receive_blocking() {
                Ok(pkt) => {
                    if inbox_tx.blocking_send(pkt.bytes().to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break, // session shut down
            }
        })
        .map_err(|e| dev(format!("thread spawn: {e}")))?;

    let writer_session = Arc::clone(&session);
    std::thread::Builder::new()
        .name("wintun-wr".into())
        .spawn(move || {
            while let Some(pkt) = outbox_rx.blocking_recv() {
                if stop_writer.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(size) = u16::try_from(pkt.len()) {
                    if let Ok(mut p) = writer_session.allocate_send_packet(size) {
                        p.bytes_mut().copy_from_slice(&pkt);
                        writer_session.send_packet(p);
                    }
                }
            }
        })
        .map_err(|e| dev(format!("thread spawn: {e}")))?;

    let cleanup_session = Arc::clone(&session);
    Ok(DeviceHandle {
        inbox: inbox_rx,
        outbox: outbox_tx,
        name: ADAPTER_NAME.to_string(),
        stop: Some(stop),
        cleanup: Some(Box::new(move || {
            let _ = cleanup_session.shutdown();
            remove_routes(&state, &tunnel_gw, &ip);
            // Leave the host as we found it: a dead adapter must not stay the
            // preferred resolver (resolution would stall after a disconnect)
            // nor keep the lowest interface metric.
            run_quiet(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    ADAPTER_NAME,
                    "source=dhcp",
                ],
            );
            run_quiet(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "interface",
                    &format!("name={ADAPTER_NAME}"),
                    "metric=automatic",
                ],
            );
        })),
    })
}
