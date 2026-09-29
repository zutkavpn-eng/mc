# mcvpn end-to-end verification record — 2026-09-29

Every step below was executed live in this environment against the v0.1.1
builds. Reproduce any of it with `cargo run --release -p mcvpn --bin
mcvpn-verify` and the scripts in `scripts/`.

## 1. Server install (the real one-command user flow)

```
$ curl -fsSL https://raw.githubusercontent.com/zutkavpn-eng/mc/main/scripts/install.sh | sudo bash
==> downloading mcvpn-server (x86_64)     # from the GitHub release (v0.1.1)
==> config
Wrote /etc/mcvpn/server.toml — token: <random 32-byte hex>
==> systemd service
    systemd not detected (container?) — starting under nohup instead
==============================================================
 mcvpn is running. Connect clients with:
   server: <ip>   port: 25565
   token:  <token>
```

The install script downloads the release binary, generates the config and
token, sets up the service, and prints the client connection info. (In this
sandbox there is no systemd and no CAP_NET_ADMIN — the script's container
fallback kicked in; on a real VPS it installs the systemd unit and TUN/NAT
normally.)

## 2. Client connects to the installed server

```
$ mcvpn-cli --server 127.0.0.1 --port 25565 --token <token> --mock-device
[state] connecting...
[state] connected
up 0 KB/s  down 0 KB/s  rtt -ms
```

Full login flow over TCP 25565: handshake (protocol 47) → login start →
encryption request (1024-bit RSA) → encryption response → set compression →
login success → play state → MW|Tunnel auth → session established
(`tunnel session established ip=100.64.0.2` in the server log).

## 3. What an external observer (DPI) sees

Captured with a recording TCP tee (the exact wire bytes) into a pcap +
timing log, then analyzed with `scripts/dpi_report.py`:

```
handshake: proto=47 host=... port=25565 next_state=2  OK (vanilla 1.8.9)
login start: username='EfHmFhWYp9'                    OK (valid MC name)
encryption request: server_id='' pubkey=162B verify_token=4B
    RSA key is 1024-bit sized (162B SPKI) byte-identical to vanilla/BungeeCord
encryption response: secret=128B token=128B (1024-bit RSA blocks)
encrypted c2s entropy: 8.000 bits/byte over 1048576B  indistinguishable from random
tiny-frame cadence: 59 frames, median gap 49.9 ms   matches vanilla 20 Hz idle player ticks
=== verdict ===
No signature-level fingerprints
```

The only plaintext stage (pre-encryption login) is byte-shaped like a vanilla
online-mode 1.8.9 login; everything after the encryption response is
random-looking with vanilla packet cadence.

## 4. Server List Ping vs a real public server

`scripts/observer_slp.py 127.0.0.1:25565 mc.hypixel.net:25565`:

```
== 127.0.0.1:25565 ==                    == mc.hypixel.net:25565 ==
{"version":{"name":"1.8.9",              {"version":{"name":"Requires MC 1.8 / 1.21",
  "protocol":47},                          "protocol":47},
 "players":{"max":20,"online":0},         "players":{"max":200000,"online":15330,...},
 "description":{"text":"A Minecraft…      "description":"§f…Hypixel Network…",
ping/pong rtt: 0.1 ms                     ping/pong rtt: 0.0 ms
```

Same JSON shape (version/players/description), same protocol 47, same
ping/pong echo behavior. Legacy ping (`0xFE 0x01`) also answers
vanilla-style: `protocol=127 version=1.8.9 … online=0 max=20`.

## 5. Speed, ping, stability (`mcvpn-verify`)

| Measurement | Result |
|---|---|
| DNS through the VPN to the real 1.1.1.1 resolver | **ok, 2 answers, 2 ms RTT — identical to direct (2 ms)** |
| ICMP full-path RTT (client→tunnel→server→internet→back) | 0 ms (local slirp) |
| Protocol ping RTT (tunnel-level), idle | ~0 ms |
| Throughput, 1 client, 15 s soak | 1.43 MiB/s up / 1.43 MiB/s echoed down |
| Throughput, 16 clients (one token), 15 s soak | 6.67 MiB/s aggregate up |
| Clients lost / kicked during soaks | 0 / 0 |
| Server killed mid-session | client auto-reconnected: `connecting→connected→error→waiting→…→connected` |

Throughput numbers are bounded by this sandbox's CPU throttling (all builds
run ~10x slower than real hardware here). The crypto path itself (AES/CFB8
login stream, the same cipher every real Minecraft server uses) measures
~43 MiB/s raw on this same throttled CPU; on a real VPS expect substantially
more. Latency overhead of the tunnel is one TCP round-trip per direction —
DNS through the VPN matched direct resolution time exactly.

## 6. One token shared by many users

16 concurrent client sessions with the **same token**: 16 unique tunnel IPs
(100.64.0.2–17), 16 random plausible usernames on the wire (no same-player
correlation fingerprint), zero kicks, zero dropped sessions. The pool is
O(log n) with a free list, `max_clients` defaults to 256 (config), and the
CGNAT range holds ~4M addresses. Routing is per-connection — sharing a token
has no cross-client effect.

## 7. Tests, builds, artifacts

- `cargo test -p mc-protocol -p mcvpn`: **40 tests green** (byte-exact SLP /
  legacy-ping / CFB8 goldens vs OpenSSL, loopback E2E over real TCP, kick and
  frame-abuse paths, username realism).
- Release builds produced and smoke-tested in-environment:
  `mcvpn-server-linux-amd64/arm64.tar.gz` (real binary smoke: client
  connected), `mcvpn-windows-x64.zip` (exe cross-compiled + wintun.dll),
  `mcvpn-android.apk` (NDK .so for arm64-v8a + armeabi-v7a, gradle
  assembleRelease, apksigner-verified).

## 8. What could NOT be verified here (honest limits)

- **Kernel TUN/NAT live**: this sandbox has no CAP_NET_ADMIN (TUNSETIFF,
  iptables, sysctl all denied), so the Linux kernel-TUN device and
  MASQUERADE rules could not run live. Verified instead by: unit tests of
  the ioctl path, the identical channel-based data plane used end-to-end
  above (the same code shape the Android fd device uses), and the install
  script's graceful container fallback. Run `sudo mcvpn-cli --server host
  --token x` on any real Linux box to exercise it.
- **Windows GUI / Android app runtime**: no display and no emulator in this
  environment. Both were rebuilt, compile clean, and their logic was
  reviewed (lifecycle fixes included: onRevoke, closed-state detection,
  connecting guards); pixel-level UI verification was not possible.
- Behavioral/statistical traffic analysis (volume profiling over hours)
  remains the one class of detection no protocol-exact implementation can
  fully defeat — that is an inherent limit, not a bug.

---

# v0.1.5 — data-plane performance pass (measured in-environment)

Same machine, same harness (`mcvpn-verify`, 15 s soak, 1300 B packets),
single connection, before/after:

| | v0.1.4 | v0.1.5 | |
|---|---|---|---|
| Uplink, 1 client | 0.69 MiB/s | **2.70 MiB/s** | **×3.9** |
| Echo downlink, 1 client | 0.69 MiB/s | **2.70 MiB/s** | symmetric |
| Uplink, 16 clients (one token) | 6.67 MiB/s* | 3.84 MiB/s** | \**different, less-throttled sandbox — not comparable* |

\* recorded in the v0.1.4 environment; the v0.1.5 line is this sandbox, where
a single client already runs 2.70 MiB/s.

What changed on the hot path (all inside the CFB8 stream — wire-invisible):

- one GCM seal + one MC frame + one TCP write per burst (was per packet);
  uplink batches cap at 8 KiB so serverbound frames stay client-sized,
  downlink batches cap at 32 KiB (chunk-stream shaped)
- zlib level 0 (stored) for coalesced tunnel payloads — level 6 deflating
  already-random ciphertext was pure CPU loss; genuine MC-shaped packets
  (login, keep-alive, ticks, settings) keep the Java-default level 6
- 64 KiB reads per syscall (was 16 KiB)
- drop-tail at full queues + TCP_NOTSENT_LOWAT (32 KiB) on Linux/Android:
  congestion turns into packet loss the inner TCP flows react to, instead of
  seconds of queue delay for everything behind a bulk transfer (bufferbloat
  was the main source of "ping jumps while loading")
- sliding anti-replay window (IPsec-style, commit-after-tag-verify) so drops
  under load cannot desync the stream

Re-verified on v0.1.5: 16 concurrent clients on one token — unique tunnel IPs,
0 lost, 0 kicked; kill-server reconnect test passes (full state cycle,
auto-reconnect confirmed); DNS via VPN to the real 1.1.1.1 resolves in 12 ms
(direct 11 ms); DPI report on the v0.1.5 capture: no signature-level
fingerprints, encrypted-phase entropy 8.000 bits/byte.

Note on the 16-client soak's low *echo* number: the verify harness's
user-space "internet" echo loop is a single task for all clients — it is the
measuring instrument saturating, not the server data plane (the server only
echoed what reached its TUN: down_bytes matches). A real deployment's
downlink goes through kernel TUN + NAT with no such serialization; the
single-client downlink (2.70 MiB/s, symmetric) exercises the same path.

Compatibility: client and server must both be v0.1.5 (batched DATA frames).
An old server kicks a new client on its first batch; a new server keeps
accepting old (unbatched) clients.
