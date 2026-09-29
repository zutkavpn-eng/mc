# mcvpn — a VPN disguised as a Minecraft server

mcvpn is a personal VPN whose **entire transport is a byte-exact Minecraft Java
Edition 1.8.9 (protocol 47) connection on port 25565** — not raw VPN bytes on a
Minecraft port. To anyone watching the wire it is a normal vanilla-style
Minecraft client/server conversation: handshake, server list ping, online-mode
login with RSA/AES-CFB8 encryption, Set Compression, plugin-channel traffic,
20 Hz idle player updates and keep-alives, exactly like real BungeeCord/vanilla
traffic. Your IP packets ride inside that encrypted stream on a registered
plugin channel (`MW|Tunnel`), the way real modded clients (Forge) carry data.

> [!WARNING]
> This is a personal-use tool, not a censorship-resistance guarantee. Traffic
> analysis (packet sizes/timing) can still distinguish it from an actual player.
> It is *protocol-compatible* camouflage, not magic. Use legally and responsibly.

## How it looks on the wire

| Stage | What an observer sees |
|---|---|
| Handshake | protocol 47, your hostname, port 25565, next state |
| Status (optional) | a normal 1.8.9 server list ping response (MOTD, players) |
| Legacy ping (0xFE) | vanilla-style legacy SLP answer |
| Login | login start with a valid player-name-shaped username → **Encryption Request** (RSA pubkey) → Encryption Response → **Set Compression → Login Success** |
| After that | AES/CFB8-encrypted stream, structurally identical to real online-mode Minecraft |
| Play state | Join Game, brand/REGISTER plugin messages, keep-alives every 15 s, 20 Hz idle player packets, custom-payload "chunky" bursts — like a modded client |

Crypto is **the same stack real BungeeCord/vanilla servers use**:
RSA PKCS#1 v1.5 over the X.509 SPKI public key (login encryption), then
AES-128/CFB8 with the shared secret (IV = key, the classic Minecraft quirk),
zlib packet compression with threshold 256. On top of that every tunneled IP
packet is sealed with **AES-256-GCM** using per-session keys derived via
HKDF-SHA256 and strict anti-replay counters (CFB8 alone is malleable; this
restores integrity).

## Quick start

### Server (any Linux VPS, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/zutkavpn-eng/mc/main/scripts/install.sh | sudo bash
```

Installs the binary, generates `/etc/mcvpn/server.toml` with a random token,
sets up NAT (idempotent, tagged iptables rules + ip_forward), installs and
starts a systemd service, and prints the token for clients.

<details><summary>Manual server run</summary>

```bash
sudo mcvpn-server --init --config ./server.toml   # writes config + token
sudo mcvpn-server --config ./server.toml           # needs root for TUN/NAT
```

</details>

### Windows client

1. Download `mcvpn-windows-x64.zip` from [releases](../../releases) and extract.
2. Run **as Administrator** (WinTun adapter + routes need it).
3. Fill in server / token → **CONNECT**.

The same `mcvpn.exe --cli --server host --token x` works headless.

### Android client

1. Download `mcvpn-android.apk` from [releases](../../releases) and install it.
2. Fill in server / token → **CONNECT** → approve the VPN permission.

### Linux client

```bash
sudo mcvpn-cli --server vpn.example.com --token <token>
```

(Root for the TUN device; routes all traffic through the tunnel.)

## What it does well

**v0.1.5 performance pass**: one encrypt/frame/write per burst of packets
(not per packet), drop-tail queues and TCP_NOTSENT_LOWAT against bufferbloat
("ping jumps while something loads"), zlib level 0 on tunnel payloads —
measured **×3.9 throughput** over v0.1.4 in the same environment, symmetric
up/down, 0 lost clients over a 16-client one-token soak.

Compatibility: update the server and clients together (both v0.1.5) —
batched tunnel frames are new.

- **Byte-exact protocol**: handshake/SLP/legacy ping/login/encryption bytes are
  pinned by golden tests, including an OpenSSL-verified AES/CFB8 stream and
  Java-compatible offline UUIDs.
- **No signature fingerprints** (verified with a live DPI capture, see
  `docs/VERIFICATION.md`): 1024-bit RSA login key like every real 1.8.9
  server, SLP serialized exactly like vanilla (chat-object description,
  sample omitted when empty), per-connection random plausible usernames,
  encrypted phase measures 8.000 bits/byte entropy, idle cadence is the
  vanilla 20 Hz player tick.
- **Throughput & latency**: TCP_NODELAY, OS-level keep-alive, batched
  coalesced writes (up to 128 packets per syscall), lossless backpressure —
  the ceiling is AES/CFB8 itself, the same cipher every real Minecraft server
  runs (byte-serial by design; expect WireGuard-unreachable speed, BungeeCord-class).
- **DNS**: clients route 1.1.1.1/8.8.8.8 (configurable) through the tunnel.
- **Reconnect**: desktop clients auto-reconnect with exponential backoff and
  jitter; Android reconnects via the app button (VpnService-safe).
- **Hardening**: 21-bit VarInt frame cap (BungeeCord/Velocity limits), strict
  field parsers, unknown-packet kicks with vanilla-style reasons, per-IP
  connect throttling, pending-login caps, strict AEAD counters, constant-time
  token comparison.
- **Multi-client**: CGNAT pool (100.64.0.0/10), per-client IP, MASQUERADE NAT.
- **Share one token with everyone**: sessions are per-connection with unique
  tunnel IPs and random usernames — 16 concurrent same-token clients verified
  with zero kicks; `max_clients` defaults to 256, the pool holds ~4M
  addresses, allocation is O(log n).

## Architecture

```
┌────────────┐  IP packets  ┌─────────────┐ GCM-sealed MW|Tunnel plugin msgs
│ TUN/wintun │◄────────────►│ tunnel pumps │◄──────────────► MC 1.8.9 stream
└────────────┘              └─────────────┘  (RSA login, AES/CFB8, zlib)

server: crates/mcvpn — mcvpn-server (TUN "mcvpn0" + NAT + SLP decoy)
client: mcvpn-gui (WinTun/.exe) · mcvpn-cli (Linux) · mcvpn-android (JNI + Kotlin VpnService)
```

Why a plugin channel instead of chunk packets (minewire-style)? Because
1.8.9 chunk packets don't contain heightmaps (1.14+), and fake NBT inside them
is a protocol fingerprint. A `REGISTER`ed plugin channel with custom-payload
bursts is exactly what every Forge/modded 1.8.9 client does — native to the
protocol, no fake structures.

## Repository

| Path | What |
|---|---|
| `crates/mc-protocol` | Minecraft 1.8.9 wire protocol (framing, crypto, packets, legacy ping) |
| `crates/mcvpn` | server + client core, devices, tunnel, NAT (bins: `mcvpn-server`, `mcvpn-cli`) |
| `crates/mcvpn-gui` | desktop client (dark UI; also `--cli`) |
| `crates/mcvpn-android` | JNI bridge for the Android app |
| `android/` | Kotlin app (VpnService, dark UI, gradle) |
| `scripts/` | install/uninstall/systemd |

References studied for byte-exactness: SpigotMC/BungeeCord (cipher/framing/SLP),
PaperMC/Velocity (limits/compression semantics), ViaVersion, the Minecraft
protocol documentation, and dmitrymodder/minewire (a useful Go predecessor
whose mixed-version packets and AES-GCM/yamux design this project deliberately
diverges from).

## Build from source

```bash
cargo test -p mc-protocol -p mcvpn     # 8 unit + 6 end-to-end loopback tests
cargo build --release                  # server + cli (+ GUI on desktop OSes)
cd android && ./gradlew assembleRelease # after building the JNI libs (see CI)
```

The Android keystore in `android/app/mcvpn-release.p12` is a **demo key**
(password `mcvpn123`) so release APKs install consistently — replace it before
distributing your own builds.
