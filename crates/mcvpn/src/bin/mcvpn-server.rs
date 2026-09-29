use clap::Parser;
use mcvpn::config::ServerConfig;
use mcvpn::{device, nat};
use std::path::PathBuf;
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(
    name = "mcvpn-server",
    about = "Minecraft-camouflaged VPN server (port 25565)"
)]
struct Args {
    /// Path to server.toml
    #[arg(long, default_value = "/etc/mcvpn/server.toml")]
    config: PathBuf,
    /// Write an example config (with a random token) and exit
    #[arg(long)]
    init: bool,
    /// Use a mock device (no root needed) — for smoke tests only
    #[arg(long)]
    mock_device: bool,
    /// Listen port override
    #[arg(long)]
    port: Option<u16>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcvpn=info".into()),
        )
        .init();
    let args = Args::parse();

    if args.init {
        let cfg = ServerConfig {
            token: token_hex(32),
            port: args.port.unwrap_or(ServerConfig::default().port),
            ..Default::default()
        };
        if let Some(parent) = args.config.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&args.config, cfg.to_toml())?;
        println!("Wrote {} — token: {}", args.config.display(), cfg.token);
        return Ok(());
    }

    let mut cfg = ServerConfig::load(&args.config)?;
    if let Some(p) = args.port {
        cfg.port = p;
    }
    if args.mock_device {
        cfg.mock_device = true;
    }
    if cfg.token.is_empty() {
        anyhow::bail!("config token is empty — run with --init first");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mock = cfg.mock_device;
        let cidr = cfg.tunnel_cidr.clone();
        let setup_nat = cfg.setup_nat && !mock;

        let server = tokio::spawn({
            let cfg = cfg.clone();
            let shutdown = shutdown_rx.clone();
            async move {
                let device = if cfg.mock_device {
                    let (a, _b) = device::mock::mock_pair();
                    a
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        let pool = mcvpn::ip_pool::IpPool::new(&cfg.tunnel_cidr)?;
                        let gw = pool.gateway();
                        let prefix = pool.prefix();
                        device::tun::open("mcvpn0", &format!("{gw}/{prefix}"), cfg.mtu)?
                    }
                    #[cfg(not(target_os = "linux"))]
                    anyhow::bail!("real TUN device supported on Linux only (use --mock-device)");
                };
                mcvpn::server::run(cfg, device, shutdown).await
            }
        });

        if setup_nat {
            #[cfg(target_os = "linux")]
            match nat::setup(&cidr, "mcvpn0") {
                Ok(()) => tracing::info!("NAT configured (iptables MASQUERADE + FORWARD)"),
                Err(e) => tracing::error!(
                    "NAT setup failed: {e} — clients will connect but have no internet"
                ),
            }
            #[cfg(not(target_os = "linux"))]
            tracing::warn!("NAT is Linux-only");
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            r = server => {
                if let Ok(Err(e)) = r {
                    tracing::error!("server error: {e}");
                }
            }
        }
        let _ = shutdown_tx.send(true);
        if setup_nat {
            #[cfg(target_os = "linux")]
            nat::teardown(&cidr, "mcvpn0");
        }
        tracing::info!("bye");
        anyhow::Ok(())
    })
}

fn token_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
