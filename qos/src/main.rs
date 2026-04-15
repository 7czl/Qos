pub mod map_manager;
pub mod protocol;
pub mod uds;

use std::sync::Arc;

use anyhow::Context;
use aya::maps::lpm_trie::LpmTrie;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use clap::Parser;
use log::info;
use tokio::sync::Mutex;

use map_manager::MapManager;

/// eBPF download rate limiter (QoS).
#[derive(Parser, Debug)]
#[command(name = "qos", about = "eBPF download rate limiter")]
pub struct Opt {
    /// Network interface to attach the eBPF program to.
    #[arg(long)]
    iface: String,

    /// Path for the Unix Domain Socket.
    #[arg(long, default_value = "/var/run/qos.sock")]
    socket_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opt = Opt::parse();

    info!("interface: {}", opt.iface);
    info!("socket path: {}", opt.socket_path);

    // Load eBPF bytecode (compiled by aya-build and written to OUT_DIR)
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/qos-ebpf-prog"
    )))
    .context("failed to load eBPF program — are you running as root?")?;

    // Add clsact qdisc to the interface (ignore if already exists)
    if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
        log::warn!("qdisc_add_clsact: {} (may already exist)", e);
    }

    // Attach TC ingress program
    let program: &mut SchedClassifier = bpf
        .program_mut("tc_ingress")
        .context("tc_ingress program not found in eBPF object")?
        .try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, TcAttachType::Ingress)
        .context(format!(
            "failed to attach TC ingress to '{}' — does the interface exist?",
            opt.iface
        ))?;

    // Get BPF map reference and create MapManager
    let rules_map = LpmTrie::try_from(
        bpf.map_mut("RULES").context("RULES map not found in eBPF object")?,
    )?;
    let map_manager = Arc::new(Mutex::new(MapManager::new(rules_map)));

    // Set up SIGTERM handler
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let socket_path = opt.socket_path.clone();

    info!("starting UDS server and waiting for connections");

    // Run UDS server until a shutdown signal is received
    tokio::select! {
        result = uds::run_uds_server(&opt.socket_path, map_manager) => {
            if let Err(e) = result {
                log::error!("UDS server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
    }

    // Cleanup: remove socket file
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
        info!("removed socket file: {}", socket_path);
    }

    info!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_iface_is_required() {
        let result = Opt::try_parse_from(["qos"]);
        assert!(result.is_err(), "--iface should be required");
    }

    #[test]
    fn test_socket_path_default() {
        let opt = Opt::try_parse_from(["qos", "--iface", "eth0"]).unwrap();
        assert_eq!(opt.iface, "eth0");
        assert_eq!(opt.socket_path, "/var/run/qos.sock");
    }

    #[test]
    fn test_socket_path_custom() {
        let opt =
            Opt::try_parse_from(["qos", "--iface", "lo", "--socket-path", "/tmp/qos.sock"])
                .unwrap();
        assert_eq!(opt.iface, "lo");
        assert_eq!(opt.socket_path, "/tmp/qos.sock");
    }

    #[test]
    fn test_unknown_arg_rejected() {
        let result = Opt::try_parse_from(["qos", "--iface", "eth0", "--bogus"]);
        assert!(result.is_err());
    }
}
