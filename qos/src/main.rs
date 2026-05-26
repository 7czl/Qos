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

/// eBPF rate limiter (QoS) — supports both download (ingress) and upload (egress).
#[derive(Parser, Debug)]
#[command(name = "qos", about = "eBPF rate limiter (download + upload)")]
pub struct Opt {
    /// Network interface to attach the eBPF programs to.
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

    // Load eBPF bytecode (compiled by aya-build into OUT_DIR).
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/qos-ebpf-prog"
    )))
    .context("failed to load eBPF program — are you running as root?")?;

    // Add clsact qdisc to the interface (needed for both ingress and egress
    // eBPF programs). Ignore "already exists" errors.
    if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
        log::debug!("qdisc_add_clsact: {} (already present, continuing)", e);
    }

    // Attach the ingress (download) classifier.
    let ingress_prog_name = "tc_ingress";
    let ingress_prog: &mut SchedClassifier = bpf
        .program_mut(ingress_prog_name)
        .context("tc_ingress program not found in eBPF object")?
        .try_into()?;
    // Surface the full anyhow cause chain (incl. eBPF verifier text) on
    // failure, then propagate so `main` exits non-zero (Requirement 2.5).
    match ingress_prog.load() {
        Ok(()) => {}
        Err(err) => {
            log::error!("failed to load {ingress_prog_name}: {err:#}");
            return Err(anyhow::Error::from(err)
                .context(format!("eBPF verifier rejected {ingress_prog_name}")));
        }
    }
    match ingress_prog.attach(&opt.iface, TcAttachType::Ingress) {
        Ok(_) => {}
        Err(err) => {
            log::error!("failed to load {ingress_prog_name}: {err:#}");
            return Err(anyhow::Error::from(err)
                .context(format!("eBPF verifier rejected {ingress_prog_name}")));
        }
    }
    info!("attached tc_ingress (download limiter) to {}", opt.iface);

    // Attach the egress (upload) classifier.
    let egress_prog_name = "tc_egress";
    let egress_prog: &mut SchedClassifier = bpf
        .program_mut(egress_prog_name)
        .context("tc_egress program not found in eBPF object")?
        .try_into()?;
    match egress_prog.load() {
        Ok(()) => {}
        Err(err) => {
            log::error!("failed to load {egress_prog_name}: {err:#}");
            return Err(anyhow::Error::from(err)
                .context(format!("eBPF verifier rejected {egress_prog_name}")));
        }
    }
    match egress_prog.attach(&opt.iface, TcAttachType::Egress) {
        Ok(_) => {}
        Err(err) => {
            log::error!("failed to load {egress_prog_name}: {err:#}");
            return Err(anyhow::Error::from(err)
                .context(format!("eBPF verifier rejected {egress_prog_name}")));
        }
    }
    info!("attached tc_egress (upload limiter) to {}", opt.iface);

    // Take both rules maps and hand them to the manager.
    let rules_ingress = LpmTrie::try_from(
        bpf.take_map("RULES_INGRESS")
            .context("RULES_INGRESS map not found in eBPF object")?,
    )?;
    let rules_egress = LpmTrie::try_from(
        bpf.take_map("RULES_EGRESS")
            .context("RULES_EGRESS map not found in eBPF object")?,
    )?;
    let map_manager = Arc::new(Mutex::new(MapManager::new(rules_ingress, rules_egress)));

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let socket_path = opt.socket_path.clone();

    info!("starting UDS server and waiting for connections");

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
