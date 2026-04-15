fn main() {
    let package = aya_build::Package {
        name: "qos-ebpf",
        root_dir: "../qos-ebpf",
        no_default_features: false,
        features: &[],
    };
    aya_build::build_ebpf([package], aya_build::Toolchain::Nightly)
        .expect("failed to build eBPF program");
}
