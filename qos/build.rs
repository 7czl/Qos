fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "qos-ebpf",
            // Let aya-build resolve the path from the workspace.
            // Using CARGO_MANIFEST_DIR ensures an absolute path.
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../qos-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )
    .expect("failed to build eBPF program");
}
