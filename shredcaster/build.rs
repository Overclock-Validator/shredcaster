fn main() -> ebpf_builder::Result<()> {
    ebpf_builder::build_ebpf("turbine-ebpf-spy")
}
