use aya::include_bytes_aligned;
use clap::Parser;
use tokio::signal;
use uuid::Uuid;
use xdp_dispatcher::{EbpfPrograms, XdpDispatcher};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/dummy-ebpf.o"));

    let ebpf_id = Uuid::new_v4().to_string();
    let ebpf_programs = EbpfPrograms::new(ebpf_id, bpf_bytes).set_priority("dummy_xdp_probe", 0);

    let _dispatcher = XdpDispatcher::new_with_programs(args.iface.clone(), vec![&ebpf_programs])?;

    signal::ctrl_c().await?;

    Ok(())
}
