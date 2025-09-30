use std::borrow::Borrow;

use arrayvec::ArrayVec;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use tokio::{io::unix::AsyncFd, signal, sync::oneshot};

#[derive(Parser)]
struct Args {
    port: u16,
    iface: String,
    #[arg(default_value_t = 8192)]
    outgoing_port: u16,
}

const PACKET_DATA_SIZE: usize = 1232;

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    mut exit: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let mut reader = AsyncFd::new(map)?;

    loop {
        tokio::select! {
            _ = &mut exit => {
                break;
            }
            mut guard = reader.readable_mut() => {
                let rb = guard.as_mut().unwrap().get_inner_mut();

                while let Some(read) = rb.next() {
                    let ptr = read.as_ptr() as *const ArrayVec<u8, PACKET_DATA_SIZE>;
                    let data = unsafe { (*ptr).as_slice() };
                    println!("TODO: implement packet forwarding {}", data.len());
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/turbine-ebpf-spy.o"
    )))?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_turbine_probe")
        .ok_or_else(|| anyhow::anyhow!("program not found"))?
        .try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpFlags::default())?;

    let mut turbine_port_map = Array::try_from(bpf.map_mut("TURBINE_PORT").unwrap())?;
    turbine_port_map.set(0, args.outgoing_port, 0)?;
    let turbine_packets = RingBuf::try_from(bpf.take_map("PACKET_BUF").unwrap())?;

    let (exit_tx, exit_rx) = oneshot::channel();
    let turbine_loop = tokio::spawn(async move {
        if let Err(e) = turbine_watcher_loop(turbine_packets, exit_rx).await {
            eprintln!("turbine watcher stopped {e}");
        }
    });

    signal::ctrl_c().await?;
    _ = exit_tx.send(());

    turbine_loop.await?;

    Ok(())
}
