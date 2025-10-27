use std::{borrow::Borrow, net::SocketAddrV4};

use arrayvec::ArrayVec;
mod xdp_forwarder;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
};
use clap::Parser;
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::{mpsc, oneshot},
};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    port: u16,
    #[arg(short, long)]
    iface: String,
    #[arg(short, long)]
    listeners: Vec<SocketAddrV4>,
    #[arg(short, long)]
    egress_port: Option<u16>,
}

const PACKET_SIZE: usize = 1280;

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    tx: mpsc::Sender<ArrayVec<u8, PACKET_SIZE>>,
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
                    let ptr = read.as_ptr() as *const ArrayVec<u8, PACKET_SIZE>;
                    let data = unsafe { core::ptr::read(ptr) };
                    _ = tx.send(data).await;
                }
            }
        }
    }

    Ok(())
}

fn packet_forwarder(
    mut xdp_forwarder: xdp_forwarder::XdpForwarder,
    mut rx: mpsc::Receiver<ArrayVec<u8, PACKET_SIZE>>,
) {
    while let Some(packet) = rx.blocking_recv() {
        if let Err(e) = xdp_forwarder.forward_packet(&packet) {
            eprintln!("failed to forward packet: {e}");
        }
    }
}

fn load_tc_program(ebpf: &mut Ebpf, iface: &str) -> anyhow::Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut("tc_egress_probe")
        .ok_or_else(|| anyhow::anyhow!("program not found"))?
        .try_into()?;

    _ = tc::qdisc_add_clsact(iface);
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

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

    if let Some(egress_port) = args.egress_port {
        load_tc_program(&mut bpf, &args.iface)?;
        let mut shred_egress_port_map = Array::try_from(bpf.map_mut("SHRED_EGRESS_PORT").unwrap())?;
        shred_egress_port_map.set(0, egress_port, 0)?;
        println!("started watching turbine egress on {egress_port}");
    } else {
        eprintln!("not watching turbine egress as no egress port was specified");
    }

    let mut turbine_port_map = Array::try_from(bpf.map_mut("TURBINE_PORT").unwrap())?;
    turbine_port_map.set(0, args.port, 0)?;

    println!("started watching turbine on {}", args.port);

    let turbine_packets = RingBuf::try_from(bpf.take_map("PACKET_BUF").unwrap())?;

    let (exit_tx, exit_rx) = oneshot::channel();

    let (packet_tx, packet_rx) = mpsc::channel(8192);

    let turbine_loop = tokio::spawn(async move {
        if let Err(e) = turbine_watcher_loop(turbine_packets, packet_tx, exit_rx).await {
            eprintln!("turbine watcher stopped {e}");
        }
    });

    let arp_cache = xdp_forwarder::ArpCache::new(args.listeners).await?;
    let pkt_fwder = std::thread::spawn(move || {
        let xdp_forwarder = xdp_forwarder::XdpForwarder::new(&args.iface, arp_cache)?;
        packet_forwarder(xdp_forwarder, packet_rx);

        Ok::<_, anyhow::Error>(())
    });

    signal::ctrl_c().await?;
    _ = exit_tx.send(());

    turbine_loop.await?;
    pkt_fwder
        .join()
        .map_err(|e| anyhow::anyhow!("packet forwarder panicked: {e:?}"))??;

    Ok(())
}
