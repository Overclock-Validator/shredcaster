use std::{borrow::Borrow, net::SocketAddr};

use arrayvec::ArrayVec;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use futures::{StreamExt, stream::FuturesUnordered};
use tokio::{
    io::unix::AsyncFd,
    net::UdpSocket,
    signal,
    sync::{mpsc, oneshot},
};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    port: u16,
    #[arg(short, long)]
    iface: String,
    #[arg(default_value_t = 8192, short, long)]
    outgoing_port: u16,
    #[arg(short, long)]
    listeners: Vec<SocketAddr>,
}

const PACKET_DATA_SIZE: usize = 1232;

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    tx: mpsc::Sender<ArrayVec<u8, PACKET_DATA_SIZE>>,
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
                    let data = unsafe { core::ptr::read(ptr) };
                    _ = tx.send(data).await;
                }
            }
        }
    }

    Ok(())
}

async fn packet_forwarder(
    socket: UdpSocket,
    listeners: Vec<SocketAddr>,
    mut rx: mpsc::Receiver<ArrayVec<u8, PACKET_DATA_SIZE>>,
) {
    while let Some(packet) = rx.recv().await {
        let mut jobs = listeners
            .iter()
            .map(async |listener| {
                if let Err(e) = socket.send_to(packet.as_slice(), listener).await {
                    eprintln!("failed to send packet to {listener}, {e}");
                }
            })
            .collect::<FuturesUnordered<_>>();
        while jobs.next().await.is_some() {}
    }
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

    let pkt_fwder_socket = UdpSocket::bind(format!("0.0.0.0:{}", args.outgoing_port)).await?;
    let pkt_fwder = tokio::spawn(packet_forwarder(
        pkt_fwder_socket,
        args.listeners,
        packet_rx,
    ));

    signal::ctrl_c().await?;
    _ = exit_tx.send(());

    turbine_loop.await?;
    pkt_fwder.await?;

    Ok(())
}
