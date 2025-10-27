use std::{borrow::Borrow, net::SocketAddr, sync::Arc, thread, time::Duration};

use agave_xdp::device::{NetworkDevice, QueueId};
use arrayvec::ArrayVec;
// mod xdp_forwarder;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
};
use clap::Parser;
use crossbeam_channel::TryRecvError;
use tokio::{io::unix::AsyncFd, signal, sync::oneshot};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    port: u16,
    #[arg(short, long)]
    iface: String,
    #[arg(short, long)]
    listeners: Vec<SocketAddr>,
    #[arg(short, long, default_value_t = 9122)]
    forwarder_port: u16,
    #[arg(short, long)]
    egress_port: Option<u16>,
}

const PACKET_DATA_SIZE: usize = 1232;

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    tx: crossbeam_channel::Sender<(Arc<[SocketAddr]>, ArrayVec<u8, PACKET_DATA_SIZE>)>,
    listeners: Arc<[SocketAddr]>,
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
                    _ = tx.try_send((listeners.clone(), data));
                }
            }
        }
    }

    Ok(())
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

    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let (drop_sender, drop_rx) = crossbeam_channel::unbounded();
    let turbine_loop = tokio::spawn(async move {
        if let Err(e) =
            turbine_watcher_loop(turbine_packets, packet_tx, args.listeners.into(), exit_rx).await
        {
            eprintln!("turbine watcher stopped {e}");
        }
    });

    let pkt_dropper = std::thread::spawn(move || {
        loop {
            match drop_rx.try_recv() {
                Ok(i) => {
                    drop(i);
                }
                Err(TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }
    });

    let pkt_fwder = std::thread::spawn(move || {
        agave_xdp::tx_loop::tx_loop(
            0,
            &NetworkDevice::new(&args.iface).unwrap(),
            QueueId(0),
            false,
            None,
            None,
            args.forwarder_port,
            None,
            packet_rx,
            drop_sender,
        )
    });

    signal::ctrl_c().await?;
    _ = exit_tx.send(());

    turbine_loop.await?;
    pkt_fwder
        .join()
        .map_err(|e| anyhow::anyhow!("packet forwarder panicked: {e:?}"))?;
    pkt_dropper
        .join()
        .map_err(|e| anyhow::anyhow!("packet dropper panicked: {e:?}"))?;

    Ok(())
}
