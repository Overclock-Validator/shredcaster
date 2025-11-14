mod metrics;

use std::{
    borrow::Borrow,
    net::SocketAddr,
    sync::Arc,
    thread::{self},
    time::Duration,
};

use agave_xdp::{
    device::{NetworkDevice, QueueId},
    dispatcher::{EbpfPrograms, XdpDispatcher},
};
use anyhow::anyhow;
use arrayvec::ArrayVec;
// mod xdp_forwarder;
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{MapData, PerCpuValues, RingBuf},
    programs::{SchedClassifier, TcAttachType, XdpFlags, tc},
    util::nr_cpus,
};
use clap::Parser;
use crossbeam_channel::TryRecvError;
use nix::net::if_::if_nametoindex;
use tokio::{io::unix::AsyncFd, signal, sync::oneshot};
use uuid::Uuid;

use crate::metrics::{PacketCtr, SharedPacketCtr, start_packet_counter_print_loop};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    tvu_ports: Vec<u16>,
    #[arg(short, long)]
    iface: String,
    #[arg(short, long)]
    listeners: Vec<SocketAddr>,
    #[arg(short, long, default_value_t = 9122)]
    forwarder_port: u16,
    #[arg(short, long, default_value_t = false)]
    watch_egress: bool,
    #[arg(short, long)]
    egress_port: Option<u16>,
}

const PACKET_DATA_SIZE: usize = 1232;

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    tx: crossbeam_channel::Sender<(Arc<[SocketAddr]>, ArrayVec<u8, PACKET_DATA_SIZE>)>,
    listeners: Arc<[SocketAddr]>,
    packet_counter: SharedPacketCtr,
    mut exit: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let mut reader = AsyncFd::new(map)?;

    loop {
        tokio::select! {
            _ = &mut exit => {
                break;
            }
            mut guard = reader.readable_mut() => {
                let guard = guard.as_mut().unwrap();
                let rb = guard.get_inner_mut();

                let mut ingress_packets = 0;
                let mut egress_packets = 0;
                while let Some(read) = rb.next() {
                    let ptr = read.as_ptr() as *const (ArrayVec<u8, PACKET_DATA_SIZE>, bool);
                    let (data, is_egress) = unsafe { core::ptr::read(ptr) };
                    _ = tx.try_send((listeners.clone(), data));
                    if is_egress {
                        egress_packets += 1;
                    } else {
                        ingress_packets += 1;
                    }
                }
                packet_counter.add(egress_packets, ingress_packets);
                guard.clear_ready();
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

    if args.tvu_ports.is_empty() || args.tvu_ports.len() > 100 {
        return Err(anyhow::anyhow!(
            "must specify between 1 and 100 tvu ports to watch"
        ));
    }

    let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/turbine-ebpf-spy.o"));

    let ebpf_id = Uuid::new_v4().to_string();
    let mut ebpf_programs = EbpfPrograms::new(ebpf_id.clone(), EbpfLoader::new(), bpf_bytes)
        .set_priority("xdp_turbine_probe", 1);

    let iface_idx = if_nametoindex(args.iface.as_str())?;
    let mut dispatcher =
        XdpDispatcher::new_with_programs(iface_idx, XdpFlags::DRV_MODE, vec![&mut ebpf_programs])
            .map_err(|e| anyhow!("{e}"))?;
    let bpf = dispatcher.ebpf_mut(&ebpf_id).unwrap();

    // if args.watch_egress {
    //     load_tc_program(&mut bpf, &args.iface)?;
    //     if let Some(egress_port) = args.egress_port {
    //         let mut shred_egress_port_map =
    //             Array::try_from(bpf.map_mut("SHRED_EGRESS_PORT").unwrap())?;
    //         shred_egress_port_map.set(0, egress_port, 0)?;
    //         println!("started watching turbine egress on {egress_port}");
    //     }
    // } else {
    //     eprintln!("not watching turbine egress as disabled");
    // }

    let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
    let mut turbine_port_map =
        aya::maps::PerCpuHashMap::<_, _, u8>::try_from(bpf.map_mut("TURBINE_PORTS").unwrap())?;
    for port in args.tvu_ports {
        turbine_port_map.insert(port, PerCpuValues::try_from(vec![0; nr_cpus])?, 0)?;
        println!("started watching turbine on {port}");
    }

    let turbine_packets = RingBuf::try_from(bpf.take_map("PACKET_BUF").unwrap())?;

    let (exit_tx, exit_rx) = oneshot::channel();

    let packet_counter = Arc::new(PacketCtr::default());

    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let (drop_sender, drop_rx) = crossbeam_channel::unbounded();

    let packet_counter_c = packet_counter.clone();
    let turbine_loop = tokio::spawn(async move {
        if let Err(e) = turbine_watcher_loop(
            turbine_packets,
            packet_tx,
            args.listeners.into(),
            packet_counter_c,
            exit_rx,
        )
        .await
        {
            eprintln!("turbine watcher stopped {e}");
        }
    });

    let pkt_counter_loop = tokio::spawn(async move {
        if let Err(e) = start_packet_counter_print_loop(packet_counter).await {
            eprintln!("packet metrics stopped: {e}");
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
            QueueId(82),
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
    pkt_counter_loop.await?;
    pkt_fwder
        .join()
        .map_err(|e| anyhow::anyhow!("packet forwarder panicked: {e:?}"))?;
    pkt_dropper
        .join()
        .map_err(|e| anyhow::anyhow!("packet dropper panicked: {e:?}"))?;

    Ok(())
}
