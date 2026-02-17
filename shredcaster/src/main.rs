mod config;
mod metrics;
mod shred_sampler;

use std::{
    borrow::Borrow,
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread::{self},
    time::Duration,
};

use agave_xdp::device::{NetworkDevice, QueueId};
use anyhow::anyhow;
use arrayvec::ArrayVec;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData, PerCpuValues, RingBuf},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
    util::nr_cpus,
};
use crossbeam_channel::TryRecvError;
use tokio::{io::unix::AsyncFd, signal, sync::oneshot, task::JoinHandle};
use wtransport::Identity;

use crate::{
    config::Config,
    metrics::{PacketCtr, SharedPacketCtr, start_packet_counter_print_loop},
    shred_sampler::{NoOpShredSamplerTx, ShredSamplerTx, spawn_webtransport_shred_sampler},
};

const PACKET_DATA_SIZE: usize = 1232;

#[derive(Clone)]
struct SharedPacketData(pub Arc<ArrayVec<u8, PACKET_DATA_SIZE>>);

impl SharedPacketData {
    pub fn new(data: ArrayVec<u8, PACKET_DATA_SIZE>) -> Self {
        Self(Arc::new(data))
    }
}

impl AsRef<[u8]> for SharedPacketData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

async fn turbine_watcher_loop<T: Borrow<MapData>>(
    map: RingBuf<T>,
    tx: crossbeam_channel::Sender<(Arc<[SocketAddr]>, SharedPacketData)>,
    listeners: Arc<Mutex<Arc<[SocketAddr]>>>,
    mut shred_sampler: impl ShredSamplerTx,
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
                let listeners = listeners.lock().unwrap().clone();

                let mut ingress_packets = 0;
                let mut egress_packets = 0;
                while let Some(read) = rb.next() {
                    let ptr = read.as_ptr() as *const (ArrayVec<u8, PACKET_DATA_SIZE>, bool);
                    let (data, is_egress) = unsafe { core::ptr::read(ptr) };
                    let data = SharedPacketData::new(data);
                    if shred_sampler.insert_shred(&data).is_none() {
                        continue;
                    }
                    _ = tx.try_send((listeners.clone(), data.clone()));
                    if is_egress {
                        egress_packets += 1;
                    } else {
                        ingress_packets += 1;
                    }
                }
                shred_sampler.flush();
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

fn spawn_turbine_watcher<T: Borrow<MapData> + 'static + Send>(
    map: RingBuf<T>,
    tx: crossbeam_channel::Sender<(Arc<[SocketAddr]>, SharedPacketData)>,
    listeners: Arc<Mutex<Arc<[SocketAddr]>>>,
    shred_sampler: impl ShredSamplerTx + 'static + Send,
    packet_counter: SharedPacketCtr,
    exit: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) =
            turbine_watcher_loop(map, tx, listeners, shred_sampler, packet_counter, exit).await
        {
            eprintln!("turbine watcher stopped: {e}");
        }
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Config::load()?;

    if args.tvu_ports.is_empty() || args.tvu_ports.len() > 100 {
        return Err(anyhow::anyhow!(
            "must specify between 1 and 100 tvu ports to watch"
        ));
    }

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

    if args.watch_egress {
        let egress_iface = args.egress_iface.as_deref().unwrap_or(&args.iface);
        load_tc_program(&mut bpf, egress_iface)?;
        if let Some(egress_port) = args.egress_port {
            let mut shred_egress_port_map =
                Array::try_from(bpf.map_mut("SHRED_EGRESS_PORT").unwrap())?;
            shred_egress_port_map.set(0, egress_port, 0)?;
            println!("started watching turbine egress on {egress_port}");
        }
    } else {
        eprintln!("not watching turbine egress as disabled");
    }

    let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
    let mut turbine_port_map =
        aya::maps::PerCpuHashMap::<_, _, u8>::try_from(bpf.map_mut("TURBINE_PORTS").unwrap())?;
    for port in args.tvu_ports.iter().copied() {
        turbine_port_map.insert(port, PerCpuValues::try_from(vec![0; nr_cpus])?, 0)?;
        println!("started watching turbine on {port}");
    }

    let turbine_packets = RingBuf::try_from(bpf.take_map("PACKET_BUF").unwrap())?;

    let (exit_tx, exit_rx) = oneshot::channel();

    let packet_counter = Arc::new(PacketCtr::default());

    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let (drop_sender, drop_rx) = crossbeam_channel::unbounded();

    let (_conf_watcher, shared_listeners) = args.spawn_config_listener()?;
    let packet_counter_c = packet_counter.clone();
    let turbine_loop = if let Some(cert_path) = args.webtransport_cert {
        let webtransport_key = args.webtransport_private_key.ok_or_else(|| {
            anyhow!("webtransport_private_key must be set if webtransport_cert is set")
        })?;
        let auth_token = args.webtransport_auth_token.ok_or_else(|| {
            anyhow!("webtransport_auth_token must be set if webtransport_cert is set")
        })?;
        let config = wtransport::ServerConfig::builder()
            .with_bind_default(args.webtransport_port)
            .with_identity(Identity::load_pemfiles(&cert_path, &webtransport_key).await?)
            .build();
        let sampler = spawn_webtransport_shred_sampler(auth_token, config)?;
        spawn_turbine_watcher(
            turbine_packets,
            packet_tx,
            shared_listeners,
            sampler,
            packet_counter_c,
            exit_rx,
        )
    } else {
        spawn_turbine_watcher(
            turbine_packets,
            packet_tx,
            shared_listeners,
            NoOpShredSamplerTx,
            packet_counter_c,
            exit_rx,
        )
    };

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
            args.tx_pinned_cpu_core,
            &NetworkDevice::new(&args.iface).unwrap(),
            QueueId(args.tx_pinned_cpu_core as u64),
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
