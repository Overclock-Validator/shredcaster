use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use solana_ledger::shred::{self, ShredType};
use tokio::{net::UdpSocket, signal};

#[derive(Parser, Debug)]
struct Args {
    /// Bind Address 1
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    addr_1: SocketAddr,
    #[arg(short, long, default_value = "0.0.0.0:8001")]
    addr_2: SocketAddr,
}

async fn packet_recv_loop(thread_id: String, addr: SocketAddr) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(&addr).await?;
    println!("{{thread_id}} listening for packets on {addr}");

    let mut buf = [0u8; 1232];

    loop {
        socket.recv_from(&mut buf).await?;
        let Some(id) = shred::layout::get_shred_id(&buf) else {
            continue;
        };
        if !matches!(shred::layout::get_shred_type(&buf), Ok(ShredType::Data)) {
            continue;
        }
        if id.index() % 100 == 0 {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            println!(
                "source: {thread_id} recv shred slot: {}, idx: {}, timestamp: {}",
                id.slot(),
                id.index(),
                timestamp.as_millis()
            );
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("Starting UDP Servers on: {}, {}", args.addr_1, args.addr_2);

    let handle1 = tokio::spawn(async move {
        if let Err(e) = packet_recv_loop("shredcaster".into(), args.addr_1).await {
            eprintln!("shredcaster thread died: {e}");
        }
    });
    let handle2 = tokio::spawn(async move {
        if let Err(e) = packet_recv_loop("val-direct".into(), args.addr_2).await {
            eprintln!("val thread died: {e}");
        }
    });
    signal::ctrl_c().await.unwrap();
    handle1.abort();
    handle2.abort();
}
