use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use clap::Parser;
use tokio::{net::UdpSocket, task::JoinSet};

#[derive(Parser)]
struct UdpSpammerArgs {
    #[arg(short, long)]
    target: SocketAddr,
    /// Packets per second
    #[arg(short, long, default_value_t = 5000)]
    pps: u32,
}

const SPAM_DURATION_SECS: u32 = 10; // 10 seconds
const PACKET_BATCH_SIZE: u32 = 100; // Number of packets to send in one go

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = UdpSpammerArgs::parse();

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let packet = [0u8; 1232];
    let total_packets = args.pps * SPAM_DURATION_SECS;
    let batch_cnt = total_packets
        .checked_div(PACKET_BATCH_SIZE)
        .ok_or_else(|| anyhow!("PPS must be at least {}", PACKET_BATCH_SIZE))?;
    let remaining = total_packets % PACKET_BATCH_SIZE;

    let batch_time = Duration::from_secs(SPAM_DURATION_SECS as u64) / batch_cnt;
    if batch_time.as_millis() < 1 {
        return Err(anyhow!(
            "PPS too high, must be at most {}",
            PACKET_BATCH_SIZE * SPAM_DURATION_SECS
        ));
    }

    for i in 0..batch_cnt {
        let packet_cnt = PACKET_BATCH_SIZE + if i == batch_cnt - 1 { remaining } else { 0 };
        let start = SystemTime::now();

        let mut spawner = JoinSet::new();
        for _ in 0..packet_cnt {
            let socket = socket.clone();
            spawner.spawn(async move {
                let _ = socket.send_to(&packet, args.target).await;
            });
        }

        spawner.join_all().await;
        println!(
            "Spawned {} packets at {} EPOCH MS",
            args.pps,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let elapsed = start.elapsed().unwrap();
        if let Some(sleep_dur) = batch_time.checked_sub(elapsed) {
            tokio::time::sleep(sleep_dur).await;
        }
    }

    Ok(())
}
