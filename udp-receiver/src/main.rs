use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Parser, Debug)]
struct Args {
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting UDP server on {}", args.addr);

    let socket = UdpSocket::bind(&args.addr).await?;
    println!("Listening for packets...");

    let mut buf = [0u8; 1232];
    let mut packet_count = 0u64;
    let mut last_packet_time: Duration;
    let timeout_duration = Duration::from_secs(10);

    let expected_packet = [0u8; 1232];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;

        if len == 1232 && buf == expected_packet {
            packet_count += 1;
            last_packet_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
            println!(
                "First packet received from {peer}, at {} EPOCH_MS",
                last_packet_time.as_millis()
            );
            break;
        } else {
            println!(
                "Ignoring invalid packet from {} ({} bytes, expected 1232 null bytes)",
                peer, len
            );
        }
    }

    loop {
        match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, peer))) => {
                // Validate packet: must be exactly 1232 bytes of null bytes
                if len == 1232 && buf[..len].iter().all(|&b| b == 0) {
                    packet_count += 1;
                    last_packet_time = SystemTime::now().duration_since(UNIX_EPOCH)?;
                } else {
                    println!(
                        "Ignoring invalid packet from {} ({} bytes, expected 1232 null bytes)",
                        peer, len
                    );
                }
            }
            Ok(Err(e)) => {
                eprintln!("Error receiving packet: {}", e);
                break;
            }
            Err(_) => {
                // Timeout occurred
                println!("\nNo packets received for 10 seconds. Shutting down...");
                break;
            }
        }
    }

    println!(
        "Last packet received at: {} EPOCH_MS",
        last_packet_time.as_millis()
    );
    println!("Total packets received: {}", packet_count);

    Ok(())
}
