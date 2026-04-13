use anyhow::Result;
use clap::Parser;
use tokio::{select, signal};
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

    let expected_packet_mask = [0u8; 1228];
    let mut packet_times = Vec::with_capacity(1000);

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;

        if len == 1232 && buf[..1228] == expected_packet_mask {
            packet_count += 1;
            last_packet_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
            println!(
                "First packet received from {peer}, at {} EPOCH_MS",
                last_packet_time.as_millis()
            );
            let packet_id = u32::from_le_bytes(buf[1228..1232].try_into().unwrap());
            packet_times.push((packet_id, last_packet_time.as_millis()));
            break;
        } else {
            // println!(
            //     "Ignoring invalid packet from {} ({} bytes, expected 1228 null bytes)",
            //     peer, len
            // );
        }
    }

    let mut ctrl_c_handle = tokio::spawn(signal::ctrl_c());
    loop {
        select! {
            _ = &mut ctrl_c_handle => {
                break;
            }
            res = timeout(timeout_duration, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, _))) => {
                        // Validate packet: must be exactly 1232 bytes of null bytes
                        if len == 1232 && buf[..1228].iter().all(|&b| b == 0) {
                            packet_count += 1;
                            last_packet_time = SystemTime::now().duration_since(UNIX_EPOCH)?;
                            let packet_id = u32::from_le_bytes(buf[1228..1232].try_into().unwrap());
                            packet_times.push((packet_id, last_packet_time.as_millis()));
                        } /*else {
                            println!(
                                "Ignoring invalid packet from {} ({} bytes, expected 1232 null bytes)",
                                peer, len
                            );
                        }*/
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
        }
    }

    println!(
        "Last packet received at: {} EPOCH_MS",
        last_packet_time.as_millis()
    );
    println!("Total packets received: {}", packet_count);
    for (packet_id, packet_time) in packet_times {
        println!("packet_id: {packet_id}, timestamp: {packet_time}")
    }

    Ok(())
}
