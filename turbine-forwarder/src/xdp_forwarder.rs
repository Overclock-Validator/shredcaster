use std::{
    cell::UnsafeCell,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    num::NonZeroU32,
    ptr::NonNull,
    time::Duration,
};

use anyhow::{Result, anyhow};
use arrayvec::ArrayVec;
use futures::{TryStreamExt, stream::FuturesUnordered};
use ping_async::IcmpEchoRequestor;
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EthernetPacket, MutableEthernetPacket},
    ipv4::{Ipv4Packet, MutableIpv4Packet, checksum},
    udp::{MutableUdpPacket, UdpPacket},
};
use xdpilone::{BufIdx, Socket, SocketConfig, Umem, UmemConfig, xdp::XdpDesc};

const PACKET_DATA_SIZE: usize = 1232;
const UMEM_SIZE: usize = 1 << 20; // 1MB
const TX_RING_SIZE: u32 = 1 << 12; // 4096 descriptors

// Static memory buffer for UMEM (required for AF_XDP)
static MEM: PacketMap = PacketMap(UnsafeCell::new([0; UMEM_SIZE]));

#[repr(align(4096))]
struct PacketMap(UnsafeCell<[u8; UMEM_SIZE]>);
unsafe impl Sync for PacketMap {}
unsafe impl Send for PacketMap {}

pub struct ArpCache {
    listeners: Vec<SocketAddrV4>,
    mac_addrs: HashMap<Ipv4Addr, [u8; 6]>,
}

impl ArpCache {
    pub async fn new(listeners: Vec<SocketAddrV4>) -> Result<Self> {
        let mut this = Self {
            listeners,
            mac_addrs: HashMap::new(),
        };
        let ips_to_ping: Vec<_> = this.listeners.iter().map(|s| *s.ip()).collect();

        println!(
            "Resolving MAC addresses for {} listeners...",
            ips_to_ping.len()
        );

        // First, check existing ARP table
        let Ok(arp_entries) = procfs::net::arp() else {
            return Err(anyhow!("Failed to read ARP table"));
        };
        for entry in arp_entries {
            if !ips_to_ping.contains(&entry.ip_address) {
                continue;
            }
            let Some(hw_addr) = entry.hw_address else {
                continue;
            };
            this.mac_addrs.insert(entry.ip_address, hw_addr);
        }

        // Ping any addresses not found in ARP table
        let mut ping_tasks = ips_to_ping
            .iter()
            .copied()
            .filter(|ip| !this.mac_addrs.contains_key(ip))
            .map(|ip| async move {
                let pinger = IcmpEchoRequestor::new(IpAddr::V4(ip), None, None, None)?;
                pinger.send().await?;
                Ok::<_, anyhow::Error>(())
            })
            .collect::<FuturesUnordered<_>>();
        while ping_tasks.try_next().await?.is_some() {}

        tokio::time::sleep(Duration::from_millis(100)).await;

        let Ok(arp_entries) = procfs::net::arp() else {
            return Err(anyhow!("Failed to read ARP table"));
        };

        for entry in arp_entries {
            if ips_to_ping.contains(&entry.ip_address)
                && !this.mac_addrs.contains_key(&entry.ip_address)
            {
                if let Some(hw_addr) = entry.hw_address {
                    this.mac_addrs.insert(entry.ip_address, hw_addr);
                    println!(
                        "Found MAC for {} after ping: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        entry.ip_address,
                        hw_addr[0],
                        hw_addr[1],
                        hw_addr[2],
                        hw_addr[3],
                        hw_addr[4],
                        hw_addr[5]
                    );
                }
            }
        }

        // Check if we resolved all addresses
        let unresolved: Vec<_> = ips_to_ping
            .iter()
            .filter(|ip| !this.mac_addrs.contains_key(ip))
            .collect();

        if !unresolved.is_empty() {
            return Err(anyhow!(
                "Could not resolve MAC addresses for: {unresolved:?}"
            ));
        }

        Ok(this)
    }
}

pub struct XdpForwarder {
    _umem: Umem,
    _socket: Socket,
    tx_ring: xdpilone::RingTx,
    buffer_pool: Vec<BufIdx>,
    listeners: ArpCache,
}

impl XdpForwarder {
    pub fn new(interface_name: &str, listeners: ArpCache) -> Result<Self> {
        // Initialize UMEM with static buffer
        let mem = NonNull::new(MEM.0.get() as *mut [u8])
            .ok_or_else(|| anyhow!("Failed to get memory buffer"))?;

        let umem = unsafe { Umem::new(UmemConfig::default(), mem) }
            .map_err(|e| anyhow!("Failed to create UMEM: {e}"))?;

        // Get interface info
        let mut info = xdpilone::IfInfo::invalid();
        let interface_cstr = std::ffi::CString::new(interface_name)
            .map_err(|e| anyhow!("Invalid interface name: {e}"))?;
        info.from_name(interface_cstr.as_c_str())
            .map_err(|e| anyhow!("Failed to get interface info for {interface_name}: {e:?}"))?;

        // Configure socket for TX only
        let socket_config = SocketConfig {
            rx_size: None, // No RX, we only transmit
            tx_size: NonZeroU32::new(TX_RING_SIZE),
            bind_flags: 0,
        };

        // Create socket
        let socket = Socket::with_shared(&info, &umem)
            .map_err(|e| anyhow!("Failed to create socket: {e:?}"))?;

        // Create ring and bind
        let rxtx = umem
            .rx_tx(&socket, &socket_config)
            .map_err(|e| anyhow!("Failed to create RX/TX rings: {e:?}"))?;

        umem.bind(&rxtx)
            .map_err(|e| anyhow!("Failed to bind socket: {e:?}"))?;

        // Get TX ring
        let tx_ring = rxtx
            .map_tx()
            .map_err(|e| anyhow!("Failed to map TX ring: {e:?}"))?;

        // Initialize buffer pool
        let buffer_pool = (0..TX_RING_SIZE).map(BufIdx).collect();

        Ok(Self {
            _umem: umem,
            _socket: socket,
            tx_ring,
            buffer_pool,
            listeners,
        })
    }

    pub fn forward_packet(&mut self, packet_data: &ArrayVec<u8, PACKET_DATA_SIZE>) -> Result<()> {
        let mut descriptors = Vec::new();
        let mut buffers_used = Vec::new();

        // Create a packet for each listener
        for listener in self.listeners.listeners.clone().iter() {
            if let Some(buf_idx) = self.get_buffer() {
                match self.prepare_packet(packet_data, listener, buf_idx) {
                    Ok(desc) => {
                        descriptors.push(desc);
                        buffers_used.push(buf_idx);
                    }
                    Err(e) => {
                        eprintln!("Failed to prepare packet for {listener}: {e}");
                        self.return_buffer(buf_idx);
                    }
                }
            } else {
                eprintln!("Warning: No available buffers for packet forwarding");
                break;
            }
        }

        if !descriptors.is_empty() {
            // Transmit all packets in one batch
            let mut writer = self.tx_ring.transmit(descriptors.len() as u32);

            let sent = writer.insert(descriptors.into_iter());
            writer.commit();

            if sent < self.listeners.listeners.len() as u32 {
                eprintln!(
                    "Warning: Only sent {} out of {} packets",
                    sent,
                    self.listeners.listeners.len()
                );
            }
        }

        // Return buffers to pool
        self.return_buffers(buffers_used);

        Ok(())
    }

    fn prepare_packet(
        &self,
        original_data: &[u8],
        listener: &SocketAddrV4,
        buf_idx: BufIdx,
    ) -> Result<XdpDesc> {
        let mut frame = self
            ._umem
            .frame(buf_idx)
            .ok_or_else(|| anyhow!("Failed to get frame for buffer index {buf_idx:?}"))?;

        let buffer = unsafe { frame.addr.as_mut() };

        // Parse the original packet
        let eth_packet = EthernetPacket::new(original_data)
            .ok_or_else(|| anyhow!("Failed to parse Ethernet packet"))?;

        let ipv4_packet = Ipv4Packet::new(eth_packet.payload())
            .ok_or_else(|| anyhow!("Failed to parse IPv4 packet"))?;

        let udp_packet = UdpPacket::new(ipv4_packet.payload())
            .ok_or_else(|| anyhow!("Failed to parse UDP packet"))?;

        // Get destination info
        let dst_ip = listener.ip();

        let dst_mac = *self
            .listeners
            .mac_addrs
            .get(dst_ip)
            .expect("[BUG] ARP cache is unpopulated");

        // Calculate total packet size
        let eth_hdr_len = 14; // Ethernet header size
        let ip_hdr_len = ipv4_packet.get_header_length() as usize * 4;
        let udp_hdr_len = 8; // UDP header size
        let payload_len = udp_packet.payload().len();
        let total_len = eth_hdr_len + ip_hdr_len + udp_hdr_len + payload_len;

        if total_len > buffer.len() {
            return Err(anyhow!("Packet too large for buffer"));
        }

        // Create new Ethernet packet
        let mut new_eth_packet = MutableEthernetPacket::new(&mut buffer[0..total_len])
            .ok_or_else(|| anyhow!("Failed to create mutable Ethernet packet"))?;

        new_eth_packet.clone_from(&eth_packet);
        new_eth_packet.set_destination(pnet::util::MacAddr::from(dst_mac));

        // Create new IPv4 packet
        let mut new_ipv4_packet = MutableIpv4Packet::new(new_eth_packet.payload_mut())
            .ok_or_else(|| anyhow!("Failed to create mutable IPv4 packet"))?;

        new_ipv4_packet.clone_from(&ipv4_packet);
        new_ipv4_packet.set_destination(*dst_ip);

        // Recalculate IPv4 checksum
        let checksum = checksum(&new_ipv4_packet.to_immutable());
        new_ipv4_packet.set_checksum(checksum);

        // Create new UDP packet
        let mut new_udp_packet = MutableUdpPacket::new(new_ipv4_packet.payload_mut())
            .ok_or_else(|| anyhow!("Failed to create mutable UDP packet"))?;

        new_udp_packet.clone_from(&udp_packet);
        new_udp_packet.set_destination(listener.port());

        new_udp_packet.set_checksum(0);

        Ok(XdpDesc {
            addr: frame.offset,
            len: total_len as u32,
            options: 0,
        })
    }

    fn get_buffer(&mut self) -> Option<BufIdx> {
        self.buffer_pool.pop()
    }

    fn return_buffer(&mut self, buffer: BufIdx) {
        self.buffer_pool.push(buffer);
    }

    fn return_buffers(&mut self, buffers: Vec<BufIdx>) {
        self.buffer_pool.extend(buffers);
    }
}
