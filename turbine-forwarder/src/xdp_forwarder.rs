use std::{cell::UnsafeCell, net::SocketAddrV4, num::NonZeroU32, ptr::NonNull};

use anyhow::{Result, anyhow};
use arrayvec::ArrayVec;
use pnet::packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ipv4::{Ipv4Packet, MutableIpv4Packet, checksum},
    udp::{MutableUdpPacket, UdpPacket},
};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig, xdp::XdpDesc};

const PACKET_SIZE: usize = 1280;
const UMEM_SIZE: usize = 1 << 20; // 1MB
const TX_RING_SIZE: u32 = 1 << 14;

// Static memory buffer for UMEM (required for AF_XDP)
static MEM: PacketMap = PacketMap(UnsafeCell::new([0; UMEM_SIZE]));

#[repr(align(4096))]
struct PacketMap(UnsafeCell<[u8; UMEM_SIZE]>);
unsafe impl Sync for PacketMap {}
unsafe impl Send for PacketMap {}

pub struct XdpForwarder {
    umem: Umem,
    _socket: Socket,
    tx_ring: xdpilone::RingTx,
    device_queue: xdpilone::DeviceQueue,
    listeners: Vec<SocketAddrV4>,
}

impl XdpForwarder {
    pub fn new(interface_name: &str, listeners: Vec<SocketAddrV4>) -> Result<Self> {
        let mem = NonNull::new(MEM.0.get() as *mut [u8])
            .ok_or_else(|| anyhow!("Failed to get memory buffer"))?;

        let umem = unsafe { Umem::new(UmemConfig::default(), mem) }
            .map_err(|e| anyhow!("Failed to create UMEM: {e}"))?;

        let mut interface_cstr = String::from(interface_name);
        interface_cstr.push('\0');
        let interface_bytes = interface_cstr.as_bytes();
        let name = std::ffi::CStr::from_bytes_with_nul(interface_bytes)
            .map_err(|e| anyhow!("Invalid interface name: {e}"))?;

        let mut info = IfInfo::invalid();
        info.from_name(name)
            .map_err(|e| anyhow!("Failed to get interface info for {interface_name}: {e:?}"))?;
        info.set_queue(0);

        // Create socket with shared UMEM
        let socket = Socket::with_shared(&info, &umem)
            .map_err(|e| anyhow!("Failed to create socket: {e:?}"))?;

        let device_queue = umem
            .fq_cq(&socket)
            .map_err(|e| anyhow!("Failed to create device queue: {e:?}"))?;

        let socket_config = SocketConfig {
            rx_size: None, // No RX, we only transmit
            tx_size: NonZeroU32::new(TX_RING_SIZE),
            bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
        };

        // Create RX/TX rings
        let rxtx = umem
            .rx_tx(&socket, &socket_config)
            .map_err(|e| anyhow!("Failed to create RX/TX rings: {e:?}"))?;

        umem.bind(&rxtx)
            .map_err(|e| anyhow!("Failed to bind socket: {e:?}"))?;

        let tx_ring = rxtx
            .map_tx()
            .map_err(|e| anyhow!("Failed to map TX ring: {e:?}"))?;

        Ok(Self {
            umem,
            _socket: socket,
            tx_ring,
            device_queue,
            listeners,
        })
    }

    pub fn forward_packet(&mut self, packet_data: &ArrayVec<u8, PACKET_SIZE>) -> Result<()> {
        self.process_completions();

        let mut descriptors = Vec::new();

        for (idx, listener) in self.listeners.iter().enumerate() {
            let buf_idx = BufIdx((idx + 1) as u32);

            match self.prepare_packet(packet_data, listener, buf_idx) {
                Ok(desc) => {
                    descriptors.push(desc);
                }
                Err(e) => {
                    eprintln!("Failed to prepare packet for {listener}: {e}");
                }
            }
        }

        if !descriptors.is_empty() {
            let sent = {
                let mut writer = self.tx_ring.transmit(descriptors.len() as u32);
                let sent = writer.insert(descriptors.into_iter());
                writer.commit();
                sent
            };

            if self.tx_ring.needs_wakeup() {
                self.tx_ring.wake();
            }

            if sent < self.listeners.len() as u32 {
                eprintln!(
                    "Warning: Only sent {} out of {} packets",
                    sent,
                    self.listeners.len()
                );
            }
        }

        Ok(())
    }

    fn process_completions(&mut self) {
        let mut reader = self.device_queue.complete(TX_RING_SIZE);
        while reader.read().is_some() {}

        reader.release();
    }

    fn prepare_packet(
        &self,
        original_data: &[u8],
        listener: &SocketAddrV4,
        buf_idx: BufIdx,
    ) -> Result<XdpDesc> {
        let mut frame = self
            .umem
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
        new_eth_packet.set_destination(pnet::util::MacAddr::zero());

        let mut new_ipv4_packet = match new_eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => MutableIpv4Packet::new(new_eth_packet.payload_mut())
                .ok_or_else(|| anyhow!("invalid ipv4 packet"))?,
            ty => return Err(anyhow!("Unsupported EtherType {ty}")),
        };
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
}
