use arrayvec::ArrayVec;
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::generated::bpf_skb_load_bytes,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{PACKET_BUF, PACKET_DATA_SIZE, PacketBuf};

#[map]
static SHRED_EGRESS_PORT: Array<u16> = Array::with_max_entries(1, 0);

#[classifier]
pub fn tc_egress_probe(ctx: TcContext) -> i32 {
    match try_tc_egress_probe(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_egress_probe(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type() {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let mut offset = EthHdr::LEN;

    let ipv4hdr: Ipv4Hdr = ctx.load(offset).map_err(|_| ())?;
    offset += Ipv4Hdr::LEN;

    if ipv4hdr.proto != IpProto::Udp {
        return Ok(TC_ACT_PIPE);
    }

    let udphdr: UdpHdr = ctx.load(offset).map_err(|_| ())?;
    let shred_egress_port = SHRED_EGRESS_PORT.get(0);
    if shred_egress_port
        .map(|p| *p != udphdr.src_port())
        .unwrap_or_default()
    {
        return Ok(TC_ACT_PIPE);
    }
    let packet_data_len = udphdr.len() as usize - UdpHdr::LEN;
    if packet_data_len > PACKET_DATA_SIZE {
        return Ok(TC_ACT_PIPE);
    }
    offset += UdpHdr::LEN;

    // based on https://github.com/anza-xyz/agave/blob/v3.0.9/ledger/src/shred/wire.rs#L76
    let shred_variant: u8 = ctx.load(offset + 64).map_err(|_| ())?;
    let payload_size = match shred_variant & 0xF0 {
        // merkle code shred
        0x40 | 0x60 | 0x70 => 1228usize,
        // merkle data shred
        0x80 | 0x90 | 0xb0 => 1203,
        _ => return Ok(TC_ACT_PIPE),
    };
    // if this is not equal
    // the packet is not valid
    // or the packet is a repair response
    if packet_data_len != payload_size {
        return Ok(TC_ACT_PIPE);
    }

    let Some(mut event) = PACKET_BUF.reserve::<PacketBuf>(0) else {
        return Ok(TC_ACT_PIPE);
    };
    unsafe {
        event.write((ArrayVec::new(), true));
        let (packet_buf, _) = event.assume_init_mut();
        if offset > packet_data_len {
            event.discard(0);
            return Ok(TC_ACT_PIPE);
        }
        match bpf_skb_load_bytes(
            ctx.skb.skb.cast(),
            offset as u32,
            packet_buf.as_mut_ptr() as *mut _,
            packet_data_len as u32,
        ) {
            0 => {
                packet_buf.set_len(packet_data_len);
                event.submit(0);
            }
            _ => event.discard(0),
        }
    }

    Ok(TC_ACT_PIPE)
}
