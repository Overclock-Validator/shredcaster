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

use crate::common::{PACKET_BUF, PACKET_DATA_SIZE};

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
    let Some(&shred_egress_port) = SHRED_EGRESS_PORT.get(0) else {
        return Ok(TC_ACT_PIPE);
    };
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
    if udphdr.src_port() != shred_egress_port {
        return Ok(TC_ACT_PIPE);
    }
    let packet_data_len = udphdr.len() as usize - UdpHdr::LEN;
    if packet_data_len > PACKET_DATA_SIZE {
        return Ok(TC_ACT_PIPE);
    }
    offset += UdpHdr::LEN;

    let Some(mut event) = PACKET_BUF.reserve::<ArrayVec<u8, PACKET_DATA_SIZE>>(0) else {
        return Ok(TC_ACT_PIPE);
    };
    unsafe {
        event.write(ArrayVec::new());
        let packet_buf = event.assume_init_mut();
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
