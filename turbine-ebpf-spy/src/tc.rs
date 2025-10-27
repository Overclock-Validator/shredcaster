use arrayvec::ArrayVec;
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    check_bounds_signed,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{PACKET_BUF, PACKET_DATA_SIZE, PACKET_SIZE};

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

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    if ipv4hdr.proto != IpProto::Udp {
        return Ok(TC_ACT_PIPE);
    }

    let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    if udphdr.src_port() != shred_egress_port {
        return Ok(TC_ACT_PIPE);
    }
    let packet_data_len = udphdr.len() as usize - UdpHdr::LEN;
    if packet_data_len > PACKET_DATA_SIZE {
        return Ok(TC_ACT_PIPE);
    }

    let Some(mut event) = PACKET_BUF.reserve::<ArrayVec<u8, PACKET_SIZE>>(0) else {
        return Ok(TC_ACT_PIPE);
    };
    unsafe {
        event.write(ArrayVec::new());
        let packet_buf = event.assume_init_mut();
        let len = ctx.data_end() - ctx.data();
        if !check_bounds_signed(len as i64, 1, PACKET_SIZE as i64) {
            event.discard(0);
            return Ok(TC_ACT_PIPE);
        }
        packet_buf.set_len(len);

        match ctx.load_bytes(0, &mut packet_buf[..len]) {
            Ok(l) if l == len => {
                event.submit(0);
            }
            _ => event.discard(0),
        }
    }

    Ok(TC_ACT_PIPE)
}
