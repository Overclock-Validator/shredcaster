#![no_std]
#![no_main]

use core::mem;

use arrayvec::ArrayVec;
use aya_ebpf::{
    bindings::xdp_action::XDP_PASS,
    helpers::generated::bpf_xdp_load_bytes,
    macros::{map, xdp},
    maps::{Array, RingBuf},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

const PACKET_DATA_SIZE: usize = 1232;

#[map]
static TURBINE_PORT: Array<u16> = Array::with_max_entries(1, 0);

const PACKET_BUF_SIZE: usize = mem::size_of::<ArrayVec<u8, PACKET_DATA_SIZE>>();

// Store a max of 8192 packets
#[map]
static PACKET_BUF: RingBuf = RingBuf::with_byte_size(8192 * PACKET_BUF_SIZE as u32, 0);

#[xdp]
pub fn xdp_turbine_probe(ctx: XdpContext) -> u32 {
    match try_xdp_turbine_probe(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_PASS,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

fn try_xdp_turbine_probe(ctx: XdpContext) -> Result<u32, ()> {
    let Some(&turbine_port) = TURBINE_PORT.get(0) else {
        return Ok(XDP_PASS);
    };

    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let mut offset = mem::size_of::<EthHdr>();

    match unsafe { (*eth_hdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, offset)? };
            if unsafe { (*hdr).proto } != IpProto::Udp {
                return Ok(XDP_PASS);
            }
            offset += mem::size_of::<Ipv4Hdr>();
        }
        Ok(EtherType::Ipv6) => {
            let hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, offset)? };
            if unsafe { (*hdr).next_hdr } != IpProto::Udp {
                return Ok(XDP_PASS);
            }
            offset += mem::size_of::<Ipv6Hdr>();
        }
        _ => return Ok(XDP_PASS),
    }

    let udp_hdr: *const UdpHdr = unsafe { ptr_at(&ctx, offset)? };
    let dst_port = unsafe { (*udp_hdr).dst_port() };
    if dst_port != turbine_port {
        return Ok(XDP_PASS);
    }

    let packet_data_len = unsafe { (*udp_hdr).len() } as usize - mem::size_of::<UdpHdr>();
    if packet_data_len > PACKET_DATA_SIZE {
        return Ok(XDP_PASS);
    }
    offset += mem::size_of::<UdpHdr>();

    let Some(mut event) = PACKET_BUF.reserve::<ArrayVec<u8, PACKET_DATA_SIZE>>(0) else {
        return Ok(XDP_PASS);
    };
    unsafe {
        event.write(ArrayVec::new());
        let packet_buf = event.assume_init_mut();
        if offset > packet_data_len {
            event.discard(0);
            return Ok(XDP_PASS);
        }

        match bpf_xdp_load_bytes(
            ctx.ctx,
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

    Ok(XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
