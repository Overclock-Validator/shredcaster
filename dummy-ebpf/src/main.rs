#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};

#[xdp]
pub fn dummy_xdp_probe(_ctx: XdpContext) -> u32 {
    XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
