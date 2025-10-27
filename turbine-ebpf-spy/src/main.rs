#![no_std]
#![no_main]

mod common;
mod tc;
mod xdp;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
