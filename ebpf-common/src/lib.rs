#![no_std]

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct XdpDispatcherConfig {
    pub num_progs_enabled: u8,
    pub chain_call_actions: [u32; 10],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for XdpDispatcherConfig {}
