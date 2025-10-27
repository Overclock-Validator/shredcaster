use core::mem;

use arrayvec::ArrayVec;
use aya_ebpf::{macros::map, maps::RingBuf};

pub const PACKET_DATA_SIZE: usize = 1232;
pub const PACKET_SIZE: usize = 1280;

pub const PACKET_BUF_SIZE: usize = mem::size_of::<ArrayVec<u8, PACKET_SIZE>>();

// Store a max of 16384 packets
#[map]
pub static PACKET_BUF: RingBuf = RingBuf::with_byte_size(8192 * PACKET_BUF_SIZE as u32, 0);
