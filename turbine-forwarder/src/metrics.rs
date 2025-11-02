use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::sleep,
    time::Duration,
};

use crossterm::{ExecutableCommand, cursor, terminal};

pub type SharedPacketCtr = Arc<PacketCtr>;

#[derive(Default)]
pub struct PacketCtr {
    ingress: AtomicUsize,
    egress: AtomicUsize,
}

impl PacketCtr {
    pub fn add(&self, egress_packets: usize, ingress_packets: usize) {
        self.egress.fetch_add(egress_packets, Ordering::SeqCst);
        self.ingress.fetch_add(ingress_packets, Ordering::SeqCst);
    }
}

pub fn start_packet_counter_print_loop(this: SharedPacketCtr) -> anyhow::Result<()> {
    let mut sto = io::stdout();
    while Arc::strong_count(&this) > 1 {
        let egress = this.egress.load(Ordering::SeqCst);
        let ingress = this.ingress.load(Ordering::SeqCst);
        sto.execute(cursor::MoveToColumn(0))?
            .execute(terminal::Clear(terminal::ClearType::CurrentLine))?;

        print!("Egress Packets: {egress} Ingress Packets: {ingress}");
        sto.flush()?;

        sleep(Duration::from_millis(300));
    }

    Ok(())
}
