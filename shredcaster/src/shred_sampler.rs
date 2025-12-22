use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::Serialize;
use solana_ledger::shred::layout;
use tokio::sync::broadcast;
use wtransport::{endpoint::IncomingSession, error::StreamWriteError};

use crate::SharedPacketData;

pub trait ShredSamplerTx {
    /// queue a shred for sampling
    /// Returning None if shred is invalid
    fn insert_shred(&mut self, shred: &SharedPacketData) -> Option<()>;

    fn flush(&mut self);
}

pub struct MaxShredSamplerTx {
    tx: crossbeam_channel::Sender<(u64, Vec<SharedPacketData>)>,
    max_slot: u64,
    slot_shreds: Vec<SharedPacketData>,
}

impl ShredSamplerTx for MaxShredSamplerTx {
    fn insert_shred(&mut self, shred: &SharedPacketData) -> Option<()> {
        let slot = layout::get_slot(&shred.0)?;
        if slot > self.max_slot {
            self.max_slot = slot;
            self.slot_shreds.clear();
            self.slot_shreds.push(shred.clone());
        } else if slot == self.max_slot {
            self.slot_shreds.push(shred.clone());
        }
        Some(())
    }

    fn flush(&mut self) {
        _ = self
            .tx
            .try_send((self.max_slot, std::mem::take(&mut self.slot_shreds)));
    }
}

pub struct NoOpShredSamplerTx;

impl ShredSamplerTx for NoOpShredSamplerTx {
    fn insert_shred(&mut self, _shred: &SharedPacketData) -> Option<()> {
        Some(())
    }

    fn flush(&mut self) {}
}

#[derive(Serialize)]
pub struct SlotData<'a> {
    pub slot: u64,
    // merkle root -> signature
    pub signature_data: HashMap<[u8; 32], HashSet<&'a [u8]>>,
}

async fn handle_session_request(
    auth_token: &str,
    session: IncomingSession,
    broadcast: broadcast::Sender<Arc<[u8]>>,
) -> anyhow::Result<()> {
    let req = session.await?;
    if !req
        .path()
        .strip_prefix("/shred_sample?token=")
        .map(|s| s == auth_token)
        .unwrap_or_default()
    {
        req.forbidden().await;
        return Ok(());
    };

    let conn = req.accept().await?;
    let mut tx_stream = conn.open_uni().await?.await?;

    let mut shred_rx = broadcast.subscribe();

    while let Ok(serialized_msg) = shred_rx.recv().await {
        match tx_stream.write_all(&serialized_msg).await {
            Err(
                StreamWriteError::Closed
                | StreamWriteError::NotConnected
                | StreamWriteError::Stopped(_),
            ) => {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
    }
    _ = tx_stream.finish().await;

    Ok(())
}

async fn accept_wt_connections(
    auth_token: Arc<str>,
    endpoint: wtransport::Endpoint<wtransport::endpoint::endpoint_side::Server>,
    broadcast: broadcast::Sender<Arc<[u8]>>,
) -> ! {
    loop {
        let incoming_session = endpoint.accept().await;
        let auth_token = auth_token.clone();
        let broadcast = broadcast.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_session_request(&auth_token, incoming_session, broadcast).await {
                eprintln!("error handling wt shred sampler connection: {e}");
            }
        });
    }
}

fn process_shreds_for_sampling(
    rx: crossbeam_channel::Receiver<(u64, Vec<SharedPacketData>)>,
    broadcast: broadcast::Sender<Arc<[u8]>>,
) {
    while let Ok((slot, shreds)) = rx.recv() {
        let mut signature_data: HashMap<_, HashSet<_>> = HashMap::new();
        for shred in shreds.iter() {
            let Some(merkle_root) = layout::get_merkle_root(&shred.0) else {
                continue;
            };
            let Some(sig) = shred.0.get(..64) else {
                continue;
            };
            signature_data
                .entry(merkle_root.to_bytes())
                .or_default()
                .insert(sig);
        }
        let slot_data = SlotData {
            slot,
            signature_data,
        };
        let serialized = sonic_rs::to_vec(&slot_data).unwrap();
        _ = broadcast.send(Arc::from(serialized));
    }
}

pub fn spawn_webtransport_shred_sampler(
    auth_token: String,
    config: wtransport::ServerConfig,
) -> anyhow::Result<MaxShredSamplerTx> {
    let (tx, rx) = crossbeam_channel::unbounded();
    let endpoint = wtransport::Endpoint::server(config)?;
    let (client_broadcast, _) = broadcast::channel(100);

    let sampler_tx = MaxShredSamplerTx {
        tx,
        max_slot: 0,
        slot_shreds: Vec::new(),
    };

    let auth_token = Arc::from(auth_token);
    tokio::spawn(accept_wt_connections(
        auth_token,
        endpoint,
        client_broadcast.clone(),
    ));
    std::thread::spawn(move || process_shreds_for_sampling(rx, client_broadcast));

    Ok(sampler_tx)
}
