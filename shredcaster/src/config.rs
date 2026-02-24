use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock},
};

use clap::Parser;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use notify::Watcher;
use serde::{Deserialize, Serialize};

const CONFIG_TOML: &str = "./config.toml";

pub enum MaybeSharedListeners {
    Static(Arc<[SocketAddr]>),
    Shared(Arc<RwLock<Arc<[SocketAddr]>>>),
}

impl MaybeSharedListeners {
    pub fn get(&self) -> Arc<[SocketAddr]> {
        match self {
            MaybeSharedListeners::Static(listeners) => listeners.clone(),
            MaybeSharedListeners::Shared(mutex) => mutex.read().unwrap().clone(),
        }
    }
}

#[derive(Parser, Serialize, Deserialize, Clone)]
pub struct Config {
    /// The TVU ports to monitor
    #[arg(short, long)]
    pub tvu_ports: Vec<u16>,
    /// The network interface to attach to
    #[arg(short, long)]
    pub iface: String,
    /// The egress interface to attach to (if different from ingress)
    #[arg(long)]
    pub egress_iface: Option<String>,
    /// A list of UDP listeners to forward packets to
    #[arg(short, long)]
    pub listeners: Vec<SocketAddr>,
    /// The port to use for forwarding packets
    #[arg(short, long, default_value_t = 9122)]
    pub forwarder_port: u16,
    /// Whether to watch turbine egress traffic (experimental)
    #[arg(short, long, default_value_t = false)]
    pub watch_egress: bool,
    /// Egress port to filter on, if known
    #[arg(short, long)]
    pub egress_port: Option<u16>,
    /// The CPU core to pin the TX thread to  
    /// IMPORTANT: This must not live on a CPU Heavy Core (e.g PoH core 0)  
    /// the default is 2 to ensure maximal compatibility
    #[arg(long, default_value_t = 2, verbatim_doc_comment)]
    pub tx_pinned_cpu_core: usize,
    /// Optional path to a PEM encoded TLS certificate for WebTransport
    /// enables webtransport server if set
    /// webtransport_private_key must also be set
    #[arg(long, verbatim_doc_comment)]
    pub webtransport_cert: Option<String>,
    /// Path to a PEM encoded TLS private key for WebTransport
    #[arg(long, verbatim_doc_comment)]
    pub webtransport_private_key: Option<String>,
    /// The auth token for WebTransport connections
    /// must be set if webtransport server is enabled
    #[arg(long, verbatim_doc_comment)]
    pub webtransport_auth_token: Option<String>,
    #[arg(long, default_value_t = 4433)]
    pub webtransport_port: u16,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Figment::new()
            .merge(Serialized::defaults(Self::parse()))
            .merge(Toml::file(CONFIG_TOML))
            .extract()
            .map_err(|e| e.into())
    }

    pub fn spawn_config_listener(
        &self,
    ) -> anyhow::Result<(Option<notify::RecommendedWatcher>, MaybeSharedListeners)> {
        let config_path = Path::new(CONFIG_TOML);
        if !config_path.exists() {
            return Ok((
                None,
                MaybeSharedListeners::Static(self.listeners.clone().into()),
            ));
        }

        let current = self.clone();
        let val = Arc::new(RwLock::new(self.listeners.clone().into()));
        let val_c = val.clone();
        let mut watcher =
            notify::recommended_watcher(move |ev: notify::Result<notify::Event>| match ev {
                Ok(ev) => {
                    if !ev.kind.is_modify() {
                        return;
                    }
                    let Ok(new_config): figment::Result<Self> = Figment::new()
                        .merge(Serialized::defaults(current.clone()))
                        .merge(Toml::file(CONFIG_TOML))
                        .extract()
                    else {
                        return;
                    };
                    println!(
                        "config was updated, updating listeners to: {:?}",
                        new_config.listeners
                    );
                    *val.write().unwrap() = new_config.listeners.into();
                }
                Err(e) => eprintln!("watch error: {e}"),
            })?;
        watcher.watch(config_path, notify::RecursiveMode::NonRecursive)?;

        Ok((Some(watcher), MaybeSharedListeners::Shared(val_c)))
    }
}
