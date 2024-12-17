use crate::signing_state_machine::SchnorrMusig2State;
use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::contexts::MPCContext;
use gadget_sdk::network::NetworkMultiplexer;
use gadget_sdk::store::LocalDatabase;
use gadget_sdk::subxt_core::ext::sp_core::ecdsa;
use sdk::contexts::{KeystoreContext, ServicesContext, TangleClientContext};
use std::path::PathBuf;
use std::sync::Arc;

/// The network protocol version for the Schnorr service
const NETWORK_PROTOCOL: &str = "/schnorr/musig/1.0.0";

/// Schnorr Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext, MPCContext)]
pub struct SchnorrContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    #[call_id]
    pub call_id: Option<u64>,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub store: Arc<LocalDatabase<SchnorrMusig2State>>,
    pub identity: ecdsa::Pair,
}

// Core context management implementation
impl SchnorrContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: sdk::config::StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre::eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.ecdsa_key.clone();
        let gossip_handle = match sdk::network::setup::start_p2p_network(network_config) {
            Ok(handle) => handle,
            Err(err) => {
                gadget_sdk::error!("Failed to start network: {}", err.to_string());
                return Err(eyre::eyre!("Failed to start network: {err}"));
            }
        };

        let keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("schnorr_musig.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        Ok(Self {
            store,
            identity,
            call_id: None,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }
}
