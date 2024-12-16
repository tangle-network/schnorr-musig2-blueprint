use std::collections::BTreeMap;

use crate::context::SchnorrkelContext;
use gadget_sdk::keystore::BackendExt;
use gadget_sdk::{
    contexts::*,
    event_listener::tangle::{
        jobs::{services_post_processor, services_pre_processor},
        TangleEventListener,
    },
    job,
    network::round_based_compat::NetworkDeliveryWrapper,
    tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled,
    Error as GadgetError,
};
use sp_core::ecdsa::Public;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Context error: {0}")]
    ContextError(String),
    #[error("Key retrieval error: {0}")]
    KeySetupError(String),
    #[error("MPC error: {0}")]
    MpcError(String),
}

/// Configuration constants for the BLS signing process
const SIGNING_SALT: &str = "schnorrkel-signing";

impl From<SigningError> for GadgetError {
    fn from(err: SigningError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

#[job(
    id = 1,
    params(message),
    event_listener(
        listener = TangleEventListener<SchnorrkelContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Signs a message using the BLS protocol with a previously generated key
///
/// # Arguments
/// * `message` - The message to sign as a byte vector
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the signature as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to retrieve the key entry
/// - Signing process failed
pub async fn sign(message: Vec<u8>, context: SchnorrkelContext) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let call_id = context.call_id.expect("Should exist");

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, SIGNING_SALT);

    gadget_sdk::info!(
        "Starting Schnorrkel MuSig Signing for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let local_key = context.keystore()?.ecdsa_key()?;

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::signing_state_machine::schnorrkel_signing_protocol(
        party, &parties, local_key, i, n, &message,
    )
    .await?;

    gadget_sdk::info!(
        "Ending Schnorrkel MuSig Signing for party {i}, n={n}, eid={}",
        hex::encode(deterministic_hash)
    );

    let signature = output
        .signature
        .ok_or_else(|| SigningError::KeySetupError("Signature not found".to_string()))?;

    Ok(signature.serialize().to_vec())
}
