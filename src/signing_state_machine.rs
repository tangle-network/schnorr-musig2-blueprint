use crate::signing::SigningError;
use gadget_sdk::keystore::TanglePairSigner;
use gadget_sdk::random::{rand, RngCore};
use gadget_sdk::subxt::ext::sp_runtime::app_crypto::ecdsa;
use k256::SecretKey;
use musig2::secp::{Point, Scalar};
use musig2::{
    CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecNonceSpices,
    SecondRound,
};
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use round_based::{Outgoing, SinkExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct SchnorrkelMuSigState {
    #[serde(skip)]
    pub secret_key: Option<SecretKey>,
    #[serde(skip)]
    pub signature: Option<CompactSignature>,
    pub public_key: Option<Vec<u8>>,
    received_nonces: BTreeMap<usize, PubNonce>,
    received_partial_sigs: BTreeMap<usize, PartialSignature>,
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum Msg {
    Round1Broadcast(Msg1),
    Round2Broadcast(Msg2),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg1 {
    pub sender: u16,
    pub receiver: Option<u16>,
    pub nonce: PubNonce,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg2 {
    pub sender: u16,
    pub receiver: Option<u16>,
    pub partial_sig: PartialSignature,
}

pub async fn schnorrkel_signing_protocol<M, T>(
    party: M,
    parties: &BTreeMap<u16, ecdsa::Public>,
    local_id: TanglePairSigner<ecdsa::Pair>,
    i: PartyIndex,
    n: u16,
    input_data_to_sign: T,
) -> Result<SchnorrkelMuSigState, SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
    T: AsRef<[u8]>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut signing_state = SchnorrkelMuSigState::default();
    let input_data_to_sign = input_data_to_sign.as_ref();

    // Extract secret key from local signer for additional entropy
    let secret_key_bytes = local_id.signer().seed();
    let secret_key = Scalar::from_slice(&secret_key_bytes)
        .map_err(|err| SigningError::KeySetupError(err.to_string()))?;

    let mut pk_points = vec![];

    for public_key in parties.values() {
        let pk_point = Point::from_slice(&public_key.0)
            .map_err(|err| SigningError::KeySetupError(err.to_string()))?;
        pk_points.push(pk_point);
    }

    let key_agg_context = KeyAggContext::new(pk_points)
        .map_err(|err| SigningError::KeySetupError(err.to_string()))?;

    // Generate secure nonce seed
    let mut nonce_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_seed);

    // Initialize first round
    let mut first_round = FirstRound::new(
        key_agg_context,
        nonce_seed,
        i as usize,
        SecNonceSpices::new()
            .with_seckey(secret_key)
            .with_message(&input_data_to_sign.to_vec()),
    )
    .map_err(|e| SigningError::MpcError(format!("Failed to create first round: {}", e)))?;

    // Broadcast our public nonce
    let my_msg = Msg1 {
        sender: i,
        receiver: None,
        nonce: first_round.our_public_nonce(),
    };

    let msg = Msg::Round1Broadcast(my_msg.clone());

    send_message::<M, Msg>(msg, &mut outgoings)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))?;

    // Receive nonces from other parties
    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<Msg1>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<Msg2>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let msgs = rounds
        .complete(round1)
        .await
        .map_err(|e| SigningError::MpcError(format!("Failed to complete round 1: {}", e)))?;

    for msg in msgs.into_vec_including_me(my_msg) {
        first_round
            .receive_nonce(msg.sender as usize, msg.nonce)
            .map_err(|e| SigningError::MpcError(format!("Failed to receive nonce: {}", e)))?;
    }

    // Finalize first round and start second round
    let mut second_round: SecondRound<&[u8]> = first_round
        .finalize(secret_key, input_data_to_sign)
        .map_err(|e| SigningError::MpcError(format!("Failed to finalize first round: {}", e)))?;

    // Broadcast our partial signature
    let my_msg2 = Msg2 {
        sender: i,
        receiver: None,
        partial_sig: second_round.our_signature(),
    };
    let msg = Msg::Round2Broadcast(my_msg2.clone());

    send_message::<M, Msg>(msg, &mut outgoings)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))?;

    // Receive partial signatures from other parties
    let msgs = rounds
        .complete(round2)
        .await
        .map_err(|e| SigningError::MpcError(format!("Failed to complete round 2: {}", e)))?;

    for msg in msgs.into_vec_including_me(my_msg2) {
        second_round
            .receive_signature(msg.sender as usize, msg.partial_sig)
            .map_err(|e| {
                SigningError::MpcError(format!("Failed to receive partial signature: {}", e))
            })?;
    }

    // Finalize the signing process
    signing_state.signature = Some(
        second_round
            .finalize()
            .map_err(|e| SigningError::MpcError(format!("Failed to finalize signing: {}", e)))?,
    );

    Ok(signing_state)
}

async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    tx.send(Outgoing::broadcast(msg))
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))
}
