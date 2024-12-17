use color_eyre::Result;
use gadget_sdk::info;
use gadget_sdk::runners::tangle::TangleConfig;
use gadget_sdk::runners::BlueprintRunner;
use schnorr_musig2_blueprint::context::SchnorrContext;
use sp_core::Pair;

#[gadget_sdk::main(env)]
async fn main() -> Result<()> {
    let context = SchnorrContext::new(env.clone())?;

    info!(
        "~~~ Executing the Schnorr MultiSig Blueprint for {} ~~~",
        hex::encode(context.identity.public().as_ref())
    );

    let tangle_config = TangleConfig::default();
    let signing =
        schnorr_musig2_blueprint::signing::SignEventHandler::new(&env, context.clone())
            .await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(signing)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}
