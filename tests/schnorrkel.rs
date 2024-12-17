use schnorr_musig2_blueprint::signing::SIGN_JOB_ID;

const N: usize = 3;
const T: usize = 2;

use blueprint_test_utils::tangle::NodeConfig;
use blueprint_test_utils::test_ext::new_test_ext_blueprint_manager;
use blueprint_test_utils::{
    run_test_blueprint_manager, setup_log, submit_job, wait_for_completion_of_tangle_job,
    BoundedVec, InputValue, Job,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() {
    setup_log();
    gadget_sdk::info!("Running Schnorr multisig blueprint test");
    let tmp_dir = blueprint_test_utils::tempfile::TempDir::new().unwrap();
    let tmp_dir_path = tmp_dir.path().to_string_lossy().into_owned();
    let node_config = NodeConfig::new(false);

    new_test_ext_blueprint_manager::<N, 1, String, _, _>(
        tmp_dir_path,
        run_test_blueprint_manager,
        node_config,
    )
    .await
    .execute_with_async(|client, handles, blueprint, _| async move {
        let keypair = handles[0].sr25519_id().clone();
        let service = &blueprint.services[0];
        let service_id = service.id;
        gadget_sdk::info!(
            "Submitting SIGNING job {} with service ID {service_id}",
            SIGN_JOB_ID
        );

        let job_args = vec![
            InputValue::List(BoundedVec(vec![
                InputValue::Uint8(1),
                InputValue::Uint8(2),
                InputValue::Uint8(3),
            ])),
        ];

        let job = submit_job(
            client,
            &keypair,
            service_id,
            Job::from(SIGN_JOB_ID),
            job_args,
            0,
        )
        .await
        .expect("Failed to submit job");

        let signing_call_id = job.call_id;
        gadget_sdk::info!(
            "Submitted SIGNING job {SIGN_JOB_ID} with service ID {service_id} has call id {signing_call_id}",
        );

        let _job_results = wait_for_completion_of_tangle_job(client, service_id, signing_call_id, T)
            .await
            .expect("Failed to wait for job completion");
    })
    .await
}
