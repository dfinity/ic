/* tag::catalog[]
Title:: Certificate orchestrator test

Goal:: Verify that the certificate orchestrator interface works.

Runbook:
. Set up an certificate orchestrator canister.
. Test that the certificate orchestrator API works.

Success:: The certificate orchestrator canister is installed and the API works.

Coverage:: The certificate orchestrator interface works as expected.

end::catalog[] */

use crate::{
    custom_domains_integration::setup::{
        create_bn_http_client, get_registration_status, setup_asset_canister, setup_dns_records,
        submit_registration_request, RegistrationRequestState,
    },
    driver::test_env::TestEnv,
    util::block_on,
};

use slog::info;

use std::time::Duration;

use anyhow::Error;

pub fn test_end_to_end_registration(env: TestEnv) {
    let logger = env.logger();

    let domain_name = "custom-domain.com";

    // install asset canister
    block_on(async {
        let asset_canister_id = setup_asset_canister(env.clone(), vec![domain_name]).await?;

        // DNS configuration
        setup_dns_records(env.clone(), domain_name, asset_canister_id).await?;

        // create an HTTP client
        let bn_http_client = create_bn_http_client(env);

        // submit a registration request
        let registration_response =
            submit_registration_request(bn_http_client.clone(), domain_name).await?;

        if let RegistrationRequestState::Accepted(registration_id) = registration_response {
            // check the registration status
            loop {
                let registration_status =
                    get_registration_status(bn_http_client.clone(), registration_id.as_str())
                        .await?;

                if registration_status == "Available" {
                    info!(logger, "Registration has been successfully processed");
                    break;
                }

                info!(
                    logger,
                    "Registration is still in progress: {registration_status}"
                );
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
        } else {
            info!(logger, "Failed to submit the registration request")
        }

        Ok::<(), Error>(())
    })
    .expect("failed to run test");
}

pub fn test_nop_2(_env: TestEnv) {
    block_on(async {
        println!("test 2");
        Ok::<(), Error>(())
    })
    .expect("failed to run test");
}

pub fn test_nop_3(_env: TestEnv) {
    block_on(async {
        println!("test 3");
        Ok::<(), Error>(())
    })
    .expect("failed to run test");
}
