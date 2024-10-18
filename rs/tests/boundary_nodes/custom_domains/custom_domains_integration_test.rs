/* tag::catalog[]
Title:: Custom domains end-to-end test

Goal:: Verify that custom domains is working end-to-end (certificate orchestrator, certificate issuer)

Runbook:
. Set up the certificate orhcestrator on the IC.
. Start a UVM exposing a nameserver, a mock Cloudflare API, a mock certificate authority
. Start a boundary node running the certificate issuer
. Register some custom domains

Success:: All custom domain services on the boundary node come up healthy and process the registration requests successfully

Coverage:: End-to-end registration processing

end::catalog[] */

mod setup;

use ic_system_test_driver::{
    driver::{boundary_node::BoundaryNodeVm, group::SystemTestGroup, test_env::TestEnv},
    retry_with_msg_async, systest,
    util::block_on,
};
use setup::{
    access_domain, create_bn_http_client, get_registration_status, get_service_errors,
    remove_dns_records, remove_registration, setup, setup_asset_canister, setup_dns_records,
    submit_registration_request, update_dns_records, update_registration, GetRequestState,
    RegistrationRequestState, RemoveRequestState, UpdateRequestState, BOUNDARY_NODE_VM_ID,
};

use slog::info;

use std::time::Duration;

use anyhow::{bail, Error, Result};

pub const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);

// Goal: Process a single registration
//
// Runbook:
// * setup the asset canister with the `.well-known/ic-domains` file
// * create all the necessary DNS records (CNAME, TXT)
// * submit the registration request
// * wait for the request to transition through all phases and eventually become available
// * submit the same registration request again and make sure it returns the same id
// * update the DNS records and update the custom domain mapping
pub fn test_end_to_end_registration(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_VM_ID)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let domain_name = "custom-domain.com";
    let all_domain_names = vec![domain_name];

    // install asset canister
    block_on(async {
        let asset_canister_id = setup_asset_canister(env.clone(), vec![domain_name], Some("canister1")).await?;

        // DNS configuration
        setup_dns_records(env.clone(), domain_name, asset_canister_id).await?;

        // create an HTTP client

        let bn_http_client = create_bn_http_client(env.clone(), all_domain_names);

        // submit a registration request
        let registration_response =
            submit_registration_request(bn_http_client.clone(), domain_name).await?;

        // obtain the ID of the registration request
        let registration_id = match registration_response {
            RegistrationRequestState::Accepted(registration_id) => registration_id,
            RegistrationRequestState::Rejected(issue) => panic!("Failed to submit the registration request: {issue}"),
        };

        // check the registration status
        loop {
            if let GetRequestState::Accepted(registration_status) =
                get_registration_status(bn_http_client.clone(), registration_id.as_str())
                    .await? {
                if registration_status == "Available" {
                    info!(logger, "Registration has been successfully processed");
                    break;
                }
                info!(
                    logger,
                    "Registration is still in progress: {registration_status}"
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
            } else {
                panic!("Could not retrieve the registration status")
            }
        }

        // check that the custom domain is being served by the BN by checking the content of the canister
        retry_with_msg_async!(
            "check updated domain",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let content = match access_domain(bn_http_client.clone(), domain_name).await {
                    Ok(x) => x,
                    Err(x) => bail!("Custom domain is not ready yet: {x}"),
                };

                if content != "canister1" {
                    bail!("Custom domain is not pointing to the right canister: expected 'canister1', got '{}'", content);
                }
                Ok(())
            }
        )
        .await
        .expect("The boundary node failed to configure the custom domain");

        // need to wait a second to prevent being rate-limited
        tokio::time::sleep(Duration::from_secs(1)).await;

        // submit the same registration request again
        let registration_response = submit_registration_request(bn_http_client.clone(), domain_name).await?;

        // obtain the ID of the registration request
        let duplicate_registration_id = match registration_response {
            RegistrationRequestState::Accepted(registration_id) => registration_id,
            RegistrationRequestState::Rejected(issue) => panic!("Failed to submit the registration request: {issue}"),
        };

        // make sure we get the same registration request id instead of submitting a new one
        assert_eq!(
            registration_id,
            duplicate_registration_id,
            "The request IDs for the same custom domain differ, while they should be the same: {registration_id} vs. {duplicate_registration_id}"
        );

        // create a new asset canister
        let new_asset_canister_id = setup_asset_canister(env.clone(), vec![domain_name], Some("canister2")).await?;

        // update the DNS records
        update_dns_records(env.clone(), domain_name, new_asset_canister_id).await?;

        // submit an update request
        retry_with_msg_async!(
            "update the canister of the custom domain",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let update_response = update_registration(bn_http_client.clone(), registration_id.as_str()).await?;

                // check if the update request was accepted
                match update_response {
                    UpdateRequestState::Accepted => Ok(()),
                    UpdateRequestState::Rejected(reason) => bail!("Failed to update the custom domain: {reason}"),
                }
            }
        )
        .await
        .expect("Failed to submit the update request");

        // check that the custom domain is being served by the BN by checking the content of the canister
        retry_with_msg_async!(
            "check updated domain",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let content = match access_domain(bn_http_client.clone(), domain_name).await {
                    Ok(x) => x,
                    Err(x) => bail!("Failed to fetch the content of the canister: {x}"),
                };

                if content != "canister2" {
                    bail!("Custom domain is not pointing to the right canister: expected 'canister2', got '{}'", content);
                }
                Ok(())
            }
        )
        .await
        .expect("Failed to update the domain to canister mapping");

        info!(
            logger,
            "Custom domain has been successfully updated"
        );

        // remove the DNS records of the custom domain
        remove_dns_records(env.clone(), domain_name).await?;

        // request to delete the custom domain
        retry_with_msg_async!(
            "remove custom domain",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let remove_response = remove_registration(bn_http_client.clone(), registration_id.as_str()).await?;
                // check if the removal request was accepted
                match remove_response {
                    RemoveRequestState::Accepted => Ok(()),
                    RemoveRequestState::Rejected(reason) => bail!("Couldn't process the removal request: {reason}"),
                }
            }
        )
        .await
        .expect("Failed to remove the custom domain");

        // make sure the domain has been removed
        retry_with_msg_async!(
            "check custom domain status",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let registration_status = get_registration_status(bn_http_client.clone(), registration_id.as_str()).await?;
                match registration_status {
                    GetRequestState::Accepted(_) => bail!("Failed to delete the custom domain: it still exists"),
                    GetRequestState::Rejected(reason) if reason == "not found" =>  Ok(()),
                    GetRequestState::Rejected(reason) => bail!("Failed to delete the custom domain: {reason}"),
                }
            }
        )
        .await
        .expect("Failed to check that the custom domain has been removed");

        info!(
            logger,
            "Custom domain has been successfully removed"
        );

        // check that there are no issues with the issuer (failed certification)
        assert_eq!(
            get_service_errors(&boundary_node, "certificate-issuer"),
            "-- No entries --",
            "There were errors in the issuer"
        );

        Ok::<(), Error>(())
    })
    .expect("failed to run test");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_end_to_end_registration))
        .execute_from_args()
}
