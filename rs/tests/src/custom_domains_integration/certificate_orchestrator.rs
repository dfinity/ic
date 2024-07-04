/* tag::catalog[]
Title:: Custom domains end-to-end test

Goal:: Verify that custom domains is working end-to-end (certificate orchestrator, certificate issuer, certificate syncer)

Runbook:
. Set up the certificate orhcestrator on the IC.
. Start a UVM exposing a nameserver, a mock Cloudflare API, a mock certificate authority
. Start a boundary node running the certificate issuer and syncer
. Register some custom domains

Success:: All custom domain services on the boundary node come up healthy and process the registration requests successfully

Coverage:: End-to-end registration processing

end::catalog[] */

use crate::custom_domains_integration::setup::{
    access_domain, create_bn_http_client, get_certificate_syncer_state, get_registration_status,
    get_service_errors, remove_dns_records, remove_registration, setup_asset_canister,
    setup_dns_records, submit_registration_request, update_dns_records, update_registration,
    GetRequestState, RegistrationRequestState, RemoveRequestState, UpdateRequestState,
    BOUNDARY_NODE_VM_ID,
};
use ic_system_test_driver::{
    driver::boundary_node::BoundaryNodeVm, driver::test_env::TestEnv, util::block_on,
};

use slog::info;

use std::time::Duration;

use anyhow::Error;

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

        // wait for the certificate syncer to update the nginx config
        tokio::time::sleep(Duration::from_secs(2)).await;

        // check that the custom domain is being served by the BN by checking the content of the canister
        assert_eq!(
            access_domain(bn_http_client.clone(), domain_name).await?,
            "canister1",
            "Site content of the custom domain is not correct"
        );

        // check that the syncer sees the custom domain and maps it to the right canister
        assert_eq!(
            get_certificate_syncer_state(&boundary_node, domain_name),
            asset_canister_id.to_string(),
            "Certificate syncer does not know about the custom domain or maps it to the wrong canister"
        );

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

        // wait for DNS changes to propagate
        tokio::time::sleep(Duration::from_secs(1)).await;

        // submit an update request
        let update_response = update_registration(bn_http_client.clone(), registration_id.as_str()).await?;

        // check if the update request was accepted
        match update_response {
            UpdateRequestState::Accepted => {},
            UpdateRequestState::Rejected(reason) => panic!("Failed to update the custom domain: {reason}"),
        };

        // wait for the certificate syncer to update the nginx config
        tokio::time::sleep(Duration::from_secs(2)).await;

        // check that the custom domain is being served by the BN by checking the content of the canister
        assert_eq!(
            access_domain(bn_http_client.clone(), domain_name).await?,
            "canister2",
            "Site content of the custom domain is not correct"
        );

        // check that the syncer sees the custom domain and maps it to the right canister
        assert_eq!(
            get_certificate_syncer_state(&boundary_node, domain_name),
            new_asset_canister_id.to_string(),
            "Certificate syncer does not know about the custom domain or maps it to the wrong canister"
        );

        info!(
            logger,
            "Custom domain has been successfully updated"
        );

        // remove the DNS records of the custom domain
        remove_dns_records(env.clone(), domain_name).await?;

        // wait for DNS changes to propagate
        tokio::time::sleep(Duration::from_secs(1)).await;

        // request to delete the custom domain
        let remove_response = remove_registration(bn_http_client.clone(), registration_id.as_str()).await?;

        // check if the removal request was accepted
        match remove_response {
            RemoveRequestState::Accepted => {},
            RemoveRequestState::Rejected(reason) => panic!("Failed to remove the custom domain: {reason}"),
        };

        // need to wait a second to prevent being rate-limited
        tokio::time::sleep(Duration::from_secs(1)).await;

        // make sure the domain has been removed
        let registration_status = get_registration_status(bn_http_client.clone(), registration_id.as_str()).await?;
        match registration_status {
            GetRequestState::Accepted(_) => panic!("Failed to delete the custom domain: it still exists"),
            GetRequestState::Rejected(reason) if reason == "not found" =>  {},
            GetRequestState::Rejected(reason) => panic!("Failed to delete the custom domain: {reason}"),
        };

        // make sure the certificate syncer removed the domain
        assert_eq!(
            get_certificate_syncer_state(&boundary_node, domain_name),
            "",
            "Certificate syncer still has an entry for the deleted custom domain"
        );

        info!(
            logger,
            "Custom domain has been successfully removed"
        );

        // check that there are no issues with the syncer (failed certification)
        assert_eq!(
            get_service_errors(&boundary_node, "certificate-syncer"),
            "-- No entries --",
            "There were errors in the syncer"
        );

        assert_eq!(
            get_service_errors(&boundary_node, "certificate-issuer"),
            "-- No entries --",
            "There were errors in the issuer"
        );

        Ok::<(), Error>(())
    })
    .expect("failed to run test");
}
