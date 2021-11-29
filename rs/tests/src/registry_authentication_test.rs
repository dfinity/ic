/* tag::catalog[]
Title:: A node can authenticate registry queries from the IC

Goal:: A node can query the Registry and verify the authenticity of
the response, based on the root of trust of the IC.

Runbook::
. Deploy the registry canister.
. Execute an update() call that adds a key value pair.
. Execute query() call against the registry canister.
. Verify correctness of response.
. Make one NNS node return something incorrect.
. Execute query() against it.
. Ensure verification of response fails.


end::catalog[] */
use crate::util::{block_on, get_random_root_node_endpoint, runtime_from_url};
use fondue::{self, log::info};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response,
};
use ic_crypto::threshold_sig_public_key_from_der;
use ic_fondue::{
    ic_manager::IcHandle,
    internet_computer::{InternetComputer, Subnet},
};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_universal_canister,
};
use ic_nns_test_utils::{
    itest_helpers::install_registry_canister, registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_registry_common::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_registry_transport::upsert;
use ic_types::RegistryVersion;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use std::convert::Infallible;
use std::net::SocketAddr;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
}

pub fn test(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let root_subnet_endpoint = get_random_root_node_endpoint(&handle, &mut rng);
    block_on(root_subnet_endpoint.assert_ready(ctx));

    let pk_bytes = handle
        .ic_prep_working_dir
        .as_ref()
        .unwrap()
        .root_public_key()
        .expect("failed to read threshold sig PK bytes");
    let pk = threshold_sig_public_key_from_der(&pk_bytes[..])
        .expect("failed to decode threshold sig PK");

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Describes a proxy server that replaces all occurrences of "Good" with "Evil".
    let make_mitm = make_service_fn({
        let root_url = root_subnet_endpoint.url.clone();
        move |_conn| {
            let root_url = root_url.clone();
            async move {
                Ok::<_, Infallible>(service_fn({
                    let root_url = root_url.clone();
                    move |mut req: Request<Body>| {
                        let root_url = root_url.clone();
                        async move {
                            let client = hyper::client::Client::builder()
                                .http2_only(true)
                                .build_http();

                            let mut target_url = root_url.clone();
                            target_url.set_path(req.uri().path());
                            *req.uri_mut() = target_url.to_string().parse::<hyper::Uri>().unwrap();
                            let response = client.request(req).await?;
                            let (parts, body) = response.into_parts();
                            let mut bytes = hyper::body::to_bytes(body).await?.to_vec();

                            if bytes.len() < 4 {
                                return Ok::<_, hyper::Error>(Response::from_parts(
                                    parts,
                                    Body::from(bytes),
                                ));
                            }

                            for i in 0..bytes.len() - 3 {
                                if &bytes[i..i + 4] == b"Good" {
                                    bytes[i..i + 4].copy_from_slice(b"Evil");
                                }
                            }
                            Ok::<_, hyper::Error>(Response::from_parts(parts, Body::from(bytes)))
                        }
                    }
                }))
            }
        }
    });

    rt.block_on(async {
        let proxy_server =
            hyper::server::Server::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).serve(make_mitm);
        info!(
            ctx.logger,
            "Started a MITM proxy on {}",
            proxy_server.local_addr()
        );
        let proxy_url = url::Url::parse(&format!("http://{}", proxy_server.local_addr())).unwrap();

        tokio::runtime::Handle::current().spawn(async move {
            proxy_server.await.ok();
        });

        let runtime = runtime_from_url(root_subnet_endpoint.url.clone());

        info!(ctx.logger, "creating a new registry canister...");
        let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
        info!(ctx.logger, "installing registry canister...");
        let registry_init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            // Populate registry with some data
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![upsert("IC", "Good")],
                preconditions: vec![],
            })
            .build();
        install_registry_canister(&mut canister, registry_init_payload).await;
        let client = RegistryCanister::new(vec![root_subnet_endpoint.url.clone()]);

        info!(ctx.logger, "validating registry contents...");
        // Check that the registry indeed contains the data
        let value = client
            .get_value(b"IC".to_vec(), None)
            .await
            .expect("failed to get value");

        assert_eq!(value, (b"Good".to_vec(), 2));

        info!(ctx.logger, "fetching certified deltas...");
        // Check that deltas pass verification
        let (changes, version, time_v1) = client.get_certified_changes_since(1, &pk).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(version, RegistryVersion::new(2));

        // Install the universal canister in place of the governance canister so
        // it can impersonate it.
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &canister,
                "atomic_mutate",
                encode_or_panic(&RegistryAtomicMutateRequest {
                    mutations: vec![upsert("Proprietory Clouds", "Less Good")],
                    preconditions: vec![]
                })
            )
            .await,
            "failed to apply registry mutation"
        );
        // Check that the certificate time progresses
        let (changes, version, time_v2) = client.get_certified_changes_since(2, &pk).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(version, RegistryVersion::new(3));
        assert!(
            time_v2 > time_v1,
            "Expected certification time to advance, got the same time {}",
            time_v1
        );

        // MITM case
        let client = RegistryCanister::new(vec![proxy_url]);
        let value = client
            .get_value(b"IC".to_vec(), None)
            .await
            .expect("failed to get value");
        // Make sure the uncertified API believes Eve's data.
        assert_eq!(value, (b"Evil".to_vec(), 2));

        // But you can't fool the certified API!
        let result = client.get_certified_changes_since(0, &pk).await;
        assert!(
            result.is_err(),
            "Expected get_certified_changes_since() to fail, got {:?}",
            result
        );
        assert!(
            format!("{:?}", result).contains("CertifiedDataMismatch"),
            "Expected the result to contain signature verification error, got {:?}",
            result
        );
    });
}
