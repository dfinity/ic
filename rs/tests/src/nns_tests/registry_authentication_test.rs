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
use axum::{
    body::Body,
    extract::{Request, State},
    routing::any,
};
use ic_async_utils::axum::BodyDataStream;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_from_der;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_universal_canister,
};
use ic_nns_test_utils::{
    itest_helpers::install_registry_canister, registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_registry_transport::upsert;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::{HasIcPrepDir, TestEnv};
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::util::{block_on, runtime_from_url};
use ic_types::RegistryVersion;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use reqwest::header::HeaderMap;
use slog::info;
use std::net::SocketAddr;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let root_node = env.get_first_healthy_nns_node_snapshot();
    let pk_bytes = env
        .prep_dir("")
        .as_ref()
        .unwrap()
        .root_public_key()
        .expect("failed to read threshold sig PK bytes");
    let pk = threshold_sig_public_key_from_der(&pk_bytes[..])
        .expect("failed to decode threshold sig PK");

    let mitm = any(mitm_service)
        .with_state(root_node.get_public_url())
        .into_make_service();

    block_on(async {
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = tokio::net::TcpListener::bind(socket_addr)
            .await
            .expect("failed to bind");
        let socket_addr = listener.local_addr().unwrap();

        let proxy_server = axum::serve(listener, mitm);
        info!(logger, "Started a MITM proxy on {}", socket_addr);
        let proxy_url =
            url::Url::parse(&format!("http://{}", socket_addr)).expect("failed to parse url");

        tokio::runtime::Handle::current().spawn(async move {
            proxy_server.await.ok();
        });

        let runtime = runtime_from_url(
            root_node.get_public_url(),
            root_node.effective_canister_id(),
        );

        info!(logger, "creating a new registry canister...");
        let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
        info!(logger, "installing registry canister...");
        let registry_init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
            // Populate registry with some data
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![upsert("IC", "Good")],
                preconditions: vec![],
            })
            .build();
        install_registry_canister(&mut canister, registry_init_payload).await;
        let client = RegistryCanister::new(vec![root_node.get_public_url()]);

        info!(logger, "validating registry contents...");
        // Check that the registry indeed contains the data
        let value = client
            .get_value(b"IC".to_vec(), None)
            .await
            .expect("failed to get value");

        assert_eq!(value, (b"Good".to_vec(), 2));

        info!(logger, "fetching certified deltas...");
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
                RegistryAtomicMutateRequest {
                    mutations: vec![upsert("Proprietary Clouds", "Less Good")],
                    preconditions: vec![]
                }
                .encode_to_vec()
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

// Describes a proxy server that replaces all occurrences of "Good" with "Evil".
async fn mitm_service(
    State(root_url): State<url::Url>,
    req: Request<Body>,
) -> Result<(HeaderMap, Body), String> {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .map_err(|err| err.to_string())?;

    let mut target_url = root_url.clone();
    target_url.set_path(req.uri().path());

    let mut request = reqwest::Request::new(req.method().clone(), target_url);

    let (parts, body) = req.into_parts();
    *request.headers_mut() = parts.headers;
    *request.body_mut() = Some(reqwest::Body::wrap_stream(BodyDataStream::new(body)));

    let response = client
        .execute(request)
        .await
        .map_err(|err| err.to_string())?;

    let headers = response.headers().clone();
    let mut bytes = response
        .bytes()
        .await
        .map_err(|err| err.to_string())?
        .to_vec();

    if bytes.len() < 4 {
        return Ok((headers, bytes.into()));
    }

    for i in 0..bytes.len() - 3 {
        if &bytes[i..i + 4] == b"Good" {
            bytes[i..i + 4].copy_from_slice(b"Evil");
        }
    }
    Ok((headers, bytes.into()))
}
