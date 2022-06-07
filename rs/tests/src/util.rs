use crate::types::*;
use candid::{Decode, Encode};
use canister_test::{Canister, RemoteTestRuntime, Runtime, Wasm};
use ic_agent::{Agent, AgentError, Identity, RequestId};
use ic_canister_client::{Agent as DeprecatedAgent, Sender};
use ic_config::ConfigOptional;
use ic_fondue::ic_manager::{IcEndpoint, IcHandle};
use ic_ic00_types::{CanisterStatusResult, EmptyBlob};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use slog::{debug, info};

use dfn_protobuf::{protobuf, ProtoBuf};
use ic_agent::export::Principal;
use ic_constants::MAX_INGRESS_TTL;
use ic_nns_test_utils::governance::upgrade_nns_canister_by_proposal;
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_api::convert::to_arg;
use ic_types::{CanisterId, Cycles, PrincipalId};
use ic_universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, Memo, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};
use on_wire::FromWire;
use rand_chacha::ChaCha8Rng;
use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime as TRuntime;
use url::Url;

pub const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
pub const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
pub const AGENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A short wasm module that is a legal canister binary.
pub(crate) const _EMPTY_WASM: &[u8] = &[0, 97, 115, 109, 1, 0, 0, 0];

pub(crate) const CFG_TEMPLATE_BYTES: &[u8] =
    include_bytes!("../../../ic-os/guestos/rootfs/opt/ic/share/ic.json5.template");

fn get_identity() -> ic_agent::identity::BasicIdentity {
    let contents = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILhMGpmYuJ0JEhDwocj6pxxOmIpGAXZd40AjkNhuae6q\noSMDIQBeXC6ae2dkJ8QC50bBjlyLqsFQFsMsIThWB21H6t6JRA==\n-----END PRIVATE KEY-----";
    ic_agent::identity::BasicIdentity::from_pem(contents.as_bytes()).expect("Invalid secret key.")
}

/// Initializes a testing [Runtime] from a node's url. You should really
/// think of this runtime as a _HTTP Agent_, perhaps one day we should rename
/// it. Anyway, the [Runtime] is used to talk to a node in a caching manner.
///
/// We use the [Runtime] to install and interact with canisters. It might be
/// tempting to pack a [Runtime] and a [Canister<'_>] into the same struct but
/// this can lead to inconsistent data if we install a canister from one node's
/// runtime but delete it from another node's runtime.
pub fn runtime_from_url(url: Url) -> Runtime {
    let agent = DeprecatedAgent::new(
        url,
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
    );
    Runtime::Remote(RemoteTestRuntime { agent })
}

/// Provides an abstraction to the universal canister.
#[derive(Clone)]
pub struct UniversalCanister<'a> {
    agent: &'a Agent,
    canister_id: Principal,
}

impl<'a> UniversalCanister<'a> {
    /// Initializes a [UniversalCanister] using the provided [Agent] and
    /// allocates some stable memory at canister installation.
    pub async fn new(agent: &'a Agent) -> UniversalCanister<'a> {
        Self::new_with_comp_alloc(agent, None, None)
            .await
            .expect("Could not create universal canister.")
    }

    pub async fn try_new(agent: &'a Agent) -> Result<UniversalCanister<'a>, String> {
        Self::new_with_comp_alloc(agent, None, None).await
    }

    pub async fn new_with_comp_alloc(
        agent: &'a Agent,
        compute_allocation: Option<u64>,
        cycles: Option<u64>,
    ) -> Result<UniversalCanister<'a>, String> {
        let payload = universal_canister_argument_builder().stable_grow(1).build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .with_optional_compute_allocation(compute_allocation)
            .as_provisional_create_with_amount(cycles)
            .call_and_wait(delay())
            .await
            .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait(delay())
            .await
            .map_err(|err| format!("Couldn't install universal canister: {}", err))?;

        Ok(Self { agent, canister_id })
    }

    pub async fn new_with_cycles<C: Into<u64>>(
        agent: &'a Agent,
        cycles: C,
    ) -> UniversalCanister<'a> {
        let payload = universal_canister_argument_builder().stable_grow(1).build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(Some(cycles.into()))
            .call_and_wait(delay())
            .await
            .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {}", err))
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait(delay())
            .await
            .unwrap_or_else(|err| panic!("Couldn't install universal canister: {}", err));

        Self { agent, canister_id }
    }

    pub async fn new_with_64bit_stable_memory(
        agent: &'a Agent,
    ) -> Result<UniversalCanister<'a>, String> {
        let payload = universal_canister_argument_builder()
            .stable64_grow(1)
            .build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .call_and_wait(delay())
            .await
            .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait(delay())
            .await
            .map_err(|err| format!("Couldn't install universal canister: {}", err))?;

        Ok(Self { agent, canister_id })
    }

    /// Initializes a universal canister wrapper from a canister id. Does /NOT/
    /// perform any installation operation on the runtime.
    pub fn from_canister_id(agent: &'a Agent, canister_id: Principal) -> UniversalCanister<'a> {
        Self { agent, canister_id }
    }

    /// Upgrades an NNS canister to universal abilities (by proposal),
    /// preserving the Id.
    pub async fn upgrade(
        runtime: &'a Runtime,
        agent: &'a Agent,
        nns_canister_id: &CanisterId,
    ) -> UniversalCanister<'a> {
        let can = Canister::new(runtime, *nns_canister_id);
        let governance = Canister::new(runtime, GOVERNANCE_CANISTER_ID);
        let root = Canister::new(runtime, ROOT_CANISTER_ID);
        upgrade_nns_canister_by_proposal(
            &can,
            &governance,
            &root,
            true,
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
        )
        .await;
        Self::from_canister_id(
            agent,
            Principal::try_from(nns_canister_id.get().to_vec()).unwrap(),
        )
    }

    /// Builds the arguments to use with stable writer
    pub fn stable_writer(offset: u32, msg: &[u8]) -> Vec<u8> {
        universal_canister_argument_builder()
            .stable_write(offset, msg)
            .reply()
            .build()
    }

    /// Try to store `msg` in stable memory starting at `offset` bytes.
    pub async fn try_store_to_stable(
        &self,
        offset: u32,
        msg: &[u8],
        delay: garcon::Delay,
    ) -> Result<(), AgentError> {
        let res = self
            .agent
            .update(&self.canister_id, "update")
            .with_arg(Self::stable_writer(offset, msg))
            .call_and_wait(delay)
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Stores `msg` in stable memory starting at `offset` bytes.
    pub async fn store_to_stable(&self, offset: u32, msg: &[u8]) {
        self.agent
            .update(&self.canister_id, "update")
            .with_arg(Self::stable_writer(offset, msg))
            .call_and_wait(delay())
            .await
            .unwrap_or_else(|err| panic!("Could not push message to stable: {}", err));
    }

    /// Tries to read `len` bytes of the stable memory, starting from `offset`.
    pub async fn read_stable(&self, offset: u32, len: u32) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query(&self.canister_id, "query")
            .with_arg(
                universal_canister_argument_builder()
                    .stable_read(offset, len)
                    .reply_data_append()
                    .reply()
                    .build(),
            )
            .call()
            .await
    }

    /// Tries to read `len` bytes of the stable memory, starting from `offset`.
    /// Panics if the read could not be performed.
    pub async fn try_read_stable(&self, offset: u32, len: u32) -> Vec<u8> {
        self.read_stable(offset, len).await.unwrap_or_else(|err| {
            panic!("could not read message of len {} from stable: {}", len, err)
        })
    }

    /// Tries to read `len` bytes of the stable memory, starting from `offset`.
    /// Panics if the read could not be performed after `max_retries`.
    pub async fn try_read_stable_with_retries(
        &self,
        log: &slog::Logger,
        offset: u32,
        len: u32,
        max_retries: u64,
        retry_wait: Duration,
    ) -> Vec<u8> {
        for i in 0..max_retries + 1 {
            debug!(log, "Reading from stable memory, attempt {}.", i + 1);
            let result = self.read_stable(offset, len).await;
            match result {
                Ok(message) => return message,
                Err(err) => {
                    debug!(log, "Couldn't read from stable memory, err={}", err);
                    debug!(log, "Retrying in {} secs ...", retry_wait.as_secs());
                    tokio::time::sleep(retry_wait).await;
                }
            }
        }
        panic!(
            "Could not read message from stable memory after {} retries.",
            max_retries
        );
    }

    /// Forwards a message to the `receiver` that calls
    /// `receiver.method(payload)` along with the specified amount of cycles
    /// and returns the result.
    pub async fn forward_with_cycles_to(
        &self,
        receiver: &Principal,
        method: &str,
        payload: Vec<u8>,
        cycles: Cycles,
    ) -> Result<Vec<u8>, AgentError> {
        let universal_canister_payload = universal_canister_argument_builder()
            .call_with_cycles(
                // The universal canister API expects a `PrincipalId`.
                PrincipalId::try_from(receiver.as_slice()).unwrap(),
                method,
                call_args().other_side(payload).on_reject(
                    universal_canister_argument_builder()
                        .reject_message()
                        .reject(),
                ),
                cycles.into_parts(),
            )
            .build();

        self.agent
            .update(&self.canister_id, "update")
            .with_arg(universal_canister_payload)
            .call_and_wait(delay())
            .await
    }

    /// Forwards a message to the `receiver` that calls
    /// `receiver.method(payload)` and returns the result.
    pub async fn forward_to(
        &self,
        receiver: &Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        self.forward_with_cycles_to(
            receiver,
            method,
            payload,
            Cycles::zero(), /* no cycles */
        )
        .await
    }

    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    pub async fn query<P: Into<Vec<u8>>>(&self, payload: P) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query(&self.canister_id, "query")
            .with_arg(payload.into())
            .call()
            .await
    }

    pub async fn update<P: Into<Vec<u8>>>(&self, payload: P) -> Result<Vec<u8>, AgentError> {
        self.agent
            .update(&self.canister_id, "update")
            .with_arg(payload.into())
            .call_and_wait(delay())
            .await
    }
}

/// Initializes an `Agent` using the provided URL.
/// The root key is fetched as part of the initialization in order
/// to validate certificates from the replica.
pub async fn assert_create_agent(url: &str) -> Agent {
    create_agent(url)
        .await
        .unwrap_or_else(|err| panic!("Failed to create agent for {}: {:?}", url, err))
}

pub async fn create_agent(url: &str) -> Result<Agent, AgentError> {
    agent_with_identity(url, get_identity()).await
}
pub async fn create_agent_mapping(url: &str, addr_mapping: IpAddr) -> Result<Agent, AgentError> {
    agent_with_identity_mapping(url, Some(addr_mapping), get_identity()).await
}

pub async fn agent_with_identity(
    url: &str,
    identity: impl Identity + 'static,
) -> Result<Agent, AgentError> {
    agent_with_identity_mapping(url, None, identity).await
}

pub async fn agent_with_identity_mapping(
    url: &str,
    addr_mapping: Option<IpAddr>,
    identity: impl Identity + 'static,
) -> Result<Agent, AgentError> {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    use rustls::client::HandshakeSignatureValid;
    use rustls::client::ServerCertVerified;
    use rustls::client::ServerCertVerifier;
    use rustls::client::ServerName;
    use rustls::internal::msgs::handshake::DigitallySignedStruct;

    struct NoVerifier;
    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::Certificate,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::Certificate,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
    }
    let mut tls_config = builder
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    // Advertise support for HTTP/2
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let builder = reqwest::Client::builder()
        .timeout(AGENT_REQUEST_TIMEOUT)
        .use_preconfigured_tls(tls_config);
    let builder = match (
        addr_mapping,
        reqwest::Url::parse(url).as_ref().map(|u| u.domain()),
    ) {
        (Some(addr_mapping), Ok(Some(domain))) => builder.resolve(domain, (addr_mapping, 0).into()),
        _ => builder,
    };
    let client = builder
        .build()
        .map_err(|err| AgentError::TransportError(Box::new(err)))?;
    agent_with_client_identity(url, client, identity).await
}

pub async fn agent_with_client_identity(
    url: &str,
    client: reqwest::Client,
    identity: impl Identity + 'static,
) -> Result<Agent, AgentError> {
    let a = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create_with_client(
            url, client,
        )?)
        .with_identity(identity)
        // Ingresses are created with the system time but are checked against the consensus time.
        // Consensus time is the time that is in the last finalized block. Consensus time might lag
        // behind, for example when the subnet has many modes and the progress of consensus is
        // computaionally heavy for the system to deal with in time. In such cases, the consensus
        // time might be 'x', while the system time is x+2sn, for example. When the handlers check
        // the validity of ingresses, they expect the expiry time to be between x and
        // x+MAX_INGRESS_TTL. If we used MAX_INGRESS_TTL as the expiry delay while creating the
        // ingresses as well, we would set the ingresses' expiry_time to x+MAX_INGRESS_TTL+2sn in
        // this case. Then, such ingresses would get rejected by the replica as their expiry_time is
        // too further in the future, i.e. greater than x+MAX_INGRESS_TTL in this case. To tolerate
        // the delays in the progress of consensus, we reduce 30sn from MAX_INGRESS_TTL and set the
        // expiry_time of ingresses accordingly.
        .with_ingress_expiry(Some(MAX_INGRESS_TTL - std::time::Duration::from_secs(30)))
        .build()
        .unwrap();
    a.fetch_root_key().await?;
    Ok(a)
}

// Creates an identity to be used with `Agent`.
pub fn random_ed25519_identity() -> impl Identity {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    ic_agent::identity::BasicIdentity::from_key_pair(
        ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
            .expect("Could not read the key pair."),
    )
}

// How `Agent` is instructed to wait for update calls.
pub fn delay() -> garcon::Delay {
    garcon::Delay::builder()
        .throttle(std::time::Duration::from_millis(500))
        .timeout(std::time::Duration::from_secs(60 * 5))
        .build()
}

pub fn create_delay(throttle_duration: u64, timeout: u64) -> garcon::Delay {
    garcon::Delay::builder()
        .throttle(std::time::Duration::from_millis(throttle_duration))
        .timeout(std::time::Duration::from_secs(timeout))
        .build()
}

pub fn get_random_node_endpoint<'a>(handle: &'a IcHandle, rng: &mut ChaCha8Rng) -> &'a IcEndpoint {
    handle.as_permutation(rng).next().unwrap()
}

pub fn get_random_nns_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    // NOTE: Root subnet and NNS subnet are currently the same.
    get_random_root_node_endpoint(handle, rng)
}

pub fn get_random_root_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    handle
        .as_permutation(rng)
        .find(|ep| ep.is_root_subnet)
        .unwrap()
}

pub fn get_random_non_root_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    handle
        .as_permutation(rng)
        .find(|ep| !ep.is_root_subnet)
        .unwrap()
}

pub fn get_random_non_nns_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    // NOTE: Root subnet and NNS subnet are currently the same.
    get_random_non_root_node_endpoint(handle, rng)
}

pub fn get_random_application_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    get_random_node_endpoint_of_init_subnet_type(handle, SubnetType::Application, rng)
}

pub fn get_random_verified_app_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    get_random_node_endpoint_of_init_subnet_type(handle, SubnetType::VerifiedApplication, rng)
}

pub fn get_random_system_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    get_random_node_endpoint_of_init_subnet_type(handle, SubnetType::System, rng)
}

pub fn get_random_system_but_not_nns_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    handle
        .as_permutation(rng)
        .find(|ep| {
            ep.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::System) && !ep.is_root_subnet
        })
        .unwrap()
}

pub fn get_random_node_endpoint_of_init_subnet_type<'a>(
    handle: &'a IcHandle,
    subnet_type: SubnetType,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    handle
        .as_permutation(rng)
        .find(|ep| ep.subnet.as_ref().map(|s| s.type_of) == Some(subnet_type))
        .unwrap()
}

pub fn get_other_subnet_nodes<'a>(
    handle: &'a IcHandle,
    endpoint: &'a IcEndpoint,
) -> Vec<&'a IcEndpoint> {
    handle
        .public_api_endpoints
        .iter()
        .filter(|ep| {
            ep.subnet.is_some()
                && ep.subnet_id() == endpoint.subnet_id()
                && ep.node_id != endpoint.node_id
        })
        .collect()
}

pub fn get_random_unassigned_node_endpoint<'a>(
    handle: &'a IcHandle,
    rng: &mut ChaCha8Rng,
) -> &'a IcEndpoint {
    handle
        .as_permutation(rng)
        .find(|ep| ep.subnet.is_none())
        .unwrap()
}

pub fn get_unassinged_nodes_endpoints(handle: &IcHandle) -> Vec<&IcEndpoint> {
    handle
        .public_api_endpoints
        .iter()
        .filter(|ep| ep.subnet.is_none())
        .collect()
}

// This indirectly asserts a non-zero finalization rate of the subnet:
// - We store a string in the memory by sending an `update` message to a canister
// - We retrieve the saved string by sending `query` message to a canister
pub(crate) async fn assert_subnet_can_make_progress(message: &[u8], endpoint: &IcEndpoint) {
    let agent = assert_create_agent(endpoint.url.as_str()).await;
    let universal_canister = UniversalCanister::new(&agent).await;
    universal_canister.store_to_stable(0, message).await;
    assert_eq!(
        universal_canister
            .try_read_stable(0, message.len() as u32)
            .await,
        message.to_vec()
    );
}

pub(crate) fn assert_reject<T: std::fmt::Debug>(res: Result<T, AgentError>, code: RejectCode) {
    match res {
        Ok(val) => panic!("Expected call to fail but it succeeded with {:?}", val),
        Err(agent_error) => match agent_error {
            AgentError::ReplicaError {
                reject_code,
                reject_message,
            } => assert_eq!(
                reject_code, code as u64,
                "Expect code {} did not match {}. Reject message: {}",
                reject_code, code as u64, reject_message
            ),
            others => panic!(
                "Expected call to fail with a replica error but got {:?} instead",
                others
            ),
        },
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EndpointsStatus {
    AllReachable,
    AllUnreachable,
}

pub(crate) async fn assert_endpoints_reachability(
    endpoints: &[&IcEndpoint],
    status: EndpointsStatus,
) {
    // Returns true if: either all endpoints are reachable or all unreachable (depending on the desired input status).
    let check_reachability = || async move {
        let hs = futures::future::join_all(endpoints.iter().map(|e| e.healthy())).await;
        match status {
            // For AllReachable status, we return the result of healthy().
            EndpointsStatus::AllReachable => hs.iter().all(|x| x.as_ref().map_or(false, |x| x.0)),
            // For AllUnreachable status, we return the NOT result of healthy().
            EndpointsStatus::AllUnreachable => hs.iter().all(|x| x.as_ref().map_or(true, |x| !x.0)),
        }
    };

    const TIMEOUT: Duration = Duration::from_secs(500);
    const DELAY: Duration = Duration::from_secs(20);
    let start = Instant::now();
    while start.elapsed() < TIMEOUT {
        if check_reachability().await {
            return;
        }
        tokio::time::sleep(DELAY).await;
    }
    panic!("Not all endpoints have reached the desired reachability status {:?} within timeout {} sec.", status, TIMEOUT.as_secs());
}

pub(crate) fn assert_http_submit_fails(
    result: Result<RequestId, AgentError>,
    http_status_code: reqwest::StatusCode,
) {
    match result {
        Ok(val) => panic!("Expected call to fail but it succeeded with {:?}", val),
        Err(agent_error) => match agent_error {
            AgentError::HttpError(payload) => assert_eq!(
                payload.status, http_status_code,
                "Unexpected HTTP status code: {}",
                payload
            ),
            others => panic!(
                "Expected call to fail with http error but got {:?} instead",
                others
            ),
        },
    }
}

pub(crate) async fn create_and_install(agent: &Agent, canister_wasm: &[u8]) -> Principal {
    // Initialize the canister with a healthy amount of cycles.
    create_and_install_with_cycles(agent, canister_wasm, CYCLES_LIMIT_PER_CANISTER).await
}

pub(crate) async fn create_and_install_with_cycles(
    agent: &Agent,
    canister_wasm: &[u8],
    amount: Cycles,
) -> Principal {
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(Some(amount.into()))
        .call_and_wait(delay())
        .await
        .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {}", err))
        .0;

    // Install the universal canister.
    mgr.install_code(&canister_id, canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait(delay())
        .await
        .unwrap_or_else(|err| panic!("Couldn't install canister: {}", err));

    canister_id
}

pub(crate) fn assert_balance_equals(expected: Cycles, actual: Cycles, epsilon: Cycles) {
    // Tolerate both positive and negative difference. Assumes no u64 overflows.
    assert!(
        expected < actual + epsilon && actual < expected + epsilon,
        "assert_balance_equals: expected {} actual {} epsilon {}",
        expected,
        actual,
        epsilon
    );
}

pub(crate) async fn get_balance(canister_id: &Principal, agent: &Agent) -> u128 {
    let mgr = ManagementCanister::create(agent);
    let canister_status = mgr
        .canister_status(canister_id)
        .call_and_wait(delay())
        .await
        .unwrap_or_else(|err| panic!("Could not get canister status: {}", err))
        .0;
    u128::try_from(canister_status.cycles.0).unwrap()
}

pub(crate) async fn set_controller(
    controllee: &Principal,
    controller: &Principal,
    controllee_agent: &Agent,
) {
    let mgr = ManagementCanister::create(controllee_agent);
    mgr.update_settings(controllee)
        .with_controller(*controller)
        .call_and_wait(delay())
        .await
        .unwrap_or_else(|err| panic!("Could not set controller: {}", err))
}

pub(crate) async fn deposit_cycles(
    controller: &UniversalCanister<'_>,
    &canister_id: &Principal,
    cycles_to_deposit: Cycles,
) {
    controller
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "deposit_cycles",
            Encode!(&CanisterIdRecord { canister_id }).unwrap(),
            cycles_to_deposit,
        )
        .await
        .unwrap_or_else(|err| panic!("Failed to deposit to canister: {}", err));
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt =
        TRuntime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));
    rt.block_on(f)
}

pub(crate) async fn create_canister_via_canister(
    wallet_canister: &UniversalCanister<'_>,
) -> Result<Principal, AgentError> {
    create_canister_via_canister_with_cycles(wallet_canister, Cycles::new(2_000_000_000_000)).await
}

pub(crate) async fn create_canister_via_canister_with_cycles(
    wallet_canister: &UniversalCanister<'_>,
    cycles: Cycles,
) -> Result<Principal, AgentError> {
    wallet_canister
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "create_canister",
            EmptyBlob::encode(),
            cycles,
        )
        .await
        .map(|res| {
            Decode!(res.as_slice(), CreateCanisterResult)
                .unwrap()
                .canister_id
        })
}

pub(crate) async fn get_balance_via_canister(
    &canister_id: &Principal,
    via_canister: &UniversalCanister<'_>,
) -> Cycles {
    via_canister
        .forward_to(
            &Principal::management_canister(),
            "canister_status",
            Encode!(&CanisterIdRecord { canister_id }).unwrap(),
        )
        .await
        .map(|res| {
            Decode!(res.as_slice(), CanisterStatusResult)
                .unwrap()
                .cycles()
                .into()
        })
        .unwrap()
}

pub(crate) async fn get_icp_balance(
    ledger: &Canister<'_>,
    can: &CanisterId,
    subaccount: Option<Subaccount>,
) -> Result<Tokens, String> {
    ledger
        .query_(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs::new(AccountIdentifier::new(can.get(), subaccount)),
        )
        .await
}

pub(crate) async fn transact_icp_subaccount(
    ctx: &ic_fondue::pot::Context,
    ledger: &Canister<'_>,
    sender: (&UniversalCanister<'_>, Option<Subaccount>),
    amount: u64,
    recipient: (&UniversalCanister<'_>, Option<Subaccount>),
) -> anyhow::Result<Tokens, String> {
    let pid = PrincipalId::try_from(recipient.0.canister_id().as_slice()).unwrap();

    let args = SendArgs {
        memo: Memo::default(),
        amount: Tokens::from_e8s(amount),
        fee: DEFAULT_TRANSFER_FEE,
        to: AccountIdentifier::new(pid, recipient.1),
        created_at_time: None,
        from_subaccount: sender.1,
    };
    info!(ctx.logger, "send {:?}", args);
    let reply = sender
        .0
        .forward_to(
            &Principal::try_from(ledger.canister_id().get().to_vec()).unwrap(),
            "send_pb",
            to_arg(args),
        )
        .await
        .map_err(|e| format!("{:?}", e))?;

    let decoded: u64 = ProtoBuf::from_bytes(reply).map(|ProtoBuf(c)| c)?;
    info!(ctx.logger, "decoded result is {:?}", decoded);

    get_icp_balance(
        ledger,
        &CanisterId::try_from(recipient.0.canister_id().as_slice()).unwrap(),
        recipient.1,
    )
    .await
}

pub(crate) async fn transact_icp(
    ctx: &ic_fondue::pot::Context,
    ledger: &Canister<'_>,
    sender: &UniversalCanister<'_>,
    amount: u64,
    recipient: &UniversalCanister<'_>,
) -> Result<Tokens, String> {
    transact_icp_subaccount(ctx, ledger, (sender, None), amount, (recipient, None)).await
}

pub(crate) fn to_principal_id(principal: &Principal) -> PrincipalId {
    PrincipalId::try_from(principal.as_slice()).unwrap()
}

pub(crate) async fn assert_all_ready(endpoints: &[&IcEndpoint], ctx: &ic_fondue::pot::Context) {
    for &e in endpoints {
        e.assert_ready(ctx).await;
    }
}

pub async fn assert_agent_observes_canister_module(agent: &Agent, canister_id: &Principal) {
    let has_module_hash = || async {
        ManagementCanister::create(agent)
            .canister_status(canister_id)
            .call_and_wait(delay())
            .await
            .unwrap()
            .0
            .module_hash
            .is_some()
    };
    assert!(has_module_hash().await);
}

pub(crate) async fn assert_canister_counter_with_retries(
    log: &slog::Logger,
    agent: &Agent,
    canister_id: &Principal,
    payload: Vec<u8>,
    min_expected_count: usize,
    max_retries: u32,
    retry_wait: Duration,
) {
    for i in 1..=1 + max_retries {
        debug!(
            log,
            "Reading counter value from canister with id={}, attempt {}.", canister_id, i
        );
        let res = agent
            .query(canister_id, "read")
            .with_arg(&payload)
            .call()
            .await
            .unwrap();
        let counter = u32::from_le_bytes(
            res.as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        ) as usize;
        debug!(log, "Counter value is {}.", counter);
        if counter >= min_expected_count {
            debug!(
                log,
                "Counter value on canister is {}, above the minimum expectation {}.",
                counter,
                min_expected_count
            );
            return;
        } else {
            debug!(
                log,
                "Counter value on canister is {}, below the minimum expectation {}.",
                counter,
                min_expected_count
            );
            debug!(log, "Retrying in {} secs ...", retry_wait.as_secs());
            tokio::time::sleep(retry_wait).await;
        }
    }
    panic!(
        "Minimum expected counter value {} on counter canister was not observed after {} retries.",
        min_expected_count, max_retries
    );
}

/// Converts Canister id into an escaped byte string
pub(crate) fn escape_for_wat(id: &Principal) -> String {
    // Quoting from
    // https://webassembly.github.io/spec/core/text/values.html#text-string:
    //
    // "Strings [...] can represent both textual and binary data" and
    //
    // "hexadecimal escape sequences ‘∖ℎℎ’, [...] represent raw bytes of the
    // respective value".
    id.as_slice().iter().fold(String::new(), |mut res, b| {
        res.push_str(&format!("\\{:02x}", b));
        res
    })
}

pub fn get_config() -> ConfigOptional {
    let cfg = String::from_utf8_lossy(CFG_TEMPLATE_BYTES).to_string();
    // Make the string parsable by filling the template placeholders with dummy values
    let cfg = cfg.replace("{{ node_index }}", "0");
    let cfg = cfg.replace("{{ ipv6_address }}", "::");
    let cfg = cfg.replace("{{ backup_retention_time_secs }}", "0");
    let cfg = cfg.replace("{{ backup_purging_interval_secs }}", "0");
    let cfg = cfg.replace("{{ log_debug_overrides }}", "[]");
    let cfg = cfg.replace("{{ nns_url }}", "http://www.fakeurl.com/");
    let cfg = cfg.replace("{{ malicious_behavior }}", "null");
    json5::from_str::<ConfigOptional>(&cfg).expect("Could not parse json5")
}

// TODO: remove in favor of dfinity/agent-rs/pull/337
use http_transport::ReqwestHttpReplicaV2Transport;
#[allow(dead_code)]
mod http_transport {
    use hyper_rustls::ConfigBuilderExt;
    use ic_agent::{
        agent::{
            agent_error::HttpErrorPayload, http_transport::PasswordManager, ReplicaV2Transport,
        },
        ic_types::Principal,
        AgentError, RequestId,
    };
    use reqwest::Method;
    use std::{future::Future, pin::Pin, sync::Arc};

    /// A [ReplicaV2Transport] using Reqwest to make HTTP calls to the internet computer.
    pub struct ReqwestHttpReplicaV2Transport {
        url: reqwest::Url,
        client: reqwest::Client,
        password_manager: Option<Arc<dyn PasswordManager>>,
    }

    const IC0_DOMAIN: &str = "ic0.app";
    const IC0_SUB_DOMAIN: &str = ".ic0.app";

    impl ReqwestHttpReplicaV2Transport {
        /// Creates a replica transport from a HTTP URL.
        pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
            let mut tls_config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_webpki_roots()
                .with_no_client_auth();

            // Advertise support for HTTP/2
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Self::create_with_client(
                url,
                reqwest::Client::builder()
                    .use_preconfigured_tls(tls_config)
                    .build()
                    .expect("Could not create HTTP client."),
            )
        }

        /// Creates a replica transport from a HTTP URL and a [`reqwest::Client`].
        pub fn create_with_client<U: Into<String>>(
            url: U,
            client: reqwest::Client,
        ) -> Result<Self, AgentError> {
            let url = url.into();
            Ok(Self {
                url: reqwest::Url::parse(&url)
                    .and_then(|mut url| {
                        // rewrite *.ic0.app to ic0.app
                        if let Some(domain) = url.domain() {
                            if domain.ends_with(IC0_SUB_DOMAIN) {
                                url.set_host(Some(IC0_DOMAIN))?;
                            }
                        }
                        url.join("api/v2/")
                    })
                    .map_err(|_| AgentError::InvalidReplicaUrl(url.clone()))?,
                client,
                password_manager: None,
            })
        }

        /// Sets a password manager to use with HTTP authentication.
        pub fn with_password_manager<P: 'static + PasswordManager>(
            self,
            password_manager: P,
        ) -> Self {
            ReqwestHttpReplicaV2Transport {
                password_manager: Some(Arc::new(password_manager)),
                url: self.url,
                client: self.client,
            }
        }

        /// Same as [`with_password_manager`], but providing the Arc so one does not have to be created.
        pub fn with_arc_password_manager(self, password_manager: Arc<dyn PasswordManager>) -> Self {
            ReqwestHttpReplicaV2Transport {
                password_manager: Some(password_manager),
                url: self.url,
                client: self.client,
            }
        }

        /// Gets the set password manager, if one exists. Otherwise returns None.
        pub fn password_manager(&self) -> Option<&dyn PasswordManager> {
            self.password_manager.as_deref()
        }

        fn maybe_add_authorization(
            &self,
            http_request: &mut reqwest::Request,
            cached: bool,
        ) -> Result<(), AgentError> {
            if let Some(pm) = &self.password_manager {
                let maybe_user_pass = if cached {
                    pm.cached(http_request.url().as_str())
                } else {
                    pm.required(http_request.url().as_str()).map(Some)
                };

                if let Some((u, p)) = maybe_user_pass.map_err(AgentError::AuthenticationError)? {
                    let auth = base64::encode(&format!("{}:{}", u, p));
                    http_request.headers_mut().insert(
                        reqwest::header::AUTHORIZATION,
                        format!("Basic {}", auth).parse().unwrap(),
                    );
                }
            }
            Ok(())
        }

        async fn request(
            &self,
            http_request: reqwest::Request,
        ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>), AgentError>
        {
            let response = self
                .client
                .execute(
                    http_request
                        .try_clone()
                        .expect("Could not clone a request."),
                )
                .await
                .map_err(|x| AgentError::TransportError(Box::new(x)))?;

            let http_status = response.status();
            let response_headers = response.headers().clone();
            let bytes = response
                .bytes()
                .await
                .map_err(|x| AgentError::TransportError(Box::new(x)))?
                .to_vec();

            Ok((http_status, response_headers, bytes))
        }

        async fn execute(
            &self,
            method: Method,
            endpoint: &str,
            body: Option<Vec<u8>>,
        ) -> Result<Vec<u8>, AgentError> {
            let url = self.url.join(endpoint)?;
            let mut http_request = reqwest::Request::new(method, url);
            http_request.headers_mut().insert(
                reqwest::header::CONTENT_TYPE,
                "application/cbor".parse().unwrap(),
            );

            self.maybe_add_authorization(&mut http_request, true)?;

            *http_request.body_mut() = body.map(reqwest::Body::from);

            let mut status;
            let mut headers;
            let mut body;
            loop {
                let request_result = self.request(http_request.try_clone().unwrap()).await?;
                status = request_result.0;
                headers = request_result.1;
                body = request_result.2;

                // If the server returned UNAUTHORIZED, and it is the first time we replay the call,
                // check if we can get the username/password for the HTTP Auth.
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    if self.url.scheme() == "https" || self.url.host_str() == Some("localhost") {
                        // If there is a password manager, get the username and password from it.
                        self.maybe_add_authorization(&mut http_request, false)?;
                    } else {
                        return Err(AgentError::CannotUseAuthenticationOnNonSecureUrl());
                    }
                } else {
                    break;
                }
            }

            if status.is_client_error() || status.is_server_error() {
                Err(AgentError::HttpError(HttpErrorPayload {
                    status: status.into(),
                    content_type: headers
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(|x| x.to_string()),
                    content: body,
                }))
            } else {
                Ok(body)
            }
        }
    }

    impl ReplicaV2Transport for ReqwestHttpReplicaV2Transport {
        fn call<'a>(
            &'a self,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
            _request_id: RequestId,
        ) -> Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send + 'a>> {
            async fn run(
                s: &ReqwestHttpReplicaV2Transport,
                effective_canister_id: Principal,
                envelope: Vec<u8>,
            ) -> Result<(), AgentError> {
                let endpoint = format!("canister/{}/call", effective_canister_id.to_text());
                s.execute(Method::POST, &endpoint, Some(envelope)).await?;
                Ok(())
            }

            Box::pin(run(self, effective_canister_id, envelope))
        }

        fn read_state<'a>(
            &'a self,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
            async fn run(
                s: &ReqwestHttpReplicaV2Transport,
                effective_canister_id: Principal,
                envelope: Vec<u8>,
            ) -> Result<Vec<u8>, AgentError> {
                let endpoint = format!("canister/{}/read_state", effective_canister_id.to_text());
                s.execute(Method::POST, &endpoint, Some(envelope)).await
            }

            Box::pin(run(self, effective_canister_id, envelope))
        }

        fn query<'a>(
            &'a self,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
            async fn run(
                s: &ReqwestHttpReplicaV2Transport,
                effective_canister_id: Principal,
                envelope: Vec<u8>,
            ) -> Result<Vec<u8>, AgentError> {
                let endpoint = format!("canister/{}/query", effective_canister_id.to_text());
                s.execute(Method::POST, &endpoint, Some(envelope)).await
            }

            Box::pin(run(self, effective_canister_id, envelope))
        }

        fn status<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
            async fn run(s: &ReqwestHttpReplicaV2Transport) -> Result<Vec<u8>, AgentError> {
                s.execute(Method::GET, "status", None).await
            }

            Box::pin(run(self))
        }
    }
}
