use crate::{
    canister_agent::CanisterAgent,
    canister_api::GenericRequest,
    driver::{
        group::{MAX_RUNTIME_BLOCKING_THREADS, MAX_RUNTIME_THREADS},
        test_env_api::*,
    },
    generic_workload_engine::{engine::Engine, metrics::LoadTestMetrics},
    retry_with_msg, retry_with_msg_async,
    types::*,
};
use anyhow::{anyhow, bail};
use candid::{Decode, Encode};
use canister_test::{Canister, RemoteTestRuntime, Runtime, Wasm};
use dfn_protobuf::{ProtoBuf, protobuf};
use futures::{
    FutureExt,
    future::{join_all, select_all, try_join_all},
};
use ic_agent::{
    Agent, AgentError, Identity, Signature,
    agent::{
        CallResponse, EnvelopeContent, RejectCode, RejectResponse,
        http_transport::reqwest_transport::reqwest,
    },
    export::Principal,
    identity::BasicIdentity,
};
use ic_canister_client::{Agent as DeprecatedAgent, Sender};
use ic_cdk::management_canister::{
    SignWithEcdsaResult, SignWithSchnorrResult, VetKDDeriveKeyResult,
};
use ic_config::{ConfigOptional, ConfigSource};
use ic_limits::MAX_INGRESS_TTL;
use ic_management_canister_types_private::{CanisterStatusResultV2, EmptyBlob, Payload};
use ic_message::ForwardParams;
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    CreateServiceNervousSystem,
    create_service_nervous_system::{
        SwapParameters,
        swap_parameters::NeuronBasketConstructionParameters as GovApiNeuronBasketConstructionParameters,
    },
};
use ic_nns_test_utils::governance::upgrade_nns_canister_with_args_by_proposal;
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_api::convert::to_arg;
use ic_signer::{GenEcdsaParams, GenSchnorrParams, GenVetkdParams};
use ic_sns_swap::pb::v1::{NeuronBasketConstructionParameters, Params};
use ic_test_identity::TEST_IDENTITY_KEYPAIR;
use ic_types::{
    CanisterId, Cycles, PrincipalId,
    messages::{HttpCallContent, HttpQueryContent, HttpReadStateContent},
};
use ic_universal_canister::{call_args, wasm as universal_canister_argument_builder};
use ic_utils::{call::AsyncCall, interfaces::ManagementCanister};
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, DEFAULT_TRANSFER_FEE, Memo, SendArgs, Subaccount,
    Tokens, tokens_from_proto,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use on_wire::FromWire;
use slog::{Logger, debug, info};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fmt::Debug,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpSocket, TcpStream},
    runtime::{Builder, Handle as THandle},
    time::timeout,
};
use url::Url;

pub mod delegations;

pub const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
pub const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
pub const AGENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
pub const CANISTER_CREATE_TIMEOUT: Duration = Duration::from_secs(30);
/// A short wasm module that is a legal canister binary.
pub const _EMPTY_WASM: &[u8] = &[0, 97, 115, 109, 1, 0, 0, 0];

// Requests are multiplexed over H2 requests.
pub const MAX_CONCURRENT_REQUESTS: usize = 10_000;

pub const MAX_TCP_ERROR_RETRIES: usize = 5;

pub fn get_identity() -> ic_agent::identity::BasicIdentity {
    ic_agent::identity::BasicIdentity::from_pem(std::io::Cursor::new(
        TEST_IDENTITY_KEYPAIR.to_pem(),
    ))
    .expect("Invalid secret key.")
}

/// Initializes a testing [Runtime] from a node's url. You should really
/// think of this runtime as a _HTTP Agent_, perhaps one day we should rename
/// it. Anyway, the [Runtime] is used to talk to a node in a caching manner.
///
/// We use the [Runtime] to install and interact with canisters. It might be
/// tempting to pack a [Runtime] and a [Canister<'_>] into the same struct but
/// this can lead to inconsistent data if we install a canister from one node's
/// runtime but delete it from another node's runtime.
pub fn runtime_from_url(url: Url, effective_canister_id: PrincipalId) -> Runtime {
    let agent = DeprecatedAgent::new(
        url,
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
    );
    Runtime::Remote(RemoteTestRuntime {
        agent,
        effective_canister_id,
    })
}

// Note that we can't use the UNIVERSAL_CANISTER_WASM from rs/universal_canister/lib/src/lib.rs
// since in system-tests paths to runtime dependencies need to be get via get_dependency_path(path).
lazy_static! {
    /// The WASM of the Universal Canister.
    pub static ref UNIVERSAL_CANISTER_WASM: &'static [u8] = {
        let vec = get_canister_wasm("UNIVERSAL_CANISTER_WASM_PATH");
        Box::leak(vec.into_boxed_slice())
    };

    pub static ref MESSAGE_CANISTER_WASM: &'static [u8] = {
        let vec = get_canister_wasm("MESSAGE_CANISTER_WASM_PATH");
        Box::leak(vec.into_boxed_slice())
    };

    pub static ref SIGNER_CANISTER_WASM: &'static [u8] = {
        let vec = get_canister_wasm("SIGNER_CANISTER_WASM_PATH");
        Box::leak(vec.into_boxed_slice())
    };
}

fn get_canister_wasm(env_var: &str) -> Vec<u8> {
    let uc_wasm_path = get_dependency_path(
        std::env::var(env_var).unwrap_or_else(|e| panic!("{env_var:?} not set: {e:?}")),
    );
    std::fs::read(&uc_wasm_path)
        .unwrap_or_else(|e| panic!("Could not read WASM from {uc_wasm_path:?}: {e:?}"))
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
    pub async fn new(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
    ) -> UniversalCanister<'a> {
        Self::new_with_params_with_timeout(agent, effective_canister_id, None, None, None)
            .await
            .expect("Could not create universal canister.")
    }

    pub async fn try_new(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
    ) -> Result<UniversalCanister<'a>, String> {
        Self::new_with_params_with_timeout(agent, effective_canister_id, None, None, None).await
    }

    pub async fn new_with_retries(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        log: &slog::Logger,
    ) -> UniversalCanister<'a> {
        retry_with_msg_async!(
            format!(
                "install UniversalCanister {}",
                effective_canister_id.to_string()
            ),
            log,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                Self::new_with_params_with_timeout(agent, effective_canister_id, None, None, None)
                    .await
                    .map_err(|e| anyhow!(e))
            }
        )
        .await
        .expect("Could not create universal canister.")
    }

    pub async fn new_with_cycles_with_retries<C: Into<u128>>(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        cycles: C,
        log: &slog::Logger,
    ) -> UniversalCanister<'a> {
        let c = cycles.into();
        retry_with_msg_async!(
            format!(
                "install UniversalCanister {}",
                effective_canister_id.to_string()
            ),
            log,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                Self::new_with_cycles(agent, effective_canister_id, c)
                    .await
                    .map_err(|e| anyhow!(e))
            }
        )
        .await
        .expect("Could not create universal canister with cycles.")
    }

    pub async fn new_with_params_with_retries(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
        pages: Option<u32>,
        log: &slog::Logger,
    ) -> UniversalCanister<'a> {
        retry_with_msg_async!(
            format!(
                "install UniversalCanister {}",
                effective_canister_id.to_string()
            ),
            log,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                Self::new_with_params_with_timeout(
                    agent,
                    effective_canister_id,
                    compute_allocation,
                    cycles,
                    pages,
                )
                .await
                .map_err(|e| anyhow!(e))
            }
        )
        .await
        .expect("Could not create universal canister with params.")
    }

    pub async fn new_with_params_with_timeout(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
        pages: Option<u32>,
    ) -> Result<UniversalCanister<'a>, String> {
        match timeout(
            CANISTER_CREATE_TIMEOUT,
            Self::new_with_params(
                agent,
                effective_canister_id,
                compute_allocation,
                cycles,
                pages,
            ),
        )
        .await
        {
            Ok(Ok(canister)) => Ok(canister),
            Ok(Err(err)) => Err(format!("Could not create universal canister: {err:?}")),
            Err(_elasped) => Err("Timeout while creating universal canister".to_string()),
        }
    }

    pub async fn new_with_params(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
        pages: Option<u32>,
    ) -> Result<UniversalCanister<'a>, String> {
        let pages = pages.unwrap_or(1);
        let payload = universal_canister_argument_builder()
            .stable_grow(pages)
            .build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .with_optional_compute_allocation(compute_allocation)
            .as_provisional_create_with_amount(cycles)
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't create canister with provisional API: {err}"))?
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, &UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't install universal canister: {err}"))?;
        Ok(Self { agent, canister_id })
    }

    pub async fn new_with_cycles<C: Into<u128>>(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        cycles: C,
    ) -> Result<UniversalCanister<'a>, String> {
        let payload = universal_canister_argument_builder().stable_grow(1).build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(Some(cycles.into()))
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {err}"))
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, &UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't install universal canister: {err}"))?;
        Ok(Self { agent, canister_id })
    }

    pub async fn new_with_64bit_stable_memory(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
    ) -> Result<UniversalCanister<'a>, String> {
        let payload = universal_canister_argument_builder()
            .stable64_grow(1)
            .build();

        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't create canister with provisional API: {err}"))?
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, &UNIVERSAL_CANISTER_WASM)
            .with_raw_arg(payload.clone())
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't install universal canister: {err}"))?;

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
        upgrade_nns_canister_with_args_by_proposal(
            &can,
            &governance,
            &root,
            true,
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
            vec![],
        )
        .await;
        Self::from_canister_id(
            agent,
            Principal::try_from(nns_canister_id.get().to_vec()).unwrap(),
        )
    }

    pub async fn upgrade_with_args(
        runtime: &'a Runtime,
        agent: &'a Agent,
        nns_canister_id: &CanisterId,
        args: Vec<u8>,
    ) -> UniversalCanister<'a> {
        let can = Canister::new(runtime, *nns_canister_id);
        let governance = Canister::new(runtime, GOVERNANCE_CANISTER_ID);
        let root = Canister::new(runtime, ROOT_CANISTER_ID);
        upgrade_nns_canister_with_args_by_proposal(
            &can,
            &governance,
            &root,
            true,
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
            args,
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
    pub async fn try_store_to_stable(&self, offset: u32, msg: &[u8]) -> Result<(), AgentError> {
        self.agent
            .update(&self.canister_id, "update")
            .with_arg(Self::stable_writer(offset, msg))
            .call_and_wait()
            .await
            .map(|_| ())
    }

    /// Stores `msg` in stable memory starting at `offset` bytes.
    pub async fn store_to_stable(&self, offset: u32, msg: &[u8]) {
        self.agent
            .update(&self.canister_id, "update")
            .with_arg(Self::stable_writer(offset, msg))
            .call_and_wait()
            .await
            .unwrap_or_else(|err| panic!("Could not push message to stable: {err}"));
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
        self.read_stable(offset, len)
            .await
            .unwrap_or_else(|err| panic!("could not read message of len {len} from stable: {err}"))
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
        panic!("Could not read message from stable memory after {max_retries} retries.");
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
                cycles,
            )
            .build();

        self.agent
            .update(&self.canister_id, "update")
            .with_arg(universal_canister_payload)
            .call_and_wait()
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

    pub async fn replicated_query<P: Into<Vec<u8>>>(
        &self,
        payload: P,
    ) -> Result<Vec<u8>, AgentError> {
        self.agent
            .update(&self.canister_id, "query")
            .with_arg(payload.into())
            .call_and_wait()
            .await
    }

    pub async fn composite_query<P: Into<Vec<u8>>>(
        &self,
        payload: P,
    ) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query(&self.canister_id, "composite_query")
            .with_arg(payload.into())
            .call()
            .await
    }

    pub async fn update<P: Into<Vec<u8>>>(&self, payload: P) -> Result<Vec<u8>, AgentError> {
        self.agent
            .update(&self.canister_id, "update")
            .with_arg(payload.into())
            .call_and_wait()
            .await
    }
}

/// Provides an abstraction to the message canister.
#[derive(Clone)]
pub struct MessageCanister<'a> {
    agent: &'a Agent,
    canister_id: Principal,
}

impl<'a> MessageCanister<'a> {
    /// Initializes a [MessageCanister] using the provided [Agent].
    pub async fn new(agent: &'a Agent, effective_canister_id: PrincipalId) -> MessageCanister<'a> {
        Self::new_with_params_with_timeout(agent, effective_canister_id, None, None)
            .await
            .expect("Could not create message canister.")
    }

    pub async fn try_new(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
    ) -> Result<MessageCanister<'a>, String> {
        Self::new_with_params_with_timeout(agent, effective_canister_id, None, None).await
    }

    pub async fn new_with_retries(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        log: &slog::Logger,
        timeout: Duration,
        backoff: Duration,
    ) -> MessageCanister<'a> {
        retry_with_msg_async!(
            format!(
                "install MessageCanister {}",
                effective_canister_id.to_string()
            ),
            log,
            timeout,
            backoff,
            || async {
                Self::new_with_params_with_timeout(agent, effective_canister_id, None, None)
                    .await
                    .map_err(|e| anyhow!(e))
            }
        )
        .await
        .expect("Could not create message canister.")
    }

    async fn new_with_params_with_timeout(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
    ) -> Result<MessageCanister<'a>, String> {
        match timeout(
            CANISTER_CREATE_TIMEOUT,
            Self::new_with_params(agent, effective_canister_id, compute_allocation, cycles),
        )
        .await
        {
            Ok(Ok(canister)) => Ok(canister),
            Ok(Err(err)) => Err(format!("Could not create message canister: {err:?}")),
            Err(_elasped) => Err("Timeout while creating message canister".to_string()),
        }
    }

    async fn new_with_params(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
    ) -> Result<MessageCanister<'a>, String> {
        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .with_optional_compute_allocation(compute_allocation)
            .as_provisional_create_with_amount(cycles)
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't create canister with provisional API: {err}"))?
            .0;

        // Install the universal canister.
        mgr.install_code(&canister_id, &MESSAGE_CANISTER_WASM)
            .call_and_wait()
            .await
            .map_err(|err| format!("Couldn't install message canister: {err}"))?;
        Ok(Self { agent, canister_id })
    }

    pub async fn new_with_cycles<C: Into<u128>>(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        cycles: C,
    ) -> MessageCanister<'a> {
        Self::new_with_params(agent, effective_canister_id, None, Some(cycles.into()))
            .await
            .unwrap()
    }

    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    /// Initializes a message canister wrapper from a canister id. Does /NOT/
    /// perform any installation operation on the runtime.
    pub fn from_canister_id(agent: &'a Agent, canister_id: Principal) -> MessageCanister<'a> {
        Self { agent, canister_id }
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
        let params = ForwardParams {
            receiver: Principal::from_slice(receiver.as_slice()),
            method: method.to_string(),
            cycles: cycles.get(),
            payload,
        };
        let arg = Encode!(&params).unwrap();
        self.agent
            .update(&self.canister_id, "forward")
            .with_arg(arg)
            .call_and_wait()
            .await
            .map(|bytes| Decode!(&bytes, Vec<u8>).unwrap())
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

    pub async fn try_store_msg<P: Into<String>>(&self, msg: P) -> Result<(), AgentError> {
        self.agent
            .update(&self.canister_id, "store")
            .with_arg(Encode!(&msg.into()).unwrap())
            .call_and_wait()
            .await
            .map(|_| ())
    }

    pub async fn store_msg<P: Into<String>>(&self, msg: P) {
        self.try_store_msg(msg)
            .await
            .unwrap_or_else(|err| panic!("Could not store message: {err}"))
    }

    pub async fn try_read_msg(&self) -> Result<Option<String>, String> {
        self.agent
            .query(&self.canister_id, "read")
            .with_arg(Encode!(&()).unwrap())
            .call()
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| Decode!(r.as_slice(), Option<String>).map_err(|e| e.to_string()))
    }

    pub async fn read_msg(&self) -> Option<String> {
        self.try_read_msg()
            .await
            .unwrap_or_else(|err| panic!("Could not read message: {err}"))
    }
}

/// Provides an abstraction to the signer canister.
#[derive(Clone)]
pub struct SignerCanister<'a> {
    agent: &'a Agent,
    canister_id: Principal,
}

impl<'a> SignerCanister<'a> {
    /// Initializes a [SignerCanister] using the provided [Agent].
    pub async fn new(agent: &'a Agent, effective_canister_id: PrincipalId) -> SignerCanister<'a> {
        timeout(
            CANISTER_CREATE_TIMEOUT,
            Self::new_with_params(agent, effective_canister_id, None, None),
        )
        .await
        .expect("Timeout while creating signer canister")
    }

    pub async fn new_with_cycles<C: Into<u128>>(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        cycles: C,
    ) -> SignerCanister<'a> {
        Self::new_with_params(agent, effective_canister_id, None, Some(cycles.into())).await
    }

    async fn new_with_params(
        agent: &'a Agent,
        effective_canister_id: PrincipalId,
        compute_allocation: Option<u64>,
        cycles: Option<u128>,
    ) -> SignerCanister<'a> {
        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .with_optional_compute_allocation(compute_allocation)
            .as_provisional_create_with_amount(cycles)
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {err}"))
            .0;

        // Install the signer canister.
        mgr.install_code(&canister_id, &SIGNER_CANISTER_WASM)
            .call_and_wait()
            .await
            .unwrap_or_else(|err| panic!("Couldn't install signer canister: {err}"));

        Self { agent, canister_id }
    }

    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    pub async fn gen_ecdsa_sig(
        &self,
        params: GenEcdsaParams,
    ) -> Result<SignWithEcdsaResult, AgentError> {
        self.agent
            .update(&self.canister_id, "gen_ecdsa_sig")
            .with_arg(Encode!(&params).unwrap())
            .call_and_wait()
            .await
            .map(|bytes| Decode!(&bytes, SignWithEcdsaResult).unwrap())
    }

    pub async fn gen_schnorr_sig(
        &self,
        params: GenSchnorrParams,
    ) -> Result<SignWithSchnorrResult, AgentError> {
        self.agent
            .update(&self.canister_id, "gen_schnorr_sig")
            .with_arg(Encode!(&params).unwrap())
            .call_and_wait()
            .await
            .map(|bytes| Decode!(&bytes, SignWithSchnorrResult).unwrap())
    }

    pub async fn gen_vetkd_key(
        &self,
        params: GenVetkdParams,
    ) -> Result<VetKDDeriveKeyResult, AgentError> {
        self.agent
            .update(&self.canister_id, "gen_vetkd_key")
            .with_arg(Encode!(&params).unwrap())
            .call_and_wait()
            .await
            .map(|bytes| Decode!(&bytes, VetKDDeriveKeyResult).unwrap())
    }
}

/// Initializes an `Agent` using the provided URL.
/// The root key is fetched as part of the initialization in order
/// to validate certificates from the replica.
pub async fn assert_create_agent(url: &str) -> Agent {
    let start = Instant::now();
    while start.elapsed() < READY_WAIT_TIMEOUT {
        if let Ok(v) = create_agent(url).await {
            return v;
        }
        tokio::time::sleep(RETRY_BACKOFF).await;
    }

    create_agent(url)
        .await
        .unwrap_or_else(|err| panic!("Failed to create agent for {url}: {err:?}"))
}

/// Initializes an `Agent` using the provided URL and identity.
pub async fn assert_create_agent_with_identity(
    url: &str,
    identity: impl Identity + Clone + 'static,
) -> Agent {
    let start = Instant::now();
    while start.elapsed() < READY_WAIT_TIMEOUT {
        if let Ok(v) = agent_with_identity(url, identity.clone()).await {
            return v;
        }
        tokio::time::sleep(RETRY_BACKOFF).await;
    }

    agent_with_identity(url, identity)
        .await
        .unwrap_or_else(|err| panic!("Failed to create agent for {url}: {err:?}"))
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
    let builder = reqwest::Client::builder()
        .timeout(AGENT_REQUEST_TIMEOUT)
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true);

    let builder = match (
        addr_mapping,
        reqwest::Url::parse(url).as_ref().map(|u| u.domain()),
    ) {
        (Some(addr_mapping), Ok(Some(domain))) => builder.resolve(domain, (addr_mapping, 0).into()),
        _ => builder,
    };
    let client = builder.build().map_err(AgentError::TransportError)?;
    agent_with_client_identity(url, client, identity).await
}

pub async fn agent_with_client_identity(
    url: &str,
    client: reqwest::Client,
    identity: impl Identity + 'static,
) -> Result<Agent, AgentError> {
    let a = Agent::builder()
        .with_url(url)
        .with_http_client(client)
        .with_identity(identity)
        // Setting a large polling time for the sake of long-running update calls.
        .with_max_polling_time(Duration::from_secs(3600))
        .with_max_concurrent_requests(MAX_CONCURRENT_REQUESTS)
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
        .with_ingress_expiry(MAX_INGRESS_TTL - std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    a.fetch_root_key().await?;
    Ok(a)
}

// Creates an identity to be used with `Agent`.
pub fn random_ed25519_identity() -> BasicIdentity {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    BasicIdentity::from_key_pair(
        ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
            .expect("Could not read the key pair."),
    )
}

pub fn get_nns_node(topo_snapshot: &TopologySnapshot) -> IcNodeSnapshot {
    let nns_node = topo_snapshot.root_subnet().nodes().next().unwrap();
    nns_node.await_status_is_healthy().unwrap();
    nns_node
}

pub fn get_app_subnet_and_node(
    topo_snapshot: &TopologySnapshot,
) -> (SubnetSnapshot, IcNodeSnapshot) {
    let app_subnet = topo_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");
    let app_node = app_subnet
        .nodes()
        .next()
        .expect("there is no application node");
    app_node.await_status_is_healthy().unwrap();
    (app_subnet, app_node)
}

// This indirectly asserts a non-zero finalization rate of the subnet:
// - We store a string in the memory by sending an `update` message to a canister
// - We retrieve the saved string by sending `query` message to a canister
pub async fn assert_subnet_can_make_progress(message: &[u8], node: &IcNodeSnapshot) {
    let agent = assert_create_agent(node.get_public_url().as_str()).await;
    let universal_canister = UniversalCanister::new(&agent, node.effective_canister_id()).await;
    universal_canister.store_to_stable(0, message).await;
    assert_eq!(
        universal_canister
            .try_read_stable(0, message.len() as u32)
            .await,
        message.to_vec()
    );
}

pub fn assert_reject<T: std::fmt::Debug>(res: Result<T, AgentError>, code: RejectCode) {
    match res {
        Ok(val) => panic!("Expected call to fail but it succeeded with {val:?}"),
        Err(agent_error) => match agent_error {
            AgentError::UncertifiedReject {
                reject:
                    RejectResponse {
                        reject_code,
                        reject_message,
                        ..
                    },
                ..
            } => assert_eq!(
                code, reject_code,
                "Expect code {code:?} did not match {reject_code:?}. Reject message: {reject_message}"
            ),
            AgentError::CertifiedReject {
                reject:
                    RejectResponse {
                        reject_code,
                        reject_message,
                        ..
                    },
                ..
            } => assert_eq!(
                code, reject_code,
                "Expect code {code:?} did not match {reject_code:?}. Reject message: {reject_message}"
            ),
            others => {
                panic!("Expected call to fail with a replica error but got {others:?} instead")
            }
        },
    }
}

pub fn assert_reject_msg<T: std::fmt::Debug>(
    res: Result<T, AgentError>,
    code: RejectCode,
    partial_message: &str,
) {
    match res {
        Ok(val) => panic!("Expected call to fail but it succeeded with {val:?}"),
        Err(agent_error) => match agent_error {
            AgentError::CertifiedReject {
                reject:
                    RejectResponse {
                        reject_code,
                        reject_message,
                        ..
                    },
                ..
            } => {
                assert_eq!(
                    code, reject_code,
                    "Expect code {code:?} did not match {reject_code:?}. Reject message: {reject_message}"
                );
                assert!(
                    reject_message.contains(partial_message),
                    "Actual reject message: {reject_message}"
                );
            }
            AgentError::UncertifiedReject {
                reject:
                    RejectResponse {
                        reject_code,
                        reject_message,
                        ..
                    },
                ..
            } => {
                assert_eq!(
                    code, reject_code,
                    "Expect code {code:?} did not match {reject_code:?}. Reject message: {reject_message}"
                );
                assert!(
                    reject_message.contains(partial_message),
                    "Actual reject message: {reject_message}"
                );
            }
            others => {
                panic!("Expected call to fail with a replica error but got {others:?} instead")
            }
        },
    }
}

#[derive(Copy, Clone, Debug)]
pub enum EndpointsStatus {
    AllHealthy,
    AllUnhealthy,
}

pub fn assert_nodes_health_statuses(
    log: slog::Logger,
    nodes: &[IcNodeSnapshot],
    status: EndpointsStatus,
) {
    let nodes_with_undesired_status = || {
        let health_statuses = nodes.iter().map(|n| (n, n.status_is_healthy()));
        match status {
            EndpointsStatus::AllHealthy => health_statuses
                .into_iter()
                .filter_map(|(n, s)| s.map_or(Some(n), |f| (!f).then_some(n)))
                .collect(),
            EndpointsStatus::AllUnhealthy => health_statuses
                .into_iter()
                .filter_map(|(n, s)| s.map_or(None, |f| f.then_some(n)))
                .collect(),
        }
    };

    retry_with_msg!(
        format!("check for desired health status {:?}", status),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            let nodes: Vec<&IcNodeSnapshot> = nodes_with_undesired_status();
            if nodes.is_empty() {
                Ok(())
            } else {
                let nodes_str = nodes.iter().map(|e|format!("[node_id={}, ip={}]", e.node_id, e.get_ip_addr())).join(",\n");
                let msg = format!("The following nodes have not reached the desired health statuses {status:?}:\n{nodes_str}");
                bail!(msg);
            }
        }
    ).unwrap_or_else(|err| panic!("Retry function failed within the timeout of {} sec, {err}", READY_WAIT_TIMEOUT.as_secs()));
}

/// Asserts that the response from an agent call is rejected by the replica
/// resulting in a [`AgentError::UncertifiedReject`], and an expected [`RejectCode`].
pub fn assert_http_submit_fails<Output>(
    result: Result<CallResponse<Output>, AgentError>,
    expected_reject_code: RejectCode,
) where
    Output: std::fmt::Debug,
{
    match result {
        Ok(val) => panic!("Expected call to fail but it succeeded with {val:?}."),
        Err(agent_error) => match agent_error {
            AgentError::UncertifiedReject {
                reject: RejectResponse { reject_code, .. },
                ..
            } => assert_eq!(
                expected_reject_code, reject_code,
                "Unexpected reject_code: `{reject_code:?}`."
            ),
            others => panic!(
                "Expected agent call to replica to fail with AgentError::UncertifiedReject, but got {others:?} instead."
            ),
        },
    }
}

pub async fn create_and_install(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    canister_wasm: &[u8],
) -> Principal {
    // Initialize the canister with a healthy amount of cycles.
    create_and_install_with_cycles(
        agent,
        effective_canister_id,
        canister_wasm,
        CYCLES_LIMIT_PER_CANISTER,
    )
    .await
}

pub async fn create_canister(agent: &Agent, effective_canister_id: PrincipalId) -> Principal {
    create_canister_with_cycles(agent, effective_canister_id, CYCLES_LIMIT_PER_CANISTER).await
}

pub async fn create_canister_with_cycles(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    amount: Cycles,
) -> Principal {
    let mgr = ManagementCanister::create(agent);
    mgr.create_canister()
        .as_provisional_create_with_amount(Some(amount.into()))
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {err}"))
        .0
}

pub async fn create_canister_with_cycles_and_specified_id(
    agent: &Agent,
    specified_id: PrincipalId,
    amount: Cycles,
) -> Principal {
    let mgr = ManagementCanister::create(agent);
    mgr.create_canister()
        .as_provisional_create_with_amount(Some(amount.into()))
        .as_provisional_create_with_specified_id(specified_id.into())
        .call_and_wait()
        .await
        .unwrap_or_else(|err| panic!("Couldn't create canister with provisional API: {err}"))
        .0
}

pub async fn install_canister(
    agent: &Agent,
    canister_id: Principal,
    canister_wasm: &[u8],
    arg: Vec<u8>,
) {
    let mgr = ManagementCanister::create(agent);
    mgr.install_code(&canister_id, canister_wasm)
        .with_raw_arg(arg)
        .call_and_wait()
        .await
        .unwrap_or_else(|err| panic!("Couldn't install canister: {err}"));
}

pub async fn create_and_install_with_cycles(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    canister_wasm: &[u8],
    amount: Cycles,
) -> Principal {
    let canister_id = create_canister_with_cycles(agent, effective_canister_id, amount).await;
    install_canister(agent, canister_id, canister_wasm, vec![]).await;
    canister_id
}

pub async fn create_and_install_with_cycles_and_specified_id(
    agent: &Agent,
    specified_id: PrincipalId,
    canister_wasm: &[u8],
    amount: Cycles,
) -> Principal {
    let canister_id =
        create_canister_with_cycles_and_specified_id(agent, specified_id, amount).await;
    install_canister(agent, canister_id, canister_wasm, vec![]).await;
    canister_id
}

pub fn assert_balance_equals(expected: Cycles, actual: Cycles, epsilon: Cycles) {
    // Tolerate both positive and negative difference. Assumes no u64 overflows.
    assert!(
        expected < actual + epsilon && actual < expected + epsilon,
        "assert_balance_equals: expected {expected} actual {actual} epsilon {epsilon}"
    );
}

pub async fn get_balance(canister_id: &Principal, agent: &Agent) -> u128 {
    let mgr = ManagementCanister::create(agent);
    let canister_status = mgr
        .canister_status(canister_id)
        .call_and_wait()
        .await
        .unwrap_or_else(|err| panic!("Could not get canister status: {err}"))
        .0;
    u128::try_from(canister_status.cycles.0).unwrap()
}

pub async fn set_controller(
    controllee: &Principal,
    controller: &Principal,
    controllee_agent: &Agent,
) {
    let mgr = ManagementCanister::create(controllee_agent);
    mgr.update_settings(controllee)
        .with_controller(*controller)
        .call_and_wait()
        .await
        .unwrap_or_else(|err| panic!("Could not set controller: {err}"))
}

pub async fn deposit_cycles(
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
        .unwrap_or_else(|err| panic!("Failed to deposit to canister: {err}"));
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    // Try to get the current tokio runtime, otherwise create a new one
    match THandle::try_current() {
        Ok(h) => {
            let _ = h.enter();
            futures::executor::block_on(f)
        }
        Err(_) => {
            let rt = {
                let cpus = num_cpus::get();
                let workers = std::cmp::min(MAX_RUNTIME_THREADS, cpus);
                let blocking_threads = std::cmp::min(MAX_RUNTIME_BLOCKING_THREADS, cpus);
                Builder::new_multi_thread()
                    .worker_threads(workers)
                    .max_blocking_threads(blocking_threads)
                    .enable_all()
                    .build()
            }
            .unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
            rt.block_on(f)
        }
    }
}

pub async fn create_canister_via_canister(
    wallet_canister: &UniversalCanister<'_>,
) -> Result<Principal, AgentError> {
    create_canister_via_canister_with_cycles(wallet_canister, Cycles::new(2_000_000_000_000)).await
}

pub async fn create_canister_via_canister_with_cycles(
    wallet_canister: &UniversalCanister<'_>,
    cycles: Cycles,
) -> Result<Principal, AgentError> {
    wallet_canister
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "create_canister",
            EmptyBlob.encode(),
            cycles,
        )
        .await
        .map(|res| {
            Decode!(res.as_slice(), CreateCanisterResult)
                .unwrap()
                .canister_id
        })
}

pub async fn get_balance_via_canister(
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
            Decode!(res.as_slice(), CanisterStatusResultV2)
                .unwrap()
                .cycles()
                .into()
        })
        .unwrap()
}

pub async fn get_icp_balance(
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
        .map(tokens_from_proto)
}

pub async fn transact_icp_subaccount(
    log: &slog::Logger,
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
    info!(log, "send {:?}", args);
    let reply = sender
        .0
        .forward_to(
            &Principal::try_from(ledger.canister_id().get().to_vec()).unwrap(),
            "send_pb",
            to_arg(args),
        )
        .await
        .map_err(|e| format!("{e:?}"))?;

    let decoded: u64 = ProtoBuf::from_bytes(reply).map(|ProtoBuf(c)| c)?;
    info!(log, "decoded result is {:?}", decoded);

    get_icp_balance(
        ledger,
        &CanisterId::try_from(recipient.0.canister_id().as_slice()).unwrap(),
        recipient.1,
    )
    .await
}

pub async fn transact_icp(
    log: &slog::Logger,
    ledger: &Canister<'_>,
    sender: &UniversalCanister<'_>,
    amount: u64,
    recipient: &UniversalCanister<'_>,
) -> Result<Tokens, String> {
    transact_icp_subaccount(log, ledger, (sender, None), amount, (recipient, None)).await
}

pub fn to_principal_id(principal: &Principal) -> PrincipalId {
    PrincipalId::try_from(principal.as_slice()).unwrap()
}

pub async fn agent_observes_canister_module(agent: &Agent, canister_id: &Principal) -> bool {
    ManagementCanister::create(agent)
        .canister_status(canister_id)
        .call_and_wait()
        .await
        .is_ok_and(|s| s.0.module_hash.is_some())
}

pub async fn assert_canister_counter_with_retries(
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
            .with_arg(payload.clone())
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
        "Minimum expected counter value {min_expected_count} on counter canister was not observed after {max_retries} retries."
    );
}

/// Converts Canister id into an escaped byte string
pub fn escape_for_wat(id: &Principal) -> String {
    // Quoting from
    // https://webassembly.github.io/spec/core/text/values.html#text-string:
    //
    // "Strings [...] can represent both textual and binary data" and
    //
    // "hexadecimal escape sequences ‘∖ℎℎ’, [...] represent raw bytes of the
    // respective value".
    id.as_slice().iter().fold(String::new(), |mut res, b| {
        res.push_str(&format!("\\{b:02x}"));
        res
    })
}

pub fn get_config() -> ConfigOptional {
    let template = config::guestos::generate_ic_config::IcConfigTemplate {
        ipv6_address: "::".to_string(),
        ipv6_prefix: "::/64".to_string(),
        ipv4_address: "".to_string(),
        ipv4_gateway: "".to_string(),
        nns_urls: "http://www.fakeurl.com/".to_string(),
        backup_retention_time_secs: "0".to_string(),
        backup_purging_interval_secs: "0".to_string(),
        query_stats_epoch_length: "600".to_string(),
        jaeger_addr: "".to_string(),
        domain_name: "".to_string(),
        node_reward_type: "".to_string(),
        malicious_behavior: "null".to_string(),
        enable_beta_registration_feature: false,
    };

    let ic_json = config::guestos::generate_ic_config::render_ic_config(template)
        .expect("Failed to render config template");
    ConfigSource::Literal(ic_json)
        .load()
        .expect("Failed to parse dummy config")
}

/// A stream of logs from one or multiple nodes
pub struct LogStream {
    nodes: Vec<(IcNodeSnapshot, Lines<BufReader<TcpStream>>)>,
}

impl LogStream {
    /// Open a new [`LogStream`] on the nodes
    pub async fn open(nodes: impl Iterator<Item = IcNodeSnapshot>) -> std::io::Result<Self> {
        let addrs = nodes
            .map(|node| {
                let addr = match node.get_ip_addr() {
                    IpAddr::V6(x) => x,
                    IpAddr::V4(_ip) => panic!(),
                };
                Self::open_stream(addr).map(|result| result.map(|ep| (node, ep)))
            })
            .collect::<Vec<_>>();

        let nodes = try_join_all(addrs).await?;
        Ok(Self { nodes })
    }

    /// Read the next line of the logs
    pub async fn read(&mut self) -> std::io::Result<Option<(IcNodeSnapshot, String)>> {
        select_all(self.nodes.iter_mut().map(|(node, ep)| {
            Box::pin(ep.next_line().map(move |result| {
                result.map(|maybe_line| maybe_line.map(|line| (node.clone(), line)))
            }))
        }))
        .await
        .0
    }

    /// Wait for a specific predicate to be true before continuing
    pub async fn wait_until<P>(&mut self, predicate: P) -> std::io::Result<()>
    where
        P: Fn(&IcNodeSnapshot, &str) -> bool,
    {
        self.find(predicate).await.map(|_| ())
    }

    /// Find and return the first log line that satisfies the given predicate
    pub async fn find<P>(&mut self, predicate: P) -> std::io::Result<(IcNodeSnapshot, String)>
    where
        P: Fn(&IcNodeSnapshot, &str) -> bool,
    {
        while let Some((node, line)) = self.read().await? {
            if predicate(&node, &line) {
                return Ok((node, line));
            }
        }

        // NOTE: We should never reach the end of the log stream while waiting for a log line
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Log stream ended unexpectedly",
        ))
    }

    /// Open a stream the the node specified by the [`Ipv6Addr`]
    async fn open_stream(ip_addr: Ipv6Addr) -> std::io::Result<Lines<BufReader<TcpStream>>> {
        let socket_addr: SocketAddr = SocketAddr::V6(SocketAddrV6::new(ip_addr, 19531, 0, 0));
        let socket = TcpSocket::new_v6()?;
        let mut stream = socket.connect(socket_addr).await?;

        // Use plaintext instead of json, because some messages are too large for the journal json serializer
        stream
            .write_all(
                format!("GET /entries?follow HTTP/1.1\r\nHost:{ip_addr}:19531\r\n\r\n").as_bytes(),
            )
            .await?;

        let bf = BufReader::new(stream);
        Ok(bf.lines())
    }
}

/// Tool to fetch metrics from a set of nodes.
///
/// Can be useful if waiting for a specific condition of a metric to become true.
pub struct MetricsFetcher {
    nodes: Vec<IcNodeSnapshot>,
    metrics: Vec<String>,
    port: u16,
}

impl MetricsFetcher {
    /// Create a new [`MetricsFetcher`]
    pub fn new(nodes: impl Iterator<Item = IcNodeSnapshot>, metrics: Vec<String>) -> Self {
        Self::new_with_port(nodes, metrics, 9090)
    }

    /// Create a new [`MetricsFetcher`] for a specific port
    pub fn new_with_port(
        nodes: impl Iterator<Item = IcNodeSnapshot>,
        metrics: Vec<String>,
        port: u16,
    ) -> Self {
        Self {
            nodes: nodes.collect(),
            metrics,
            port,
        }
    }

    /// Fetch the metrics
    pub async fn fetch<T>(&self) -> reqwest::Result<BTreeMap<String, Vec<T>>>
    where
        T: Copy + Debug + std::str::FromStr,
    {
        // Fetch the metrics from the nodes in parallel and collect into a result
        let metrics = join_all(
            self.nodes
                .iter()
                .map(|node| Box::pin(self.fetch_from_node::<T>(node.get_ip_addr()))),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<BTreeMap<String, T>>, reqwest::Error>>()?;

        // Accumulate results into a single BTreeMap
        let mut results = BTreeMap::new();
        for metric in metrics {
            for (metric_name, val) in metric.into_iter() {
                results
                    .entry(metric_name)
                    .and_modify(|entry: &mut Vec<T>| entry.push(val))
                    .or_insert_with(|| vec![val]);
            }
        }

        Ok(results)
    }

    /// Fetch metrics from a single node
    async fn fetch_from_node<T>(&self, ip_addr: IpAddr) -> reqwest::Result<BTreeMap<String, T>>
    where
        T: Copy + Debug + std::str::FromStr,
    {
        let ip_addr = match ip_addr {
            IpAddr::V4(_) => panic!("Ipv4 addresses not supported"),
            IpAddr::V6(ipv6_addr) => ipv6_addr,
        };

        let socket_addr: SocketAddr = SocketAddr::V6(SocketAddrV6::new(ip_addr, self.port, 0, 0));
        let url = format!("http://{socket_addr}");
        let response = reqwest::get(url).await?.text().await?;

        // Filter out only lines that contain metrics we are interested in
        let mut result = BTreeMap::new();
        for line in response.split('\n') {
            // Skip the comment lines
            if line.starts_with('#') {
                continue;
            }

            if self
                .metrics
                .iter()
                .any(|metric_name| line.starts_with(metric_name))
            {
                let metric = line.split(' ').collect::<Vec<_>>();
                assert_eq!(metric.len(), 2);

                let val = match metric[1].parse::<T>() {
                    Ok(val) => val,
                    Err(_) => panic!("Failed to parse metric"),
                };
                result.insert(metric[0].to_string(), val);
            }
        }
        Ok(result)
    }
}

/// Assert that all malicious nodes in a topology produced log that signals malicious behavior.
/// For every node, the log is searched until any of the given substrings is found, or timeout is reached.
/// Use this function at the end of malicious node tests, when all logs are present already.
pub fn assert_malicious_from_topo(topology: &TopologySnapshot, malicious_signals: Vec<&str>) {
    let malicious_nodes = topology
        .subnets()
        .flat_map(|x| x.nodes())
        .filter(|n| n.is_malicious());
    assert_malicious(malicious_nodes, malicious_signals);
}

/// Assert that all nodes of the given set produced log that signals malicious behavior.
/// For every node, the log is searched until any of the given substrings is found, or timeout is reached.
/// Use this function at the end of malicious node tests, when all logs are present already.
pub fn assert_malicious(
    malicious_nodes: impl Iterator<Item = IcNodeSnapshot>,
    malicious_signals: Vec<&str>,
) {
    block_on(async {
        // This should produce a result quickly, because all the logs are already present on the remote.
        // But the logstream does not terminate, so if a malicious signal is missing, we stop the Future after a while and fail.
        tokio::time::timeout(
            Duration::from_secs(30),
            assert_nodes_malicious_parallel(malicious_nodes, malicious_signals),
        )
        .await
        .expect("Timed out while waiting for malicious logs")
        .expect("Not all malicious nodes produced logs containing the malicious signal.");
    })
}

/// Malicious node logs have to be checked individually, because all nodes have to signal malice.
async fn assert_nodes_malicious_parallel(
    nodes: impl Iterator<Item = IcNodeSnapshot>,
    signals: Vec<&str>,
) -> Result<(), &str> {
    let mut futures = vec![];
    for node in nodes {
        futures.push(async {
            let mut stream = LogStream::open(vec![node].into_iter())
                .await
                .expect("Failed to open LogStream to malicious node");
            stream
                .wait_until(|_, line| signals.iter().any(|x| line.contains(x)))
                .await
        });
    }
    if join_all(futures).await.iter().all(|x| x.is_ok()) {
        Ok(())
    } else {
        Err("Not all malicious nodes produced logs containing the malicious signal.")
    }
}

/// Assert that a node produced log that signals malicious behavior.
pub async fn assert_node_malicious(node: IcNodeSnapshot, malicious_signals: Vec<&str>) {
    LogStream::open(vec![node].into_iter())
        .await
        .expect("Failed to open LogStream to malicious node")
        .wait_until(|_, line| malicious_signals.iter().any(|x| line.contains(x)))
        .await
        .expect("Node did not have malicious log.")
}

pub fn spawn_round_robin_workload_engine(
    log: slog::Logger,
    requests: Vec<GenericRequest>,
    agents: Vec<Agent>,
    rps: usize,
    duration: Duration,
    requests_dispatch_extra_timeout: Duration,
    requests_duration_categorizations: Vec<Duration>,
) -> std::thread::JoinHandle<LoadTestMetrics> {
    let agents: Vec<CanisterAgent> = agents.into_iter().map(CanisterAgent::from).collect();
    std::thread::spawn(move || {
        let generator = move |idx: usize| {
            // Round Robin distribution over both requests and agents.
            let request = requests[idx % requests.len()].clone();
            let agent = agents[idx % agents.len()].clone();
            async move {
                agent
                    .call(&request)
                    .await
                    .map(|_| ()) // drop non-error responses
                    .into_test_outcome()
            }
        };
        // Don't log intermediate metrics during workload execution.
        let log_null = slog::Logger::root(slog::Discard, slog::o!());
        let aggregator = LoadTestMetrics::new(log_null)
            .with_requests_duration_categorizations(requests_duration_categorizations);
        let engine = Engine::new(log, generator, rps as f64, duration)
            .increase_dispatch_timeout(requests_dispatch_extra_timeout);
        block_on(engine.execute(aggregator, LoadTestMetrics::aggregator_fn))
            .expect("Execution of the workload failed.")
    })
}

/// Divides `dividend` into `divisor` "perfectly" (with zero remainder) or returns
/// an error.
pub fn divide_perfectly(
    field_name: &str,
    dividend: u64,
    divisor: u64,
) -> Result<u64, anyhow::Error> {
    match dividend.checked_rem(divisor) {
        None => bail!(
            "Attempted to divide by zero while validating {}. \
                 (This is likely due to an internal bug.)",
            field_name,
        ),

        Some(0) => Ok(dividend.saturating_div(divisor)),

        Some(remainder) => {
            assert_ne!(remainder, 0);
            bail!(
                "{} is supposed to contain a value that is evenly divisible by {}, \
                 but it contains {}, which leaves a remainder of {}.",
                field_name,
                divisor,
                dividend,
                remainder,
            )
        }
    }
}

pub fn add_box_drawing_left_border(s: String) -> String {
    let mut result = String::new();
    let lines = s.lines().map(|l| l.to_string()).collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            result.push_str("╭ ");
        } else {
            result.push('\n');
            if index != lines.len() - 1 {
                result.push_str("│ ");
            } else {
                result.push_str("╰ ");
            }
        }
        result.push_str(line);
    }
    result
}

pub fn pad_all_lines_but_first(s: String, padding: usize) -> String {
    let mut result = String::new();
    for (index, line) in s.lines().enumerate() {
        if index != 0 {
            result.push('\n');
            result.push_str(&" ".repeat(padding));
        }
        result.push_str(line);
    }
    result
}

pub fn create_service_nervous_system_into_params(
    create_service_nervous_system: CreateServiceNervousSystem,
    swap_approved_timestamp_seconds: u64,
) -> Result<Params, String> {
    let SwapParameters {
        minimum_participants,
        minimum_icp,
        maximum_icp,
        minimum_direct_participation_icp,
        maximum_direct_participation_icp,
        minimum_participant_icp,
        maximum_participant_icp,
        neuron_basket_construction_parameters,
        confirmation_text: _,
        restricted_countries: _,
        start_time,
        duration,
        neurons_fund_investment_icp: _,
        neurons_fund_participation: _,
    } = create_service_nervous_system
        .swap_parameters
        .clone()
        .ok_or("`swap_parameters` should not be None`")?;

    let neuron_basket_construction_parameters: NeuronBasketConstructionParameters =
        neuron_basket_construction_parameters
            .map(|neuron_basket_construction_params| {
                let GovApiNeuronBasketConstructionParameters {
                    count,
                    dissolve_delay_interval,
                } = neuron_basket_construction_params;
                Ok::<NeuronBasketConstructionParameters, String>(
                    NeuronBasketConstructionParameters {
                        count: count.ok_or("`count` should not be None".to_string())?,
                        dissolve_delay_interval_seconds: dissolve_delay_interval
                            .ok_or("`dissolve_delay_interval` should not be None".to_string())?
                            .seconds
                            .ok_or("`seconds` should not be None".to_string())?,
                    },
                )
            })
            .expect("`neuron_basket_construction_parameters` should not be None")?;

    let start_time = start_time.unwrap_or_else(|| GlobalTimeOfDay::from_hh_mm(12, 0).unwrap()); // Just use a random start time if it's not
    let duration = duration.ok_or("`duration` should not be None")?;
    let (swap_start_timestamp_seconds, swap_due_timestamp_seconds) =
        CreateServiceNervousSystem::swap_start_and_due_timestamps(
            start_time,
            duration,
            swap_approved_timestamp_seconds,
        )?;

    let params = Params {
        min_participants: minimum_participants.ok_or("`minimum_participants` should not be None")?
            as u32,
        min_icp_e8s: minimum_icp
            .ok_or("`minimum_icp` should not be None")?
            .e8s
            .ok_or("`e8`s should not be None")?,
        max_icp_e8s: maximum_icp
            .ok_or("`maximum_icp` should not be None")?
            .e8s
            .ok_or("`e8`s should not be None")?,
        min_direct_participation_icp_e8s: minimum_direct_participation_icp
            .and_then(|minimum_direct_participation_icp| minimum_direct_participation_icp.e8s),
        max_direct_participation_icp_e8s: maximum_direct_participation_icp
            .and_then(|maximum_direct_participation_icp| maximum_direct_participation_icp.e8s),
        min_participant_icp_e8s: minimum_participant_icp
            .ok_or("`minimum_participant_icp` should not be None")?
            .e8s
            .ok_or("`e8`s should not be None")?,
        max_participant_icp_e8s: maximum_participant_icp
            .ok_or("`maximum_participant_icp` should not be None")?
            .e8s
            .ok_or("`e8`s should not be None")?,
        swap_due_timestamp_seconds,
        sns_token_e8s: create_service_nervous_system
            .sns_token_e8s()
            .ok_or("`swap_distribution.total.e8s` should not be None")?,
        neuron_basket_construction_parameters: Some(neuron_basket_construction_parameters),
        sale_delay_seconds: Some(
            swap_start_timestamp_seconds.saturating_sub(swap_approved_timestamp_seconds),
        ),
    };
    Ok(params)
}

pub fn sign_query(content: &HttpQueryContent, identity: &impl Identity) -> Signature {
    let HttpQueryContent::Query { query: content } = content;
    let msg = EnvelopeContent::Query {
        ingress_expiry: content.ingress_expiry,
        sender: Principal::from_slice(&content.sender),
        canister_id: Principal::from_slice(&content.canister_id),
        method_name: content.method_name.clone(),
        arg: content.arg.0.clone(),
        nonce: None,
    };
    identity.sign(&msg).unwrap()
}

pub fn sign_update(content: &HttpCallContent, identity: &impl Identity) -> Signature {
    let HttpCallContent::Call { update: content } = content;
    let msg = EnvelopeContent::Call {
        ingress_expiry: content.ingress_expiry,
        sender: Principal::from_slice(&content.sender),
        canister_id: Principal::from_slice(&content.canister_id),
        method_name: content.method_name.clone(),
        arg: content.arg.0.clone(),
        nonce: content.nonce.clone().map(|blob| blob.0),
    };
    identity.sign(&msg).unwrap()
}

pub fn sign_read_state(content: &HttpReadStateContent, identity: &impl Identity) -> Signature {
    use ic_agent::hash_tree::Label;
    use std::ops::Deref;
    let HttpReadStateContent::ReadState {
        read_state: content,
    } = content;
    let paths = content
        .paths
        .iter()
        .map(|path| {
            path.deref()
                .iter()
                .map(|label| Label::from_bytes(label.as_bytes()))
                .collect::<Vec<_>>()
        })
        .collect();
    let msg = EnvelopeContent::ReadState {
        paths,
        ingress_expiry: content.ingress_expiry,
        sender: Principal::from_slice(&content.sender),
    };
    identity.sign(&msg).unwrap()
}

pub fn expiry_time() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(4 * 60)
}

/// Time the duration of the given closure and log it.
pub fn timeit<F, R>(log: Logger, description: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f(); // Run the closure
    let duration = start.elapsed();
    info!(log, "Executed '{}' in: {:?}", description, duration);
    result
}
