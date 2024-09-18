use async_trait::async_trait;
use candid::{CandidType, Decode, Encode, Error};
use ic_base_types::CanisterId;
use ic_nervous_system_clients::update_settings::CanisterSettings;
use ic_sns_governance::{
    pb::sns_root_types::{RegisterDappCanistersRequest, SetDappControllersRequest},
    types::{Environment, HeapGrowthPotential},
};
use rand::{rngs::StdRng, RngCore};
use std::sync::{Arc, Mutex};

type CanisterCallResult = Result<Vec<u8>, (Option<i32>, String)>;

#[derive(PartialEq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CanisterCallRequest {
    RegisterDappCanisters(RegisterDappCanistersRequest),
    SetDappControllers(SetDappControllersRequest),
    UpdateSettings(CanisterSettings),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CanisterCallReply {
    Response(Vec<u8>),
    Panic((Option<i32>, String)),
}

impl<T> From<T> for CanisterCallReply
where
    T: CandidType,
{
    fn from(t: T) -> Self {
        CanisterCallReply::Response(Encode!(&t).unwrap())
    }
}

/// The EnvironmentFixtureState captures the state of a given EnvironmentFixture instance.
/// This state is used to respond to environment calls from Governance in a deterministic way.
pub struct EnvironmentFixtureState {
    pub now: u64,
    pub rng: StdRng,
    pub canister_id: CanisterId,
    pub observed_canister_calls: Vec<CanisterCallRequest>,
    pub mocked_canister_replies: Vec<CanisterCallReply>,
}

/// The EnvironmentFixture allows for independent testing of Environment functionality.
#[derive(Clone)]
pub struct EnvironmentFixture {
    pub environment_fixture_state: Arc<Mutex<EnvironmentFixtureState>>,
}

impl EnvironmentFixture {
    pub fn new(state: EnvironmentFixtureState) -> Self {
        EnvironmentFixture {
            environment_fixture_state: Arc::new(Mutex::new(state)),
        }
    }

    /// Decode an Encoded inter-canister-call. Match on the method name to determine
    /// the correct structure to use in decoding.
    fn decode_canister_call(
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<CanisterCallRequest, Error> {
        let canister_call_request = match method_name {
            "register_dapp_canisters" => CanisterCallRequest::RegisterDappCanisters(Decode!(
                &args,
                RegisterDappCanistersRequest
            )?),
            "set_dapp_controllers" => {
                CanisterCallRequest::SetDappControllers(Decode!(&args, SetDappControllersRequest)?)
            }
            "update_settings" => {
                CanisterCallRequest::UpdateSettings(Decode!(&args, CanisterSettings)?)
            }
            _ => panic!("Unsupported method_name `{method_name}` in decode_canister_call."),
        };

        Ok(canister_call_request)
    }

    /// Encode a CanisterCallReply such that the expected inter-canister-call format
    /// is preserved.
    fn encode_canister_call(reply: CanisterCallReply) -> Result<CanisterCallResult, Error> {
        let encoded_canister_call_reply = match reply {
            // Special case to mock panics or replica failures.
            CanisterCallReply::Panic(err) => Err(err),
            CanisterCallReply::Response(r) => Ok(r),
        };

        Ok(encoded_canister_call_reply)
    }

    /// Pushes a reply to the mocked_canister_replies stack. The reply at the
    /// top of the stack will be popped and returned each time call_canister is
    /// invoked.
    /// If you wish to mock a panic, use `push_mocked_canister_panic` instead.
    pub fn push_mocked_canister_reply(&mut self, call: impl Into<CanisterCallReply>) {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .mocked_canister_replies
            .push(call.into())
    }

    /// Pushes a panic message to the mocked_canister_replies stack. This will
    /// be returned to the invoker of `call_canister` as if the callee panicked.
    pub fn push_mocked_canister_panic(&mut self, message: &str) {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .mocked_canister_replies
            .push(CanisterCallReply::Panic((Some(0), message.to_string())))
    }

    pub fn pop_observed_canister_call(&mut self) -> CanisterCallRequest {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .observed_canister_calls
            .pop()
            .unwrap()
    }
}

#[async_trait]
impl Environment for EnvironmentFixture {
    fn now(&self) -> u64 {
        self.environment_fixture_state.try_lock().unwrap().now
    }

    fn random_u64(&mut self) -> u64 {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .rng
            .next_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .rng
            .fill_bytes(&mut bytes);
        bytes
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        let observed_canister_call = match Self::decode_canister_call(method_name, arg) {
            Ok(decoded_canister_call) => decoded_canister_call,
            Err(candid_error) => {
                panic!("call_canister failed due to candid decoding. Err: {candid_error:?}")
            }
        };

        println!(
            "Calling {canister_id:?} method `{method_name}` with request {observed_canister_call:?}"
        );

        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .observed_canister_calls
            .push(observed_canister_call);

        let encode_result = Self::encode_canister_call(
            self.environment_fixture_state
                .try_lock()
                .unwrap()
                .mocked_canister_replies
                .pop()
                .unwrap_or_else(|| panic!("Expected there to be a mocked canister reply on the stack for method `{method_name}`")),
        );

        match encode_result {
            Ok(encoded_canister_reply) => encoded_canister_reply,
            Err(candid_error) => panic!("call_canister failed due encoding. Err: {candid_error:?}"),
        }
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }

    fn canister_id(&self) -> CanisterId {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .canister_id
    }

    fn canister_version(&self) -> Option<u64> {
        None
    }
}
