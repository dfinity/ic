use crate::{
    governance::{Environment, Governance, HeapGrowthPotential, RandomnessGenerator, RngError},
    pb::v1::{GovernanceError, governance_error::ErrorType},
    proposals::execute_nns_function::ValidExecuteNnsFunction,
};

use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_nervous_system_canisters::cmc::CMCCanister;
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;
use ic_nervous_system_runtime::CdkRuntime;
use ic_nervous_system_runtime::Runtime;
use ic_nervous_system_time_helpers::now_seconds;
use ic_nns_common::types::ProposalId;
use ic_nns_constants::LEDGER_CANISTER_ID;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::sync::Arc;
#[cfg(any(test, feature = "test"))]
use std::sync::RwLock;

thread_local! {
    pub(crate) static GOVERNANCE: RefCell<Governance> = RefCell::new(Governance::new_uninitialized(
        Arc::new(CanisterEnv::new()),
        Arc::new(IcpLedgerCanister::<CdkRuntime>::new(LEDGER_CANISTER_ID)),
        Arc::new(CMCCanister::<CdkRuntime>::new()),
        Box::new(CanisterRandomnessGenerator::new()),
    ));
}
/*
Recommendations for Using `unsafe` in the Governance canister:

The state of governance is captured in a mutable static global variable to allow for
concurrent mutable access and modification of state in the NNS Governance canister. Due
to safety checks in Rust, accessing the static variable must be done in an unsafe block.
While this is generally an unsafe practice in normal Rust code, due to the message model of
the Internet Computer, only one instance of the state is ever accessed at once. The following
are best practices for making use of the unsafe block:

1. Initialization First:
    - Always ensure the global state (e.g., `GOVERNANCE`) has been initialized before access.
      Typically, this initialization occurs in `canister_init` or `canister_post_upgrade`.

2. Understanding
    - Lifetimes in Runtime Context: When working with asynchronous functions that use mutable
      references to Governance pay close attention to the different runtimes the code may run in:
        - In unit tests, all futures are immediately ready. Mutating a `'static` ref is still
          valid since futures resolve instantly, but is an abuse of the rules in Rust.
        - In mainnet, "self" refers to the `GOVERNANCE` static variable, which is initialized
          once in functions like `canister_init` or `canister_post_upgrade`.

3. Lifetime Assurances:
    - In a `Drop` implementation that takes mutable references of `self`, the scope of any
      `Governance` method ensures `&self` remains alive since Governance is always
      initialized immediately after an upgrade in the post upgrade hook. Additionally,
      since upgrades cannot happen during an asynchronous call (the upgrade waits for
      all open-call-contexts to be closed), Governance will never be un-initialized
      when an async method returns. De-referencing is acceptable in this context. For
      instance, it's always safe when a `LedgerUpdateLock` goes out of scope,
      but requires an `unsafe` block.

4. Safety Checks Inside Unsafe:
    - Although a block is marked `unsafe`, internal verifications are still essential. For
      instance, `unlock_neuron` within the `Drop` implementation of `LedgerUpdateLock`
      confirms the lock's existence despite being inside an unsafe context.

5. Modifying references across and await:
    - Since the CDK will put local variables on the stack, accessing a reference across an
      await is not advised. It is best practice to reacquire a reference to the state after
      an async call.
*/
/// Returns an immutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
pub fn governance() -> &'static Governance {
    unsafe { &*GOVERNANCE.with(|g| g.as_ptr()) }
}

/// Returns a mutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
pub fn governance_mut() -> &'static mut Governance {
    unsafe { &mut *GOVERNANCE.with(|g| g.as_ptr()) }
}

pub fn with_governance<R>(f: impl FnOnce(&Governance) -> R) -> R {
    GOVERNANCE.with(|g| f(&g.borrow()))
}

pub fn with_governance_mut<R>(f: impl FnOnce(&mut Governance) -> R) -> R {
    GOVERNANCE.with(|g| f(&mut g.borrow_mut()))
}

// Sets governance global state to the given object.
pub fn set_governance(gov: Governance) {
    GOVERNANCE.set(gov);

    governance()
        .validate()
        .expect("Error initializing the governance canister.");
}
#[cfg(any(test, not(target_arch = "wasm32")))]
pub fn set_governance_for_tests(gov: Governance) {
    GOVERNANCE.set(gov);
}

#[derive(Default)]
pub struct CanisterEnv {
    #[cfg(any(test, feature = "test"))]
    time_warp: RwLock<crate::governance::TimeWarp>,
}

impl CanisterEnv {
    pub fn new() -> Self {
        CanisterEnv {
            #[cfg(any(test, feature = "test"))]
            time_warp: RwLock::new(crate::governance::TimeWarp { delta_s: 0 }),
        }
    }
}

#[derive(Default)]
pub struct CanisterRandomnessGenerator {
    rng: Option<ChaCha20Rng>,
}

impl CanisterRandomnessGenerator {
    pub fn new() -> Self {
        CanisterRandomnessGenerator { rng: None }
    }
}

impl RandomnessGenerator for CanisterRandomnessGenerator {
    fn random_u64(&mut self) -> Result<u64, RngError> {
        match self.rng.as_mut() {
            Some(rand) => Ok(rand.next_u64()),
            None => Err(RngError::RngNotInitialized),
        }
    }

    fn random_byte_array(&mut self) -> Result<[u8; 32], RngError> {
        match self.rng.as_mut() {
            Some(rand) => {
                let mut bytes = [0u8; 32];
                rand.fill_bytes(&mut bytes);
                Ok(bytes)
            }
            None => Err(RngError::RngNotInitialized),
        }
    }

    fn seed_rng(&mut self, seed: [u8; 32]) {
        self.rng.replace(ChaCha20Rng::from_seed(seed));
    }

    fn get_rng_seed(&self) -> Option<[u8; 32]> {
        self.rng.as_ref().map(|rng| rng.get_seed())
    }
}

#[async_trait]
impl Environment for CanisterEnv {
    #[cfg(any(test, feature = "test"))]
    fn now(&self) -> u64 {
        self.time_warp.read().unwrap().apply(now_seconds())
    }

    #[cfg(not(any(test, feature = "test")))]
    fn now(&self) -> u64 {
        now_seconds()
    }

    #[cfg(any(test, feature = "test"))]
    fn set_time_warp(&self, new_time_warp: crate::governance::TimeWarp) {
        *self.time_warp.write().unwrap() = new_time_warp;
    }

    fn execute_nns_function(
        &self,
        proposal_id: u64,
        execute_nns_function: &ValidExecuteNnsFunction,
    ) -> Result<(), crate::pb::v1::GovernanceError> {
        let reply = move || {
            governance_mut().set_proposal_execution_status(proposal_id, Ok(()));
        };
        let reject = move |(code, msg): (i32, String)| {
            let mut msg = msg;
            // There's no guarantee that the reject response is a string of character, and
            // it can also be potential large. Propagating error information
            // here is on a best-effort basis.
            const MAX_REJECT_MSG_SIZE: usize = 10000;
            if msg.len() > MAX_REJECT_MSG_SIZE {
                msg = "(truncated error message) "
                    .to_string()
                    .chars()
                    .chain(
                        msg.char_indices()
                            .take_while(|(pos, _)| *pos < MAX_REJECT_MSG_SIZE)
                            .map(|(_, char)| char),
                    )
                    .collect();
            }

            governance_mut().set_proposal_execution_status(
                proposal_id,
                Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error executing ExecuteNnsFunction proposal. Error Code: {code}. Rejection message: {msg}"
                    ),
                )),
            );
        };
        let (canister_id, method) = execute_nns_function.nns_function.canister_and_function();
        let proposal_timestamp_seconds = governance()
            .get_proposal_data(ProposalId(proposal_id))
            .map(|data| data.proposal_timestamp_seconds)
            .ok_or(GovernanceError::new(ErrorType::PreconditionFailed))?;
        let encoded_request = execute_nns_function
            .re_encode_payload_to_target_canister(proposal_id, proposal_timestamp_seconds)?;

        ic_cdk::futures::spawn_017_compat(async move {
            match CdkRuntime::call_bytes_with_cleanup(canister_id, method, &encoded_request).await {
                Ok(_) => reply(),
                Err(e) => reject(e),
            }
        });

        Ok(())
    }

    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        CdkRuntime::call_bytes_with_cleanup(target, method_name, &request)
            .await
            .map_err(|(code, msg)| (Some(code), msg))
    }

    #[cfg(target_arch = "wasm32")]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        if core::arch::wasm32::memory_size(0)
            < crate::governance::HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES
        {
            HeapGrowthPotential::NoIssue
        } else {
            HeapGrowthPotential::LimitedAvailability
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!("CanisterEnv can only be used with wasm32 environment.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_time_warp() {
        let environment = CanisterEnv::new();

        let start = environment.now();
        environment.set_time_warp(crate::governance::TimeWarp { delta_s: 1_000 });
        let delta_s = environment.now() - start;

        assert!(delta_s >= 1000, "delta_s = {delta_s}");
        assert!(delta_s < 1005, "delta_s = {delta_s}");
    }
}
