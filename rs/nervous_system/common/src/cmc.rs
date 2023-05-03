use async_trait::async_trait;
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;

/// A trait defining common patterns for accessing the CMC canister.
#[async_trait]
pub trait CMC: Send + Sync {
    /// Returns the current neuron maturity modulation.
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String>;
}

pub struct CMCCanister {
    canister_id: CanisterId,
}

impl CMCCanister {
    pub fn new() -> Self {
        CMCCanister {
            canister_id: CYCLES_MINTING_CANISTER_ID,
        }
    }
}

impl Default for CMCCanister {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CMC for CMCCanister {
    /// Returns the maturity_modulation from the CMC in basis points.
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        let result: Result<Result<i32, String>, (Option<i32>, String)> =
            dfn_core::api::call_with_cleanup(
                self.canister_id,
                "neuron_maturity_modulation",
                candid_one,
                (),
            )
            .await;
        match result {
            Ok(result) => result,
            Err(error) => Err(error.1),
        }
    }
}

pub struct FakeCmc {}

impl FakeCmc {
    pub fn new() -> Self {
        FakeCmc {}
    }
}

impl Default for FakeCmc {
    fn default() -> Self {
        FakeCmc::new()
    }
}

#[async_trait]
impl CMC for FakeCmc {
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        Ok(0)
    }
}
