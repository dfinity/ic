use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_nervous_system_common::cmc::CMC;
use ic_nervous_system_runtime::Runtime;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use std::marker::PhantomData;

pub struct CMCCanister<Rt: Runtime> {
    canister_id: CanisterId,
    _phantom: PhantomData<Rt>,
}

impl<Rt: Runtime> CMCCanister<Rt> {
    pub fn new() -> Self {
        CMCCanister {
            canister_id: CYCLES_MINTING_CANISTER_ID,
            _phantom: PhantomData,
        }
    }
}

impl<Rt: Runtime> Default for CMCCanister<Rt> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<Rt: Runtime + Send + Sync> CMC for CMCCanister<Rt> {
    /// Returns the maturity_modulation from the CMC in basis points.
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        let result: Result<(Result<i32, String>,), (i32, String)> =
            Rt::call_with_cleanup(self.canister_id, "neuron_maturity_modulation", ()).await;
        match result {
            Ok(result) => result.0,
            Err(error) => Err(error.1),
        }
    }
}
