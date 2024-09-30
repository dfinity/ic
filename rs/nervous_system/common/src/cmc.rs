use async_trait::async_trait;
use mockall::automock;

/// A trait defining common patterns for accessing the CMC canister.
#[automock]
#[async_trait]
pub trait CMC: Send + Sync {
    /// Returns the current neuron maturity modulation.
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String>;
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
