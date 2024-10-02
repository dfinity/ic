use ic_base_types::PrincipalId;
use rand_chacha::ChaCha8Rng;

pub(crate) struct GeneratorState {
    pub rng: Option<ChaCha8Rng>,
    pub ledger_principal: Option<PrincipalId>,
    pub index_principal: Option<PrincipalId>,
    pub index_wasm: Option<Vec<u8>>,
    pub worker_wasm: Option<Vec<u8>>,
}

impl GeneratorState {
    pub const fn new() -> GeneratorState {
        GeneratorState {
            rng: None,
            ledger_principal: None,
            index_principal: None,
            index_wasm: None,
            worker_wasm: None,
        }
    }
}
