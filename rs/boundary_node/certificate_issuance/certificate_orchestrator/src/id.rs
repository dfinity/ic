use certificate_orchestrator_interface::Id;
use ic_cdk::api::time;
use sha2::{Digest, Sha256};

use crate::{LocalRef, StableValue};

pub trait Generate {
    fn generate(&self) -> Id;
}

pub struct Generator {
    counter: LocalRef<StableValue<u128>>,
    id_seed: LocalRef<StableValue<u128>>,
}

impl Generator {
    pub fn new(counter: LocalRef<StableValue<u128>>, id_seed: LocalRef<StableValue<u128>>) -> Self {
        Self { counter, id_seed }
    }
}

impl Generate for Generator {
    fn generate(&self) -> Id {
        let idx = self.counter.with(|c| {
            let mut c = c.borrow_mut();
            let idx = c.get(&()).unwrap_or(0);
            c.insert((), idx + 1).unwrap();
            idx
        });

        let id_seed = self.id_seed.with(|s| s.borrow().get(&()).unwrap());

        let id = Sha256::digest(format!("{}{}{}", idx, id_seed, time()));
        hex::encode(id)
    }
}
