use certificate_orchestrator_interface::Id;
use sha2::{Digest, Sha256};

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use tests::time;
    } else {
        use ic_cdk::api::time;
    }
}

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
            c.insert((), idx + 1);
            idx
        });

        let id_seed = self.id_seed.with(|s| s.borrow().get(&()).unwrap());

        let id = Sha256::digest(format!("{}{}{}", idx, id_seed, time()));
        hex::encode(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ID_COUNTER, ID_SEED};

    pub fn time() -> u64 {
        0
    }

    #[test]
    fn generate() {
        // Initialize ID seed
        ID_SEED.with(|s| s.borrow_mut().insert((), 0));

        let g = Generator::new(&ID_COUNTER, &ID_SEED);

        // Assumed to be sha256("000")
        assert_eq!(
            g.generate(),
            "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef"
        );

        // Assumed to be sha256("100") due to COUNTER_ID being incremented
        assert_eq!(
            g.generate(),
            "ad57366865126e55649ecb23ae1d48887544976efea46a48eb5d85a6eeb4d306"
        );
    }
}
