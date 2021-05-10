use rand::Rng;

#[derive(PartialEq, Eq)]
pub struct CallContextNonce {
    pub(crate) base: [u8; 32],
    pub(crate) offset: u64,
}

impl CallContextNonce {
    pub fn new(offset: u64) -> Self {
        let mut rng = rand::thread_rng();
        let base: [u8; 32] = rng.gen();
        Self { base, offset }
    }
}

pub fn session_to_string(base: [u8; 32], offset: u64) -> String {
    let base: String = base.iter().map(|a| a.to_string()).collect();
    let offset = offset.to_string();
    base + &offset
}
