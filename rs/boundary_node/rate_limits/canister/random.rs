use ic_cdk::api::time;
use rand_chacha::ChaCha20Rng;
#[cfg(target_family = "wasm")]
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use std::cell::RefCell;

thread_local! {
  static RNG: RefCell<ChaCha20Rng> = {
    let mut seed = [42; 32];
    seed[..8].copy_from_slice(&time().to_le_bytes());
    RefCell::new(ChaCha20Rng::from_seed(seed))
  };
}

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
/// A getrandom implementation that works in the IC.
pub fn custom_getrandom_bytes_impl(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        rng.fill_bytes(dest);
    });

    Ok(())
}

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(custom_getrandom_bytes_impl);
