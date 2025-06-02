use ic_cdk::api::time;
#[cfg(target_family = "wasm")]
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
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
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let slice = std::slice::from_raw_parts_mut(dest, len);
        rng.fill_bytes(slice);
    });

    Ok(())
}
