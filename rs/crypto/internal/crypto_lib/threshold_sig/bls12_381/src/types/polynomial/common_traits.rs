//! Fr, provided indirectly by the pairing library, does not support zeroizing
//! with the Zeroize trait so we implement it here ourselves.

use super::*;

pub fn zeroize_fr(fr: &mut Scalar) {
    /*
    Safety of write_volatile requires that the destination be non-NULL
    and properly aligned. Both of these preconditions follow from fr
    being a valid reference.

    This write_volatile + compiler_fence approach is the same as used
    in the zeroize crate.
    */
    unsafe {
        std::ptr::write_volatile(fr, Scalar::zero());
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Zeroize for Polynomial {
    fn zeroize(&mut self) {
        #[cfg_attr(tarpaulin, skip)]
        for fr in self.coefficients.iter_mut() {
            zeroize_fr(fr);
        }
    }
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.zeroize();
    }
}
