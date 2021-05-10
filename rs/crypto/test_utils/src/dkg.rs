//! Utilities for testing Distributed Key Generation (DKG) code.
use ic_types::{Height, IDkgId, PrincipalId, SubnetId};
use rand::Rng;

/// Generate a random `IDkgId`.
///
/// Note: There is a proptest strategy for `IDkgId` which is useful in many
/// circumstances but cumbersome in others.  Please use the appropriate method
/// for each circumstance.
pub fn random_dkg_id<R: Rng>(rng: &mut R) -> IDkgId {
    let instance_id = Height::from(rng.gen::<u64>());
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    IDkgId {
        instance_id,
        subnet_id,
    }
}
