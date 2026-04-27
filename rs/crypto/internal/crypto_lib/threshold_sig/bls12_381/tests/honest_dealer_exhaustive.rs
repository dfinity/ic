use ic_crypto_internal_bls12_381_type::{Gt, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::dlog_recovery::*;

// This takes ~40-50 seconds in release mode or ~hours in debug
#[test]
fn honest_dealer_search_works_exhaustive_test() {
    let search = HonestDealerDlogLookupTable::new();

    let mut accum = Gt::identity();

    let mut dlogs = vec![];
    let mut targets = vec![];
    for i in 0..=0xFFFF {
        dlogs.push(i);
        targets.push(accum.clone());
        accum += Gt::generator();
    }

    let recovered_dlogs = search.solve_several(&targets);

    assert_eq!(recovered_dlogs.len(), dlogs.len());

    for i in 0..dlogs.len() {
        assert_eq!(recovered_dlogs[i], Some(Scalar::from_usize(dlogs[i])));
    }
}
