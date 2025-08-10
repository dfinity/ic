//! Utilities for testing BLS12-381 threshold signing and key generation.
use crate::ni_dkg::groth20_bls12_381::types::BTENodeBytes;
use ic_crypto_internal_seed::Seed;
use ic_types::NumberOfNodes;
use rand::seq::IteratorRandom;

#[cfg(test)]
mod tests;

/// Select `n` entries from a `list` in a randomized way, as determined by
/// `seed`.
pub fn select_n<T: Clone>(seed: Seed, n: NumberOfNodes, list: &[T]) -> Vec<Option<T>> {
    assert!(n.get() as usize <= list.len());
    let rng = &mut seed.into_rng();
    let mut ans: Vec<Option<T>> = vec![None; list.len()];
    for (index, element) in list
        .iter()
        .enumerate()
        .choose_multiple(rng, n.get() as usize)
    {
        ans[index] = Some(element.clone());
    }
    ans
}

/// Secret key serialisations, some malformed, some well formed.
pub fn malformed_secret_threshold_key_test_vectors() -> Vec<([u8; 32], bool, String)> {
    let max_value: [u8; 32] = [0xff; 32];
    let modulus: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];
    let modulus_minus_one: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];
    vec![
        (max_value, false, "Max value".to_string()),
        (modulus, false, "Modulus".to_string()),
        (modulus_minus_one, true, "Max legal".to_string()),
    ]
}

/// Check that components of a BTENodeBytes struct aren't logged
/// in a given debug string.
pub fn assert_bte_node_components_are_redacted(node: &BTENodeBytes, debug_str: &str) {
    let a_str = format!("{:?}", node.a);
    assert!(!debug_str.contains(&a_str));

    let b_str = format!("{:?}", node.b);
    assert!(!debug_str.contains(&b_str));

    let d_t_str = format!("{:?}", node.d_t);
    assert!(!debug_str.contains(&d_t_str));

    let d_h_str = format!("{:?}", node.d_h);
    assert!(!debug_str.contains(&d_h_str));

    let e_str = format!("{:?}", node.e);
    assert!(!debug_str.contains(&e_str));
}
