// Clippy is, for a good reason, convinced that due to the following line in the
// `fuzz_mutator` expansion, its generated function `rust_fuzzer_custom_mutator` should also be
// marked unsafe. But since this is part of the fuzzer, let's just disable the corresponding lint.
// let $data: &mut [u8] = unsafe { std::slice::from_raw_parts_mut($data, len) };"
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use ic_crypto_tree_hash::{LabeledTree, flatmap};
use ic_crypto_tree_hash_fuzz_check_witness_equality_utils::*;
use ic_protobuf::messaging::xnet::v1::LabeledTree as ProtobufLabeledTree;
use ic_protobuf::proxy::ProtoProxy;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const CHACHA_SEED_LEN: usize = 32;

pub fn fuzz_target<F: Fn(&LabeledTree<Vec<u8>>, &mut ChaCha20Rng)>(data: &[u8], f: F) {
    if data.len() < CHACHA_SEED_LEN {
        return;
    }
    if let Ok(tree) = ProtobufLabeledTree::proxy_decode(&data[CHACHA_SEED_LEN..]) {
        let seed: [u8; CHACHA_SEED_LEN] = data[..CHACHA_SEED_LEN]
            .try_into()
            .expect("failed to copy seed bytes");
        f(&tree, &mut ChaCha20Rng::from_seed(seed));
    };
}

pub fn fuzz_mutator(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    let tree_data = if size < CHACHA_SEED_LEN {
        // invalid tree encoding if there's not enough bytes to construct a slice
        &[0u8; 0]
    } else {
        &data[CHACHA_SEED_LEN..size]
    };

    let mut tree = match ProtobufLabeledTree::proxy_decode(tree_data) {
        Ok(tree) if matches!(tree, LabeledTree::SubTree(_)) => tree,
        Err(_) | Ok(_) /*if matches!(tree, LabeledTree::Leaf(_))*/ => {
            let seed = [0u8; CHACHA_SEED_LEN];
            let encoded_tree =
                ProtobufLabeledTree::proxy_encode(LabeledTree::<Vec<u8>>::SubTree(flatmap!()));
            let bytes: Vec<_> = seed.into_iter().chain(encoded_tree).collect();
            let new_size = bytes.len();
            if new_size <= max_size {
                data[..new_size].copy_from_slice(&bytes[..new_size]);
                return new_size;
            } else {
                panic!("The maximum size of data is too small to store an empty tree");
            }
        }
    };

    let rng = &mut rng_from_u32(seed);

    let data_size_changed = match rng.gen_range(0..9) {
        0 => try_remove_leaf(&mut tree, rng),
        1 => try_remove_empty_subtree(&mut tree, rng),
        // actions that increase the tree's size have twice the probability of those
        // that decrease it, in order to prevent being stuck with the same tree size
        2 | 3 => add_leaf(&mut tree, rng),
        4 | 5 => add_empty_subtree(&mut tree, rng),
        6 => try_randomly_change_bytes_leaf_value(&mut tree, rng, &|buffer: &mut Vec<u8>| {
            randomly_modify_buffer(buffer)
        }),
        7 => try_randomly_change_bytes_label(&mut tree, rng, &|buffer: &mut Vec<u8>| {
            randomly_modify_buffer(buffer)
        }),
        // generate new seed
        8 => {
            rng.fill_bytes(&mut data[..CHACHA_SEED_LEN]);
            false
        }
        _ => unreachable!(),
    };

    if data_size_changed {
        let encoded_tree = ProtobufLabeledTree::proxy_encode(tree);
        let new_size = CHACHA_SEED_LEN + encoded_tree.len();
        if new_size <= max_size {
            data[CHACHA_SEED_LEN..new_size].copy_from_slice(&encoded_tree[..]);
            new_size
        } else {
            size
        }
    } else {
        size
    }
}

fn randomly_modify_buffer(buffer: &mut Vec<u8>) {
    const CAPACITY: usize = 100;
    let num_bytes = buffer.len();
    if num_bytes < CAPACITY {
        // reserve some capacity s.t. the values can grow
        buffer.resize(CAPACITY, 0);
    }
    let new_size = libfuzzer_sys::fuzzer_mutate(&mut buffer[..], num_bytes, CAPACITY);
    buffer.resize(new_size, 0);
}
