#![no_main]
// Clippy is, for a good reason, convinced that due to the following line in the
// `fuzz_mutator` expansion, its generated function `rust_fuzzer_custom_mutator` should also be
// marked unsafe. But since this is part of the fuzzer, let's just disable the corresponding lint.
// let $data: &mut [u8] = unsafe { std::slice::from_raw_parts_mut($data, len) };"
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use ic_crypto_tree_hash::{flatmap, LabeledTree};
use ic_crypto_tree_hash_fuzz_check_witness_equality_utils::*;
use ic_protobuf::messaging::xnet::v1::LabeledTree as ProtobufLabeledTree;
use ic_protobuf::proxy::ProtoProxy;
use libfuzzer_sys::fuzz_target;
use rand::Rng;

fuzz_target!(|data: &[u8]| {
    if let Ok(tree) = ProtobufLabeledTree::proxy_decode(data) {
        test_tree(&tree);
    };
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let mut tree = match ProtobufLabeledTree::proxy_decode(&data[..size]) {
        Ok(tree) if matches!(tree, LabeledTree::SubTree(_)) => tree,
        Err(_) | Ok(_) /*if matches!(tree, LabeledTree::Leaf(_))*/ => {
            let bytes =
                ProtobufLabeledTree::proxy_encode(LabeledTree::<Vec<u8>>::SubTree(flatmap!()))
                    .expect("failed to serialize an empty labeled tree");
            let new_size = bytes.len();
            if new_size <= max_size {
                data[..new_size].copy_from_slice(&bytes[..new_size]);
                return new_size;
            } else {
                panic!("The maximum size of data is too small to store an empty tree");
            }
        }
    };

    let mut rng = rng_from_u32(seed);

    let tree_was_modified = match rng.gen_range(0..8) {
        0 => try_remove_leaf(&mut tree, &mut rng),
        1 => try_remove_empty_subtree(&mut tree, &mut rng),
        // actions that increase the tree's size have twice the probability of those
        // that decrease it, in order to prevent being stuck with the same tree size
        2 | 3 => add_leaf(&mut tree, &mut rng),
        4 | 5 => add_empty_subtree(&mut tree, &mut rng),
        6 => try_randomly_change_bytes_leaf_value(&mut tree, &mut rng, &|buffer: &mut Vec<u8>| {
            randomly_modify_buffer(buffer)
        }),
        7 => try_randomly_change_bytes_label(&mut tree, &mut rng, &|buffer: &mut Vec<u8>| {
            randomly_modify_buffer(buffer)
        }),
        _ => unreachable!(),
    };

    if tree_was_modified {
        let bytes = ProtobufLabeledTree::proxy_encode(tree)
            .expect("failed to serialize the labeled tree {tree}");
        let new_size = bytes.len();
        if new_size <= max_size {
            data[..new_size].copy_from_slice(&bytes[..]);
            return new_size;
        } else {
            size
        }
    } else {
        size
    }
});

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
