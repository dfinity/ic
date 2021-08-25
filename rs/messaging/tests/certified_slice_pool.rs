use assert_matches::assert_matches;
use ic_canonical_state::LabelLike;
use ic_crypto_tree_hash::{flat_map::FlatMap, Label, LabeledTree};
use ic_messaging::{
    certified_slice_pool::{
        testing, CertifiedSliceError, CertifiedSlicePool, InvalidAppend, InvalidSlice,
        UnpackedStreamSlice, LABEL_STATUS, STATUS_NONE, STATUS_SUCCESS,
    },
    ExpectedIndices,
};
use ic_metrics::MetricsRegistry;
use ic_protobuf::{messaging::xnet::v1, proxy::ProtoProxy};
use ic_test_utilities::{
    metrics::{metric_vec, HistogramStats},
    with_test_replica_logger,
};
use ic_types::{
    xnet::{CertifiedStreamSlice, StreamIndex},
    CountBytes, SubnetId,
};
use maplit::btreemap;
use proptest::prelude::*;
use std::convert::TryFrom;

mod common;
use common::*;

pub const SRC_SUBNET: SubnetId = REMOTE_SUBNET;
pub const DST_SUBNET: SubnetId = OWN_SUBNET;

proptest! {
    #[test]
    fn slice_unpack_roundtrip((stream, from, msg_count) in arb_stream_slice(0, 10)) {
        with_test_replica_logger(|log| {
            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);

            let certified_slice = fixture.get_slice(DST_SUBNET, from, msg_count);
            let unpacked = UnpackedStreamSlice::try_from(certified_slice.clone())
                .expect("failed to unpack certified stream");

            assert_slices_eq(
                certified_slice,
                CertifiedStreamSlice::from(unpacked)
            );
        });
    }

    #[test]
    fn slice_garbage_collect((mut stream, from, msg_count) in arb_stream_slice(0, 10)) {
        /// Convenience wrapper for `UnpackedStreamSlice::garbage_collect()` that takes
        /// and returns `CertifiedStreamSlices`.
        fn gc(
            certified_slice: &CertifiedStreamSlice,
            message_index: StreamIndex,
            signal_index: StreamIndex,
        ) -> Option<CertifiedStreamSlice> {
            let unpacked = UnpackedStreamSlice::try_from(certified_slice.clone())
                .expect("failed to unpack certified stream");

            unpacked
                .garbage_collect(&ExpectedIndices {
                    message_index,
                    signal_index
                })
                .unwrap()
                .map(|leftover| leftover.into())
        }

        with_test_replica_logger(|log| {
            // Increment `signals_end` so we can later safely decrement it without underflow.
            stream.increment_signals_end();
            let signals_end = stream.signals_end();

            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);
            let certified_slice = fixture.get_slice(DST_SUBNET, from, msg_count);

            if msg_count > 0 {
                // Garbage collecting no messages and no signals should yield the original slice.
                assert_opt_slices_eq(
                    Some(fixture.get_slice(DST_SUBNET, from, msg_count)),
                    gc(&certified_slice, from, signals_end.decrement()),
                );
                // Garbage collecting no messages and all signals should yield the original slice.
                assert_opt_slices_eq(
                    Some(fixture.get_slice(DST_SUBNET, from, msg_count)),
                    gc(&certified_slice, from, signals_end),
                );
                if msg_count > 1 {
                    let from_middle = from + StreamIndex::from(msg_count as u64 / 2);
                    let msgs_from_middle = (msg_count + 1) / 2;
                    // Garbage collecting some messages and no signals should truncate the slice.
                    assert_opt_slices_eq(
                        Some(fixture.get_slice(DST_SUBNET, from_middle, msgs_from_middle)),
                        gc(&certified_slice, from_middle, signals_end.decrement()),
                    );
                    // Garbage collecting some messages and all signals should truncate the slice.
                    assert_opt_slices_eq(
                        Some(fixture.get_slice(DST_SUBNET, from_middle, msgs_from_middle)),
                        gc(&certified_slice, from_middle, signals_end),
                    );
                }
            }

            let to = from + StreamIndex::from(msg_count as u64);
            // Garbage collecting all messages and no signals should yield an empty slice.
            assert_opt_slices_eq(
                Some(fixture.get_slice(DST_SUBNET, to, 0)),
                gc(&certified_slice, to, signals_end.decrement()),
            );
            // Garbage collecting all messages and all signals should yield `None`.
            assert_opt_slices_eq(
                None,
                gc(&certified_slice, to, signals_end),
            );
        });
    }

    #[test]
    fn slice_take_prefix((stream, from, msg_count) in arb_stream_slice(0, 100)) {
        /// Convenience wrapper for `UnpackedStreamSlice::take_prefix()` that takes a
        /// `&CertifiedStreamSlice` argument.
        fn take_prefix(
            certified_slice: &CertifiedStreamSlice,
            msg_limit: Option<usize>,
            byte_limit: Option<usize>,
        ) -> (Option<CertifiedStreamSlice>, Option<CertifiedStreamSlice>) {
            let unpacked = UnpackedStreamSlice::try_from(certified_slice.clone())
                .expect("failed to unpack certified stream");

            let (prefix, postfix) = unpacked.take_prefix(msg_limit, byte_limit).unwrap();

            // Ensure that any limits were respected.
            if let (Some(msg_limit), Some(prefix)) = (msg_limit, prefix.as_ref()) {
                assert!(testing::slice_len(prefix) <= msg_limit);
            }
            if let (Some(byte_limit), Some(prefix)) = (byte_limit, prefix.as_ref()) {
                assert!(prefix.count_bytes() <= byte_limit);
            }

            // And that a longer prefix would have gone over one the limits.
            let unpacked = UnpackedStreamSlice::try_from(certified_slice.clone()).unwrap();
            match prefix.as_ref() {
                Some(prefix) if postfix.is_some() => {
                    let prefix_len = testing::slice_len(prefix);
                    let longer_prefix = unpacked.take_prefix(Some(prefix_len + 1), None).unwrap().0.unwrap();
                    let over_msg_limit = msg_limit.map(|limit| testing::slice_len(&longer_prefix) > limit).unwrap_or_default();
                    let over_byte_limit = byte_limit.map(|limit| longer_prefix.count_bytes() > limit).unwrap_or_default();
                    assert!(over_msg_limit || over_byte_limit)
                },
                None => {
                    let empty_prefix = unpacked.take_prefix(Some(0), None).unwrap().0.unwrap();
                    assert!(empty_prefix.count_bytes() > byte_limit.unwrap())
                }
                _ => {}
            }

            (prefix.map(|prefix| prefix.into()), postfix.map(|postfix| postfix.into()))
        }

        /// Helper producing two adjacent `CertifiedStreamSlices` starting at `from` and
        /// of lengths `prefix_msg_count` and respectively `postfix_msg_count`.
        fn split(
            fixture: &StateManagerFixture,
            subnet_id: SubnetId,
            from: StreamIndex,
            prefix_msg_count: usize,
            postfix_msg_count: usize,
        ) -> (Option<CertifiedStreamSlice>, Option<CertifiedStreamSlice>) {
            (
                Some(fixture.get_slice(subnet_id, from, prefix_msg_count)),
                Some(fixture.get_slice(
                    subnet_id, from + StreamIndex::from(prefix_msg_count as u64), postfix_msg_count)),
            )
        }

        with_test_replica_logger(|log| {
            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);
            let certified_slice = fixture.get_slice(DST_SUBNET, from, msg_count);

            // Taking an unlimited prefix should result in the full slice and no leftover.
            assert_opt_slice_pairs_eq(
                (Some(certified_slice.clone()), None),
                take_prefix(&certified_slice, None, None),
            );

            // Taking a too-small prefix should result in no prefix and the original left over.
            assert_opt_slice_pairs_eq(
                (None, Some(certified_slice.clone())),
                take_prefix(&certified_slice, None, Some(13)),
            );

            // Even if requesting for zero messages.
            assert_opt_slice_pairs_eq(
                (None, Some(certified_slice.clone())),
                take_prefix(&certified_slice, Some(0), Some(13)),
            );

            if msg_count > 0 {
                // Taking zero messages should result in an empty prefix and the original left over.
                assert_opt_slice_pairs_eq(
                    split(&fixture, DST_SUBNET, from, 0, msg_count),
                    take_prefix(&certified_slice, Some(0), None),
                );

                // Taking an unlimited number of messages with a byte limit just under the byte size
                // should result in `msg_count - 1` messages and 1 message left over.
                let byte_size = UnpackedStreamSlice::try_from(certified_slice.clone())
                    .expect("failed to unpack certified stream").count_bytes();
                assert_opt_slice_pairs_eq(
                    split(&fixture, DST_SUBNET, from, msg_count - 1, 1),
                    take_prefix(&certified_slice, None, Some(byte_size - 1)),
                );

                // As should taking `msg_count - 1` messages.
                assert_opt_slice_pairs_eq(
                    split(&fixture, DST_SUBNET, from, msg_count - 1, 1),
                    take_prefix(&certified_slice, Some(msg_count - 1), None),
                );

                // But setting both limits exactly should result in the full slice and no leftover.
                assert_opt_slice_pairs_eq(
                (Some(certified_slice.clone()), None),
                    take_prefix(&certified_slice, Some(msg_count), Some(byte_size)),
                );
            } else {
                // Taking zero messages from an empty slice should result in the full slice and no leftover.
                assert_opt_slice_pairs_eq(
                    (Some(certified_slice.clone()), None),
                    take_prefix(&certified_slice, Some(0), None),
                );
            }
        });
    }

    #[test]
    fn invalid_slice((stream, from, msg_count) in arb_stream_slice(0, 10)) {
        // Returns the provided slice, adjusted by the provided function.
        fn adjust<F: FnMut(&mut LabeledTree<Vec<u8>>)>(
            slice: &CertifiedStreamSlice,
            mut f: F,
        ) -> CertifiedStreamSlice {
            let mut adjusted = slice.clone();
            let mut tree = v1::LabeledTree::proxy_decode(slice.payload.as_slice()).unwrap();
            f(&mut tree);
            adjusted.payload = v1::LabeledTree::proxy_encode(tree).unwrap();
            adjusted
        }

        // Asserts that unpacking the given slice fails with the expected error message.
        fn assert_unpack_fails(
            expected: InvalidSlice,
            invalid_slice: CertifiedStreamSlice,
        ) {
            match UnpackedStreamSlice::try_from(invalid_slice) {
                Err(CertifiedSliceError::InvalidPayload(reason)) => assert_eq!(expected, reason),
                actual => panic!(
                    "Expected Err(CertifiedSliceError::InvalidPayload((\"{:?}\")), got {:?}",
                    expected,
                    actual
                ),
            }
        }

        // Returns the `FlatMap` contained in a `SubTree`.
        fn children_of(tree: &mut LabeledTree<Vec<u8>>) -> &mut FlatMap<Label, LabeledTree<Vec<u8>>> {
            match tree {
                LabeledTree::SubTree(children) => children,
                LabeledTree::Leaf(_) => panic!("not a SubTree"),
            }
        }

        with_test_replica_logger(|log| {
            let stream_begin = stream.messages_begin();
            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);

            let certified_slice = fixture.get_slice(DST_SUBNET, from, msg_count);

            assert_unpack_fails(
                InvalidSlice::MissingStreams,
                adjust(
                    &certified_slice,
                    |tree| {
                        children_of(tree).split_off(&Label::from(""));
                    }
                ),
            );

            assert_unpack_fails(
                InvalidSlice::MissingStream,
                adjust(
                    &certified_slice,
                    |tree| {
                        let mut streams = children_of(tree).get_mut(&Label::from("streams")).unwrap();
                        children_of(&mut streams).split_off(&Label::from(""));
                    }
                ),
            );

            assert_unpack_fails(
                InvalidSlice::MissingHeader,
                adjust(
                    &certified_slice,
                    |tree| {
                        let streams = children_of(tree).get_mut(&Label::from("streams")).unwrap();
                        let streams_tree = children_of(streams);
                        let subnet_id = streams_tree.keys()[0].clone();
                        let mut stream = streams_tree.get_mut(&subnet_id).unwrap();
                        children_of(&mut stream).split_off(&Label::from(""));
                    }
                ),
            );

            // Must have at least 2 messages and be able to prepend one.
            if msg_count > 1 && from.get() > 0 {
                // Stream with an extra message prepended to payload only.
                let slice_with_extra_message = adjust(
                    &certified_slice,
                    |tree| {
                        let streams = children_of(tree).get_mut(&Label::from("streams")).unwrap();
                        let streams_tree = children_of(streams);
                        let subnet_id = streams_tree.keys()[0].clone();
                        let stream = streams_tree.get_mut(&subnet_id).unwrap();
                        let stream_tree = children_of(stream);
                        let messages = stream_tree.get_mut(&Label::from("messages")).unwrap();
                        let messages_tree = children_of(messages);
                        let mut messages_vec: Vec<_> =
                            messages_tree.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                        messages_vec.insert(0, (
                            from.decrement().to_label(),
                            LabeledTree::Leaf(vec![])
                        ));
                        std::mem::swap(messages_tree, &mut FlatMap::from_key_values(messages_vec));
                    }
                );

                if from > stream_begin {
                    // Valid slice, but mismatching withess.

                    // Unpacking will succeed, as we're not validating against the witness.
                    let unpacked = UnpackedStreamSlice::try_from(slice_with_extra_message.clone()).unwrap();

                    // But GC should fail.
                    match unpacked.garbage_collect(&ExpectedIndices {
                        message_index: from.increment(),
                        signal_index: StreamIndex::from(std::u64::MAX),
                    }) {
                        Err(CertifiedSliceError::WitnessPruningFailed(_)) => {}
                        actual => panic!(
                            "Expected Err(CertifiedSliceError::WitnessPruningFailed(_), got {:?}",
                            actual
                        ),
                    }

                    // As should taking a prefix.
                    let unpacked = UnpackedStreamSlice::try_from(slice_with_extra_message).unwrap();
                    match unpacked.take_prefix(Some(1), None) {
                        Err(CertifiedSliceError::WitnessPruningFailed(_)) => {}
                        actual => panic!(
                            "Expected Err(CertifiedSliceError::WitnessPruningFailed(_), got {:?}",
                            actual
                        ),
                    }
                } else {
                    // Invalid slice, begin index before stream begin index. Unpacking should fail.
                    match UnpackedStreamSlice::try_from(slice_with_extra_message) {
                        Err(CertifiedSliceError::InvalidPayload(InvalidSlice::InvalidBounds)) => {}
                        actual => panic!(
                            "Expected Err(CertifiedSliceError::InvalidPayload(InvalidBounds), got {:?}",
                            actual
                        ),
                    }
                }
            }
        });
    }

    /// Verifies that the size estimate returned by `count_bytes()` is within
    /// 5% of the actual size of the encoded struct.
    ///
    /// If this test fails, you need to check where the error lies (payload vs.
    /// witness) and adjust the estimate accordingly. Or bump the error margin.
    #[test]
    fn slice_accurate_count_bytes((stream, from, msg_count) in arb_stream_slice(2, 100)) {
        /// Asserts that the `actual` value is within `+/-(error_percent% +
        /// absolute_error)` of the `expected` value.
        fn assert_almost_equal(
            expected: usize,
            actual: usize,
            error_percent: usize,
            absolute_error: usize,
        ) {
            let expected_min = expected * (100 - error_percent) / 100 - absolute_error;
            let expected_max = expected * (100 + error_percent) / 100 + absolute_error;
            assert!(
                expected_min <= actual && actual <= expected_max,
                "Expecting estimated size to be within {}% of {}, was {}",
                error_percent,
                expected,
                actual
            );
        }

        /// Verifies that the result of calling `count_bytes()` on the
        /// `UnpackedStreamSlice` unpacked from `slice` is within 5% of the
        /// byte size of `slice`.
        fn assert_good_estimate(slice: CertifiedStreamSlice) {
            let unpacked = UnpackedStreamSlice::try_from(slice.clone())
                .expect("failed to unpack certified stream");

            let packed_payload_bytes = slice.payload.len();
            let unpacked_payload_bytes = testing::payload_count_bytes(&unpacked);
            assert_almost_equal(packed_payload_bytes, unpacked_payload_bytes, 1, 10);

            let packed_witness_bytes = slice.merkle_proof.len();
            let unpacked_witness_bytes = testing::witness_count_bytes(&unpacked);
            assert_almost_equal(packed_witness_bytes, unpacked_witness_bytes, 5, 10);

            let packed_bytes =
                slice.payload.len() + slice.merkle_proof.len() + slice.certification.count_bytes();
            let unpacked_bytes = unpacked.count_bytes();
            assert_almost_equal(packed_bytes, unpacked_bytes, 5, 0);
        }

        with_test_replica_logger(|log| {
            let fixture =
                StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);

            // Verify that we have good estimates for empty, single-message
            // and many-message slices, to ensure that both fixed and
            // per-message overheads are accurate.
            assert_good_estimate(fixture.get_slice(DST_SUBNET, from, 0));
            assert_good_estimate(fixture.get_slice(DST_SUBNET, from, 1));
            assert_good_estimate(fixture.get_slice(DST_SUBNET, from, msg_count));
        });
    }

    #[test]
    fn pool(
        (mut stream, from, msg_count) in arb_stream_slice(0, 10),
    ) {
        /// Asserts that the pool has a cached stream position for the given subnet.
        fn has_stream_position(subnet_id: SubnetId, pool: &CertifiedSlicePool) -> bool {
            !matches!(pool.slice_stats(subnet_id), (None, _, _, _))
        }
        /// Asserts that the pool contains a slice from the given subnet.
        fn has_slice(subnet_id: SubnetId, pool: &CertifiedSlicePool) -> bool {
            !matches!(pool.slice_stats(subnet_id), (_, None, 0, 0))
        }
        /// Takes the full pooled slice from the given subnet. Panics if no such slice exists.
        fn take_slice(subnet_id: SubnetId, pool: &mut CertifiedSlicePool) -> Option<CertifiedStreamSlice> {
            pool.take_slice(subnet_id, None, None, None).unwrap().map(|(slice, _)| slice)
        }
        /// Asserts that the pool contains a slice with the expected stats and non-zero byte size.
        fn assert_has_slice(
            subnet_id: SubnetId,
            pool: &mut CertifiedSlicePool,
            expected_stream_position: Option<ExpectedIndices>,
            expected_slice_begin: Option<StreamIndex>,
            expected_msg_count: usize,
        ) {
            let (stream_position, slice_begin, msg_count, byte_size) = pool.slice_stats(subnet_id);
            assert_eq!(expected_stream_position, stream_position);
            assert_eq!(expected_slice_begin, slice_begin);
            assert_eq!(expected_msg_count, msg_count);
            assert!(byte_size > 0);
        }

        with_test_replica_logger(|log| {
            // Increment `signals_end` so we can later safely decrement it without underflow.
            stream.increment_signals_end();

            // Indices just before the slice. Garbage collecting these should be a no-op.
            let indices_before = ExpectedIndices{
                message_index: from,
                signal_index: stream.signals_end().decrement(),
            };
            let zero_indices = ExpectedIndices::default();

            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream);
            let slice = fixture.get_slice(DST_SUBNET, from, msg_count);
            let messages_begin = if msg_count > 0 {
                Some(from)
            } else {
                None
            };

            let mut pool = CertifiedSlicePool::new(&MetricsRegistry::new());

            // Empty pool is empty.
            assert!(pool.peers().next().is_none());
            assert!(!has_stream_position(SRC_SUBNET, &pool));
            assert!(!has_slice(SRC_SUBNET, &pool));
            assert!(take_slice(SRC_SUBNET, &mut pool).is_none());

            // Populate the pool.
            pool.put(SRC_SUBNET, slice.clone()).unwrap();

            // Peers and stream positions still not set.
            assert!(pool.peers().next().is_none());
            assert!(!has_stream_position(SRC_SUBNET, &pool));

            // But we can take the slice out of the pool...
            assert!(has_slice(SRC_SUBNET, &pool));
            assert_eq!(slice, take_slice(SRC_SUBNET, &mut pool).unwrap());
            // ...once.
            assert!(!has_slice(SRC_SUBNET, &pool));
            assert!(take_slice(SRC_SUBNET, &mut pool).is_none());

            // Create a fresh, populated pool.
            let mut pool = CertifiedSlicePool::new(&fixture.metrics);
            pool.garbage_collect(btreemap! {SRC_SUBNET => ExpectedIndices::default()});
            pool.put(SRC_SUBNET, slice.clone()).unwrap();

            // Sanity check that the slice is in the pool.
            {
                let mut peers = pool.peers();
                assert_eq!(Some(&SRC_SUBNET), peers.next());
                assert!(peers.next().is_none());

                pool.observe_pool_size_bytes();
                assert_eq!(
                    UnpackedStreamSlice::try_from(slice.clone()).unwrap().count_bytes(),
                    fixture.fetch_pool_size_bytes()
                );
            }
            assert_has_slice(SRC_SUBNET, &mut pool, Some(zero_indices), messages_begin, msg_count);

            // Garbage collecting no messages and no signals should be a no-op.
            pool.garbage_collect(btreemap! {SRC_SUBNET => indices_before.clone()});
            // But stream position should be updated.
            assert_has_slice(SRC_SUBNET, &mut pool, Some(indices_before.clone()), messages_begin, msg_count);

            // Taking a slice with too low a byte limit should also be a no-op.
            assert_eq!(
                None,
                pool.take_slice(SRC_SUBNET, Some(&indices_before), None, Some(1)).unwrap(),
            );
            assert_has_slice(SRC_SUBNET, &mut pool, Some(indices_before.clone()), messages_begin, msg_count);

            // Taking a slice with message limit zero should return the header only...
            assert_opt_slices_eq(
                Some(fixture.get_slice(DST_SUBNET, from, 0)),
                pool.take_slice(SRC_SUBNET, Some(&indices_before), Some(0), None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
            // ...but advance `signals_end`.
            let mut stream_position = ExpectedIndices {
                message_index: from,
                signal_index: indices_before.signal_index.increment(),
            };
            if msg_count == 0 {
                // Slice had length zero, it should have been consumed.
                assert_eq!(
                    (Some(stream_position), None, 0, 0),
                    pool.slice_stats(SRC_SUBNET)
                );
                // Terminate early.
                return;
            }

            // Slice was non-empty, messages should still be there.
            assert_has_slice(SRC_SUBNET, &mut pool, Some(stream_position.clone()), Some(from), msg_count);

            // Pretend message 0 was already included into a block and take the next 1 message.
            stream_position.message_index.inc_assign();
            let prefix = pool.take_slice(SRC_SUBNET, Some(&stream_position), Some(1), None).unwrap();
            if msg_count == 1 {
                // Attempting to take a second message should have returned nothing...
                assert_eq!(None, prefix);
                // ...and GC-ed everything.
                assert_eq!(
                    (Some(stream_position), None, 0, 0),
                    pool.slice_stats(SRC_SUBNET)
                );
                // Terminate early.
                return;
            }

            // A slice containing the second message should have been returned.
            assert_opt_slices_eq(
                Some(fixture.get_slice(DST_SUBNET, from.increment(), 1)),
                prefix.map(|(slice, _)| slice),
            );

            stream_position.message_index.inc_assign();
            if msg_count == 2 {
                // Slice should have been consumed.
                assert_eq!(
                    (Some(stream_position), None, 0, 0),
                    pool.slice_stats(SRC_SUBNET)
                );
                // Terminate early.
                return;
            }

            // Rest of slice should be in the pool.
            assert_has_slice(
                SRC_SUBNET,
                &mut pool,
                Some(stream_position.clone()),
                Some(stream_position.message_index),
                msg_count - 2);

            // GC-ing with an earlier message index should leave the slice unchanged...
            let earlier_message_index = from.increment();
            let earlier_indices = ExpectedIndices {
                message_index: earlier_message_index,
                signal_index: stream_position.signal_index,
            };
            pool.garbage_collect(btreemap! {SRC_SUBNET => earlier_indices.clone()});
            assert_has_slice(
                SRC_SUBNET,
                &mut pool,
                Some(earlier_indices.clone()),
                Some(stream_position.message_index),
                msg_count - 2);

            // ...but putting back the original slice now should replace it (from the earlier index).
            pool.put(SRC_SUBNET, slice).unwrap();
            assert_has_slice(SRC_SUBNET, &mut pool, Some(earlier_indices), Some(earlier_message_index), msg_count - 1);

            assert_eq!(
                metric_vec(&[
                    (&[(LABEL_STATUS, STATUS_SUCCESS)], 2),
                    (&[(LABEL_STATUS, STATUS_NONE)], 1),
                ]),
                fixture.fetch_pool_take_count()
            );
            // take_slice() returned 2 Some(_) results, one empty, one with a single message.
            assert_eq!(
                HistogramStats {
                    count: 2,
                    sum: 1.0
                },
                fixture.fetch_pool_take_messages()
            );
            // Called take_slice() 3x, skipping one message total.
            assert_eq!(
                HistogramStats {
                    count: 3,
                    sum: 1.0
                },
                fixture.fetch_pool_take_gced_messages()
            );
            assert_eq!(2, fixture.fetch_pool_take_size_bytes().count);
        });
    }

    #[test]
    fn pool_append_same_slice(
        (mut stream, from, msg_count) in arb_stream_slice(0, 10),
    ) {
        let to = from + (msg_count as u64).into();
        with_test_replica_logger(|log| {
            // Increment `signals_end` so we can later safely decrement it without underflow.
            stream.increment_signals_end();

            let fixture = StateManagerFixture::new(log.clone()).with_stream(DST_SUBNET, stream.clone());
            let slice = fixture.get_slice(DST_SUBNET, from, msg_count);
            let slice_bytes = UnpackedStreamSlice::try_from(slice.clone()).unwrap().count_bytes();

            // Stream position guaranteed to yield a slice, even if empty.
            let stream_position = ExpectedIndices{
                message_index: from,
                signal_index: stream.signals_end().decrement(),
            };

            let mut pool = CertifiedSlicePool::new(&fixture.metrics);

            // `append()` with no slice present is equivalent to `put()`.
            pool.append(SRC_SUBNET, slice.clone()).unwrap();
            // Note: this takes the slice and updates the cached stream position to its end indices.
            assert_opt_slices_eq(
                Some(slice.clone()),
                pool.take_slice(SRC_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );

            // Appending the same slice after taking it should be a no-op.
            pool.append(SRC_SUBNET, slice).unwrap();
            let mut stream_position = ExpectedIndices{
                message_index: to,
                signal_index: stream.signals_end(),
            };
            assert_eq!(
                (Some(stream_position.clone()), None, 0, 0),
                pool.slice_stats(SRC_SUBNET)
            );

            // But appending the same slice with a higher `signals_end` should result in an empty
            // slice (with the new `signals_end`).
            stream.increment_signals_end();
            let new_fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream.clone());
            let new_slice = new_fixture.get_slice(DST_SUBNET, from, msg_count);

            pool.append(SRC_SUBNET, new_slice).unwrap();

            let empty_slice = new_fixture.get_slice(DST_SUBNET, to, 0);
            let empty_slice_bytes = UnpackedStreamSlice::try_from(empty_slice.clone()).unwrap().count_bytes();
            assert_opt_slices_eq(
                Some(empty_slice),
                pool.take_slice(SRC_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
            stream_position.signal_index = stream.signals_end();
            assert_eq!(
                (Some(stream_position), None, 0, 0),
                pool.slice_stats(SRC_SUBNET)
            );

            pool.observe_pool_size_bytes();
            assert_eq!(
                0,
                fixture.fetch_pool_size_bytes()
            );
            assert_eq!(
                metric_vec(&[
                    (&[(LABEL_STATUS, STATUS_SUCCESS)], 2),
                ]),
                fixture.fetch_pool_take_count()
            );
            // take_slice() returned 2 Some(_) results, one empty, one with msg_count messages.
            assert_eq!(
                HistogramStats {
                    count: 2,
                    sum: msg_count as f64
                },
                fixture.fetch_pool_take_messages()
            );
            // Called take_slice() 2x, not skipping any message.
            assert_eq!(
                HistogramStats {
                    count: 2,
                    sum: 0.0
                },
                fixture.fetch_pool_take_gced_messages()
            );
            assert_eq!(
                HistogramStats {
                    count: 2,
                    sum: (slice_bytes + empty_slice_bytes) as f64
                },
                fixture.fetch_pool_take_size_bytes()
            );
        });
    }

    #[test]
    fn pool_append_non_empty_to_empty(
        (mut stream, from, msg_count) in arb_stream_slice(1, 10),
    ) {
        with_test_replica_logger(|log| {
            // Increment `signals_end` so we can later safely decrement it without underflow.
            stream.increment_signals_end();

            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream.clone());
            let slice = fixture.get_slice(DST_SUBNET, from, msg_count);

            // Stream position matching slice begin.
            let stream_position = ExpectedIndices{
                message_index: from,
                signal_index: stream.signals_end(),
            };

            let mut pool = CertifiedSlicePool::new(&fixture.metrics);

            // Append an empty slice.
            let empty_prefix_slice = fixture.get_slice(DST_SUBNET, from, 0);
            pool.append(SRC_SUBNET, empty_prefix_slice).unwrap();
            assert_matches!(
                pool.slice_stats(SRC_SUBNET),
                (None, None, 0, byte_size) if byte_size > 0
            );

            // Appending the full slice should pool the full slice.
            pool.append(SRC_SUBNET, slice.clone()).unwrap();
            assert_matches!(
                pool.slice_stats(SRC_SUBNET),
                (None, Some(messages_begin), count, byte_size)
                    if messages_begin == from
                        && count == msg_count
                        && byte_size > 0
            );
            assert_opt_slices_eq(
                Some(slice),
                pool.take_slice(SRC_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
        });
    }

    #[test]
    fn pool_append_non_empty_to_non_empty(
        (mut stream, from, msg_count) in arb_stream_slice(2, 10),
    ) {
        with_test_replica_logger(|log| {
            // Increment `signals_end` so we can later safely decrement it without underflow.
            stream.increment_signals_end();

            let fixture = StateManagerFixture::new(log).with_stream(DST_SUBNET, stream.clone());
            let slice = fixture.get_slice(DST_SUBNET, from, msg_count);

            // Stream position matching slice begin.
            let stream_position = ExpectedIndices{
                message_index: from,
                signal_index: stream.signals_end(),
            };

            let mut pool = CertifiedSlicePool::new(&fixture.metrics);

            // Slice midpoint.
            let prefix_len = msg_count / 2;
            let suffix_len = msg_count - prefix_len;
            let mid = from + (prefix_len as u64).into();

            // Pool first half of slice.
            let prefix_slice = fixture.get_slice(DST_SUBNET, from, prefix_len);
            pool.put(SRC_SUBNET, prefix_slice).unwrap();
            assert_matches!(
                pool.slice_stats(SRC_SUBNET),
                (None, Some(messages_begin), count, byte_size)
                    if messages_begin == from
                        && count == prefix_len
                        && byte_size > 0
            );

            // Appending a slice with a duplicate message should fail.
            let overlapping_suffix_slice =
                fixture.get_partial_slice(DST_SUBNET, from, mid.decrement(), suffix_len + 1);
            assert_matches!(
                pool.append(SRC_SUBNET, overlapping_suffix_slice),
                Err(CertifiedSliceError::InvalidAppend(InvalidAppend::IndexMismatch))
            );
            // Pooled slice stays unchanged.
            assert_matches!(
                pool.slice_stats(SRC_SUBNET),
                (None, Some(messages_begin), count, byte_size)
                    if messages_begin == from
                        && count == prefix_len
                        && byte_size > 0
            );

            if msg_count >= 3 {
                // Appending a slice with a message gap should fail.
                let gapped_suffix_slice =
                    fixture.get_partial_slice(DST_SUBNET, from, mid.increment(), suffix_len - 1);
                assert_matches!(
                    pool.append(SRC_SUBNET, gapped_suffix_slice),
                    Err(CertifiedSliceError::InvalidAppend(InvalidAppend::IndexMismatch))
                );
                // Pooled slice stays unchanged.
                assert_matches!(
                    pool.slice_stats(SRC_SUBNET),
                    (None, Some(messages_begin), count, byte_size)
                        if messages_begin == from
                            && count == prefix_len
                            && byte_size > 0
                );
            }

            // Appending the matching second half should succeed.
            let suffix_slice =
                fixture.get_partial_slice(DST_SUBNET, from, mid, suffix_len);
            pool.append(SRC_SUBNET, suffix_slice).unwrap();
            // And result in the full slice being pooled.
            assert_matches!(
                pool.slice_stats(SRC_SUBNET),
                (None, Some(messages_begin), count, byte_size)
                    if messages_begin == from
                        && count == msg_count
                        && byte_size > 0
            );
            assert_opt_slices_eq(
                Some(slice),
                pool.take_slice(SRC_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
        });
    }
}
