use super::super::*;
use ic_base_types::PrincipalId;

mod batch_signed_idkg_dealings {
    use crate::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealings;
    use crate::crypto::canister_threshold_sig::idkg::tests::batch_dealings::{
        dealer_id, dummy_batch_signed_idkg_dealing,
    };
    use std::iter::zip;

    #[test]
    fn should_update_dealing_from_existing_dealer() {
        let dealer_id = dealer_id(1);
        let previous_dealing = dummy_batch_signed_idkg_dealing(dealer_id, vec![1]);
        let new_dealing = dummy_batch_signed_idkg_dealing(dealer_id, vec![2]);
        let mut dealings = BatchSignedIDkgDealings::new();

        assert_eq!(dealings.insert_or_update(previous_dealing.clone()), None);
        let mut iter = dealings.iter();
        assert_eq!(iter.next(), Some(&previous_dealing));
        assert_eq!(iter.next(), None);

        assert_eq!(
            dealings.insert_or_update(new_dealing.clone()),
            Some(previous_dealing)
        );
        let mut iter = dealings.iter();
        assert_eq!(iter.next(), Some(&new_dealing));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn should_not_update_dealing_from_other_dealer() {
        let dealing_from_1 = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]);
        let dealing_from_2 = dummy_batch_signed_idkg_dealing(dealer_id(2), vec![1]);
        let mut dealings = BatchSignedIDkgDealings::new();

        assert_eq!(dealings.insert_or_update(dealing_from_1.clone()), None);
        let mut iter = dealings.iter();
        assert_eq!(iter.next(), Some(&dealing_from_1));
        assert_eq!(iter.next(), None);

        assert_eq!(dealings.insert_or_update(dealing_from_2.clone()), None);
        let mut iter = dealings.iter();
        assert_eq!(iter.next(), Some(&dealing_from_1));
        assert_eq!(iter.next(), Some(&dealing_from_2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn should_only_consider_latest_dealing_from_dealer() {
        let dealing_from_0 = dummy_batch_signed_idkg_dealing(dealer_id(0), vec![0]);
        let update_1_dealing_from_0 = dummy_batch_signed_idkg_dealing(dealer_id(0), vec![1]);
        let update_2_dealing_from_0 = dummy_batch_signed_idkg_dealing(dealer_id(0), vec![2]);
        let dealings: BatchSignedIDkgDealings = vec![
            dealing_from_0,
            update_1_dealing_from_0,
            update_2_dealing_from_0.clone(),
        ]
        .into_iter()
        .collect();

        let mut iter = dealings.iter();

        assert_eq!(iter.next(), Some(&update_2_dealing_from_0));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn should_have_dealings_ordered_by_dealer_id() {
        let dealing_from_0 = dummy_batch_signed_idkg_dealing(dealer_id(0), vec![1]);
        let dealing_from_1 = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]);
        let dealing_from_2 = dummy_batch_signed_idkg_dealing(dealer_id(2), vec![1]);
        let dealings: BatchSignedIDkgDealings = vec![
            dealing_from_2.clone(),
            dealing_from_1.clone(),
            dealing_from_0.clone(),
        ]
        .into_iter()
        .collect();

        let mut iter = dealings.iter();

        assert_eq!(iter.next(), Some(&dealing_from_0));
        assert_eq!(iter.next(), Some(&dealing_from_1));
        assert_eq!(iter.next(), Some(&dealing_from_2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn should_have_correct_len_and_is_empty_value() {
        let dealing_from_1 = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]);
        let update_dealing_from_1 = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![2]);
        let dealing_from_2 = dummy_batch_signed_idkg_dealing(dealer_id(2), vec![1]);
        let mut dealings = BatchSignedIDkgDealings::new();

        assert_eq!(dealings.len(), 0);
        assert!(dealings.is_empty());

        dealings.insert_or_update(dealing_from_1);
        assert_eq!(dealings.len(), 1);
        assert!(!dealings.is_empty());

        dealings.insert_or_update(dealing_from_2);
        assert_eq!(dealings.len(), 2);
        assert!(!dealings.is_empty());

        dealings.insert_or_update(update_dealing_from_1);
        assert_eq!(dealings.len(), 2);
        assert!(!dealings.is_empty());
    }

    #[test]
    fn should_convert_to_iterator_by_reference_or_by_taking_ownership() {
        let dealing_from_0 = dummy_batch_signed_idkg_dealing(dealer_id(0), vec![1]);
        let dealing_from_1 = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]);
        let dealing_from_2 = dummy_batch_signed_idkg_dealing(dealer_id(2), vec![1]);
        let dealings: BatchSignedIDkgDealings = vec![
            dealing_from_2.clone(),
            dealing_from_1.clone(),
            dealing_from_0.clone(),
        ]
        .into_iter()
        .collect();
        let ordered_dealings = vec![dealing_from_0, dealing_from_1, dealing_from_2];

        for (dealing, ordered_dealing) in zip(&dealings, &ordered_dealings) {
            assert_eq!(dealing, ordered_dealing)
        }

        for (dealing, ordered_dealing) in zip(dealings, ordered_dealings) {
            assert_eq!(dealing, ordered_dealing)
        }
    }
}

mod dummy_batch_signed_idkg_dealing {
    use super::*;

    #[test]
    fn should_have_correct_dealer_in_dummy_dealing() {
        let dealing = dummy_batch_signed_idkg_dealing(dealer_id(1), vec![]);

        assert_eq!(dealing.dealer_id(), dealer_id(1));
    }

    #[test]
    fn should_not_be_equal_when_arg_different() {
        assert_ne!(
            dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]),
            dummy_batch_signed_idkg_dealing(dealer_id(1), vec![2])
        );

        assert_ne!(
            dummy_batch_signed_idkg_dealing(dealer_id(1), vec![1]),
            dummy_batch_signed_idkg_dealing(dealer_id(2), vec![1])
        );
    }
}

fn dealer_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn dummy_batch_signed_idkg_dealing(
    dealer_id: NodeId,
    internal_dealing_raw: Vec<u8>,
) -> BatchSignedIDkgDealing {
    use crate::crypto::BasicSig;
    use crate::crypto::BasicSigOf;

    let transcript_id = IDkgTranscriptId::new(
        SubnetId::from(PrincipalId::new_subnet_test_id(1)),
        1,
        Height::from(1),
    );
    BatchSignedIDkgDealing {
        content: SignedIDkgDealing {
            content: IDkgDealing {
                transcript_id,
                internal_dealing_raw,
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: dealer_id,
            },
        },
        signature: BasicSignatureBatch {
            signatures_map: Default::default(),
        },
    }
}
