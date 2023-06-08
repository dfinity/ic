use ic_base_types::NodeId;
use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscriptId, SignedIDkgDealing};
use ic_types::crypto::{BasicSig, BasicSigOf};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::Height;
use ic_types_test_utils::ids::SUBNET_42;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub(crate) fn batch_signed_dealing_with(
    internal_dealing_raw: Vec<u8>,
    dealer_id: NodeId,
) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234, Height::new(123)),
        internal_dealing_raw,
    };
    let signed_dealing = SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![1, 2, 3])),
            signer: dealer_id,
        },
    };
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature: BasicSignatureBatch {
            signatures_map: BTreeMap::new(),
        },
    }
}

pub(crate) fn node_set(nodes: &[NodeId]) -> BTreeSet<NodeId> {
    nodes.iter().copied().collect()
}
