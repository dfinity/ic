//! The malicious pre signature process manager

use crate::idkg::metrics::IDkgPreSignerMetrics;
use crate::idkg::{
    pre_signer::IDkgPreSignerImpl, utils::transcript_op_summary, IDkgBlockReaderImpl,
};
use ic_interfaces::{
    crypto::BasicSigner,
    idkg::{IDkgChangeAction, IDkgChangeSet},
};
use ic_logger::{warn, ReplicaLogger};
use ic_registry_client_helpers::node::RegistryVersion;
use ic_types::{
    consensus::idkg::{IDkgBlockReader, IDkgMessage},
    crypto::canister_threshold_sig::idkg::{IDkgDealing, IDkgTranscriptParams, SignedIDkgDealing},
    crypto::{BasicSigOf, CryptoResult},
    malicious_flags::MaliciousFlags,
    NodeId,
};
use std::collections::BTreeSet;

// A dealing is corrupted by changing some internal value.
// Since a dealing is signed, the signature must be re-computed so that the corrupted dealing
// is not trivially discarded and a proper complaint can be generated.
// To sign a dealing we only need something that implements the trait BasicSigner<IDkgDealing>,
// which `ConsensusCrypto` does.
// However, for Rust something of type dyn ConsensusCrypto (self.crypto is of type
// Arc<dyn ConsensusCrypto>, but the Arc<> is not relevant here) cannot be coerced into
// something of type dyn BasicSigner<IDkgDealing>. This is true for any sub trait implemented
// by ConsensusCrypto and is not specific to Crypto traits.
// Doing so would require `dyn upcasting coercion`, see
// https://github.com/rust-lang/rust/issues/65991 and
// https://articles.bchlr.de/traits-dynamic-dispatch-upcasting.
// As workaround a trivial implementation of BasicSigner<IDkgDealing> is provided by delegating to
// self.crypto.
impl BasicSigner<IDkgDealing> for IDkgPreSignerImpl {
    fn sign_basic(
        &self,
        message: &IDkgDealing,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<IDkgDealing>> {
        self.crypto.sign_basic(message, signer, registry_version)
    }
}

/// Modify the given changeset with malicious behavior.
pub fn maliciously_alter_changeset(
    changeset: IDkgChangeSet,
    pre_signer: &IDkgPreSignerImpl,
    malicious_flags: &MaliciousFlags,
) -> IDkgChangeSet {
    let block_reader = IDkgBlockReaderImpl::new(pre_signer.consensus_block_cache.finalized_chain());

    changeset
        .into_iter()
        .flat_map(|action| match action {
            IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing))
                if malicious_flags.maliciously_corrupt_idkg_dealings =>
            {
                let transcript_id = dealing.idkg_dealing().transcript_id;
                block_reader
                    .requested_transcripts()
                    .find(|params_ref| params_ref.transcript_id == transcript_id)
                    .and_then(|params_ref| {
                        pre_signer.resolve_ref(params_ref, &block_reader, "malicious_send_dealing")
                    })
                    .map(|params| {
                        let dealing = maliciously_corrupt_idkg_dealings(
                            pre_signer,
                            pre_signer.node_id,
                            dealing,
                            &params,
                            &pre_signer.log,
                            &pre_signer.metrics,
                        );
                        IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing))
                    })
            }
            _ => Some(action),
        })
        .collect::<Vec<_>>()
}

/// Helper to corrupt the signed crypto dealing for malicious testing
fn maliciously_corrupt_idkg_dealings(
    pre_signer: &IDkgPreSignerImpl,
    node_id: NodeId,
    idkg_dealing: SignedIDkgDealing,
    transcript_params: &IDkgTranscriptParams,
    log: &ReplicaLogger,
    metrics: &IDkgPreSignerMetrics,
) -> SignedIDkgDealing {
    let mut rng = rand::thread_rng();
    let mut exclude_set = BTreeSet::new();
    exclude_set.insert(node_id);
    match ic_crypto_test_utils_canister_threshold_sigs::corrupt_signed_idkg_dealing(
        idkg_dealing,
        transcript_params,
        pre_signer,
        node_id,
        &exclude_set,
        &mut rng,
    ) {
        Ok(dealing) => {
            warn!(
                 every_n_seconds => 2,
                 log,
                "Corrupted dealing: transcript_id = {:?}", transcript_params.transcript_id()
            );
            metrics.pre_sign_metrics_inc("dealing_corrupted");
            dealing
        }
        Err(err) => {
            warn!(
                log,
                "Failed to corrupt dealing: transcript_id = {:?}, type = {:?}, error = {:?}",
                transcript_params.transcript_id(),
                transcript_op_summary(transcript_params.operation_type()),
                err
            );
            metrics.pre_sign_errors_inc("corrupt_dealing");
            panic!("Failed to corrupt dealing")
        }
    }
}
