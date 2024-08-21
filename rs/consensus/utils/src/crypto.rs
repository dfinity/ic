use ic_interfaces::{crypto::*, validation::ValidationResult};
use ic_types::{
    canister_http::CanisterHttpResponseMetadata,
    consensus::{
        dkg,
        hashed::Hashed,
        idkg::{IDkgComplaintContent, IDkgOpeningContent},
        BlockMetadata, CatchUpContent, FinalizationContent, NotarizationContent,
        RandomBeaconContent, RandomTapeContent,
    },
    crypto::{
        canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing},
        threshold_sig::ni_dkg::NiDkgId,
        CryptoError, CryptoHashOf, CryptoHashable, CryptoResult, Signable, Signed,
    },
    signature::{
        BasicSignature, BasicSignatureBatch, MultiSignature, MultiSignatureShare,
        ThresholdSignature, ThresholdSignatureShare,
    },
    NodeId, RegistryVersion,
};
use std::collections::BTreeMap;

/// A trait that unifies the individual signing and verification interface for
/// both threshold and multi signatures. It is parameterized by the following:
///   - Message is the content type to sign
///   - Signature is the signature type
///   - KeySelector is either `NiDkgId` or RegistryVersion, used to select the
///     actual key are used by the signer, which is always a NodeId.
pub trait SignVerify<Message, Signature, KeySelector> {
    /// Sign a message and return the signature if successful, or CryptoError
    /// otherwise.
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        selector: KeySelector,
    ) -> CryptoResult<Signature>;

    /// Verify the signature of a Signed message. Return CryptoError if it
    /// fails.
    fn verify(
        &self,
        message: &Signed<Message, Signature>,
        selector: KeySelector,
    ) -> ValidationResult<CryptoError>;
}

impl<Message: Signable, C: BasicSigner<Message> + BasicSigVerifier<Message>>
    SignVerify<Hashed<CryptoHashOf<Message>, Message>, BasicSignature<Message>, RegistryVersion>
    for C
{
    fn sign(
        &self,
        message: &Hashed<CryptoHashOf<Message>, Message>,
        signer: NodeId,
        selector: RegistryVersion,
    ) -> CryptoResult<BasicSignature<Message>> {
        self.sign_basic(message.as_ref(), signer, selector)
            .map(|signature| BasicSignature { signature, signer })
    }
    fn verify(
        &self,
        message: &Signed<Hashed<CryptoHashOf<Message>, Message>, BasicSignature<Message>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_basic_sig(
            &message.signature.signature,
            message.content.as_ref(),
            message.signature.signer,
            selector,
        )
    }
}

impl<Message: Signable, C: BasicSigner<Message> + BasicSigVerifier<Message>>
    SignVerify<Message, BasicSignature<Message>, RegistryVersion> for C
{
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        selector: RegistryVersion,
    ) -> CryptoResult<BasicSignature<Message>> {
        self.sign_basic(message, signer, selector)
            .map(|signature| BasicSignature { signature, signer })
    }

    fn verify(
        &self,
        message: &Signed<Message, BasicSignature<Message>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_basic_sig(
            &message.signature.signature,
            &message.content,
            message.signature.signer,
            selector,
        )
    }
}

// This allows us to use sign verify directly when we provide a hash value to
// crypto instead of the actual message.
impl<Message, C> SignVerify<Message, BasicSignature<CryptoHashOf<Message>>, RegistryVersion> for C
where
    Message: CryptoHashable,
    CryptoHashOf<Message>: Signable,
    C: BasicSigner<CryptoHashOf<Message>> + BasicSigVerifier<CryptoHashOf<Message>>,
{
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        selector: RegistryVersion,
    ) -> CryptoResult<BasicSignature<CryptoHashOf<Message>>> {
        self.sign_basic(&ic_types::crypto::crypto_hash(message), signer, selector)
            .map(|signature| BasicSignature { signature, signer })
    }

    fn verify(
        &self,
        message: &Signed<Message, BasicSignature<CryptoHashOf<Message>>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_basic_sig(
            &message.signature.signature,
            &ic_types::crypto::crypto_hash(&message.content),
            message.signature.signer,
            selector,
        )
    }
}

impl<Message: Signable, C: MultiSigner<Message> + MultiSigVerifier<Message>>
    SignVerify<Message, MultiSignatureShare<Message>, RegistryVersion> for C
{
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        selector: RegistryVersion,
    ) -> CryptoResult<MultiSignatureShare<Message>> {
        self.sign_multi(message, signer, selector)
            .map(|signature| MultiSignatureShare { signature, signer })
    }

    fn verify(
        &self,
        message: &Signed<Message, MultiSignatureShare<Message>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_multi_sig_individual(
            &message.signature.signature,
            &message.content,
            message.signature.signer,
            selector,
        )
    }
}

impl<Message, C> SignVerify<Message, MultiSignatureShare<CryptoHashOf<Message>>, RegistryVersion>
    for C
where
    Message: CryptoHashable,
    CryptoHashOf<Message>: Signable,
    C: MultiSigner<CryptoHashOf<Message>> + MultiSigVerifier<CryptoHashOf<Message>>,
{
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        selector: RegistryVersion,
    ) -> CryptoResult<MultiSignatureShare<CryptoHashOf<Message>>> {
        self.sign_multi(&ic_types::crypto::crypto_hash(message), signer, selector)
            .map(|signature| MultiSignatureShare { signature, signer })
    }

    fn verify(
        &self,
        message: &Signed<Message, MultiSignatureShare<CryptoHashOf<Message>>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_multi_sig_individual(
            &message.signature.signature,
            &ic_types::crypto::crypto_hash(&message.content),
            message.signature.signer,
            selector,
        )
    }
}

impl<Message: Signable, C: ThresholdSigner<Message> + ThresholdSigVerifier<Message>>
    SignVerify<Message, ThresholdSignatureShare<Message>, NiDkgId> for C
{
    fn sign(
        &self,
        message: &Message,
        signer: NodeId,
        dkg_id: NiDkgId,
    ) -> CryptoResult<ThresholdSignatureShare<Message>> {
        self.sign_threshold(message, dkg_id)
            .map(|signature| ThresholdSignatureShare { signature, signer })
    }

    fn verify(
        &self,
        message: &Signed<Message, ThresholdSignatureShare<Message>>,
        dkg_id: NiDkgId,
    ) -> ValidationResult<CryptoError>
where {
        self.verify_threshold_sig_share(
            &message.signature.signature,
            &message.content,
            dkg_id,
            message.signature.signer,
        )
    }
}

/// A trait that unifies the aggregation and verification interface
/// for both threshold and multi signatures. It is parameterized by the
/// following:
///   - Message is the content type to sign
///   - Signature is the individual signature type
///   - KeySelector is either `NiDkgId` or RegistryVersion, used to select the
///     actual key are used by the signer, which is always a NodeId.
///   - AggregatedSignature is the aggregated signature type.
pub trait Aggregate<Message, Signature, KeySelector, AggregatedSignature> {
    /// Upcast self to a trait object of the Aggregate interface to work around
    /// a Rust limitation. It is used by ShareAggregator.
    fn as_aggregate(&self) -> &dyn Aggregate<Message, Signature, KeySelector, AggregatedSignature>;

    /// Aggregate signature shares and return the aggregated result signature if
    /// successful, or CryptoError otherwise.
    fn aggregate(
        &self,
        shares: Vec<&Signature>,
        selector: KeySelector,
    ) -> CryptoResult<AggregatedSignature>;

    /// Verify the aggregated signature of a signed message. Return CryptoError
    /// if it fails.
    fn verify_aggregate(
        &self,
        message: &Signed<Message, AggregatedSignature>,
        selector: KeySelector,
    ) -> ValidationResult<CryptoError>;
}

impl<Message: Signable, C: MultiSigner<Message> + MultiSigVerifier<Message>>
    Aggregate<Message, MultiSignatureShare<Message>, RegistryVersion, MultiSignature<Message>>
    for C
{
    fn as_aggregate(
        &self,
    ) -> &dyn Aggregate<
        Message,
        MultiSignatureShare<Message>,
        RegistryVersion,
        MultiSignature<Message>,
    > {
        self
    }

    fn aggregate(
        &self,
        mut shares: Vec<&MultiSignatureShare<Message>>,
        selector: RegistryVersion,
    ) -> CryptoResult<MultiSignature<Message>> {
        let signer_share_map = shares
            .iter()
            .map(|share| (share.signer, share.signature.clone()))
            .collect();
        let signature = self.combine_multi_sig_individuals(signer_share_map, selector)?;
        shares.sort_unstable_by_key(|s| s.signer);
        shares.dedup_by_key(|s| s.signer);
        let signers = shares.iter().map(|share| share.signer).collect();
        Ok(MultiSignature { signature, signers })
    }

    fn verify_aggregate(
        &self,
        message: &Signed<Message, MultiSignature<Message>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_multi_sig_combined(
            &message.signature.signature,
            &message.content,
            message.signature.signers.iter().cloned().collect(),
            selector,
        )
    }
}

impl<Message: Signable, C: BasicSigVerifier<Message>>
    Aggregate<Message, BasicSignature<Message>, RegistryVersion, BasicSignatureBatch<Message>>
    for C
{
    fn as_aggregate(
        &self,
    ) -> &dyn Aggregate<
        Message,
        BasicSignature<Message>,
        RegistryVersion,
        BasicSignatureBatch<Message>,
    > {
        self
    }

    fn aggregate(
        &self,
        shares: Vec<&BasicSignature<Message>>,
        selector: RegistryVersion,
    ) -> CryptoResult<BasicSignatureBatch<Message>> {
        let mut signatures_map = BTreeMap::new();
        for share in shares.into_iter() {
            signatures_map.insert(share.signer, &share.signature);
        }
        self.combine_basic_sig(signatures_map, selector)
    }

    fn verify_aggregate(
        &self,
        message: &Signed<Message, BasicSignatureBatch<Message>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_basic_sig_batch(&message.signature, &message.content, selector)
    }
}

impl<Message, C: MultiSigner<CryptoHashOf<Message>> + MultiSigVerifier<CryptoHashOf<Message>>>
    Aggregate<
        Message,
        MultiSignatureShare<CryptoHashOf<Message>>,
        RegistryVersion,
        MultiSignature<CryptoHashOf<Message>>,
    > for C
where
    Message: CryptoHashable,
    CryptoHashOf<Message>: Signable,
{
    fn as_aggregate(
        &self,
    ) -> &dyn Aggregate<
        Message,
        MultiSignatureShare<CryptoHashOf<Message>>,
        RegistryVersion,
        MultiSignature<CryptoHashOf<Message>>,
    > {
        self
    }

    fn aggregate(
        &self,
        mut shares: Vec<&MultiSignatureShare<CryptoHashOf<Message>>>,
        selector: RegistryVersion,
    ) -> CryptoResult<MultiSignature<CryptoHashOf<Message>>> {
        let signer_share_map = shares
            .iter()
            .map(|share| (share.signer, share.signature.clone()))
            .collect();
        let signature = self.combine_multi_sig_individuals(signer_share_map, selector)?;
        shares.sort_unstable_by_key(|s| s.signer);
        shares.dedup_by_key(|s| s.signer);
        let signers = shares.iter().map(|share| share.signer).collect();
        Ok(MultiSignature { signature, signers })
    }

    fn verify_aggregate(
        &self,
        message: &Signed<Message, MultiSignature<CryptoHashOf<Message>>>,
        selector: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        self.verify_multi_sig_combined(
            &message.signature.signature,
            &ic_types::crypto::crypto_hash(&message.content),
            message.signature.signers.iter().cloned().collect(),
            selector,
        )
    }
}

impl<Message: Signable, C: ThresholdSigner<Message> + ThresholdSigVerifier<Message>>
    Aggregate<Message, ThresholdSignatureShare<Message>, NiDkgId, ThresholdSignature<Message>>
    for C
{
    fn as_aggregate(
        &self,
    ) -> &dyn Aggregate<
        Message,
        ThresholdSignatureShare<Message>,
        NiDkgId,
        ThresholdSignature<Message>,
    > {
        self
    }

    fn aggregate(
        &self,
        shares: Vec<&ThresholdSignatureShare<Message>>,
        dkg_id: NiDkgId,
    ) -> CryptoResult<ThresholdSignature<Message>> {
        self.combine_threshold_sig_shares(
            shares
                .iter()
                .map(|share| (share.signer, share.signature.clone()))
                .collect(),
            dkg_id,
        )
        .map(|signature| ThresholdSignature {
            signer: dkg_id,
            signature,
        })
    }

    fn verify_aggregate(
        &self,
        message: &Signed<Message, ThresholdSignature<Message>>,
        _dkg_id: NiDkgId,
    ) -> ValidationResult<CryptoError> {
        self.verify_threshold_sig_combined(
            &message.signature.signature,
            &message.content,
            message.signature.signer,
        )
    }
}

/// A trait that encompass all crypto signing/verification interface required by
/// consensus. Anything that implements the Crypto trait automatically
/// implements this trait.
pub trait ConsensusCrypto:
    SignVerify<BlockMetadata, BasicSignature<BlockMetadata>, RegistryVersion>
    + SignVerify<NotarizationContent, MultiSignatureShare<NotarizationContent>, RegistryVersion>
    + SignVerify<FinalizationContent, MultiSignatureShare<FinalizationContent>, RegistryVersion>
    + SignVerify<SignedIDkgDealing, BasicSignature<SignedIDkgDealing>, RegistryVersion>
    + SignVerify<IDkgDealing, BasicSignature<IDkgDealing>, RegistryVersion>
    + SignVerify<IDkgComplaintContent, BasicSignature<IDkgComplaintContent>, RegistryVersion>
    + SignVerify<IDkgOpeningContent, BasicSignature<IDkgOpeningContent>, RegistryVersion>
    + SignVerify<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>, NiDkgId>
    + SignVerify<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>, NiDkgId>
    + SignVerify<CatchUpContent, ThresholdSignatureShare<CatchUpContent>, NiDkgId>
    + SignVerify<dkg::DealingContent, BasicSignature<dkg::DealingContent>, RegistryVersion>
    + SignVerify<
        CanisterHttpResponseMetadata,
        BasicSignature<CanisterHttpResponseMetadata>,
        RegistryVersion,
    > + SignVerify<
        CanisterHttpResponseMetadata,
        BasicSignature<CanisterHttpResponseMetadata>,
        RegistryVersion,
    > + Aggregate<
        NotarizationContent,
        MultiSignatureShare<NotarizationContent>,
        RegistryVersion,
        MultiSignature<NotarizationContent>,
    > + Aggregate<
        FinalizationContent,
        MultiSignatureShare<FinalizationContent>,
        RegistryVersion,
        MultiSignature<FinalizationContent>,
    > + Aggregate<
        SignedIDkgDealing,
        BasicSignature<SignedIDkgDealing>,
        RegistryVersion,
        BasicSignatureBatch<SignedIDkgDealing>,
    > + Aggregate<
        RandomBeaconContent,
        ThresholdSignatureShare<RandomBeaconContent>,
        NiDkgId,
        ThresholdSignature<RandomBeaconContent>,
    > + Aggregate<
        RandomTapeContent,
        ThresholdSignatureShare<RandomTapeContent>,
        NiDkgId,
        ThresholdSignature<RandomTapeContent>,
    > + Aggregate<
        CatchUpContent,
        ThresholdSignatureShare<CatchUpContent>,
        NiDkgId,
        ThresholdSignature<CatchUpContent>,
    > + Aggregate<
        CanisterHttpResponseMetadata,
        BasicSignature<CanisterHttpResponseMetadata>,
        RegistryVersion,
        BasicSignatureBatch<CanisterHttpResponseMetadata>,
    > + Crypto
    + Send
    + Sync
{
}

impl<C: Crypto + Send + Sync> ConsensusCrypto for C {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        crypto::{CombinedMultiSig, CombinedMultiSigOf, IndividualMultiSig, IndividualMultiSigOf},
        messages::MessageId,
    };

    struct AggregateImpl {}
    /// Fake Aggregate implementation
    impl MultiSigner<MessageId> for AggregateImpl {
        fn sign_multi(
            &self,
            _message: &MessageId,
            _signer: NodeId,
            _registry_version: RegistryVersion,
        ) -> CryptoResult<IndividualMultiSigOf<MessageId>> {
            Ok(IndividualMultiSigOf::from(IndividualMultiSig(vec![])))
        }
    }
    impl MultiSigVerifier<MessageId> for AggregateImpl {
        fn verify_multi_sig_individual(
            &self,
            _signature: &IndividualMultiSigOf<MessageId>,
            _message: &MessageId,
            _signer: NodeId,
            _registry_version: RegistryVersion,
        ) -> CryptoResult<()> {
            Ok(())
        }
        fn combine_multi_sig_individuals(
            &self,
            _signatures: BTreeMap<NodeId, IndividualMultiSigOf<MessageId>>,
            _registry_version: RegistryVersion,
        ) -> CryptoResult<CombinedMultiSigOf<MessageId>> {
            Ok(CombinedMultiSigOf::from(CombinedMultiSig(vec![])))
        }
        fn verify_multi_sig_combined(
            &self,
            _signature: &CombinedMultiSigOf<MessageId>,
            _message: &MessageId,
            _signers: BTreeSet<NodeId>,
            _registry_version: RegistryVersion,
        ) -> CryptoResult<()> {
            Ok(())
        }
    }

    /// Assert that the MultiSignature in aggregate() does not
    /// contain duplicate signers.
    #[test]
    fn test_deduplicate_signers_aggregate() {
        let m: MessageId = [0u8; 32].into();
        let s1 = fake_share(0, m.clone(), vec![1]);
        let s2 = fake_share(0, m.clone(), vec![2]);
        let s3 = fake_share(1, m, vec![1]);
        // Block::new(id, payload, height, rank, context);

        let x = AggregateImpl {};
        let multisig = x
            .aggregate(
                vec![&s1.signature, &s2.signature, &s3.signature],
                RegistryVersion::from(1),
            )
            .unwrap();

        // the duplicate signers needed to be removed
        assert_eq!(multisig.signers.len(), 2);
        assert!(multisig.signers.contains(&s1.signature.signer));
        assert!(multisig.signers.contains(&s2.signature.signer));
    }

    fn fake_share<C: Eq + Ord + Clone>(
        signer_id: u64,
        content: C,
        sig: Vec<u8>,
    ) -> Signed<C, MultiSignatureShare<C>> {
        let signer = node_test_id(signer_id);
        let signature = MultiSignatureShare {
            signature: IndividualMultiSigOf::new(IndividualMultiSig(sig)),
            signer,
        };
        Signed { content, signature }
    }
}
