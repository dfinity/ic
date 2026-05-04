#[cfg_attr(test, derive(strum_macros::EnumIter, Debug, PartialEq))]
pub enum DomainSeparator {
    /// The domain separator to be used when calculating the sender signature for a
    /// request to the Internet Computer according to the
    /// [interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
    IcRequest,
    IcRequestAuthDelegation,
    NotarizationContent,
    Notarization,
    NotarizationShare,
    FinalizationContent,
    Finalization,
    FinalizationShare,
    Block,
    _BlockProposal,
    BlockMetadata,
    BlockMetadataProposal,
    EquivocationProof,
    InmemoryPayload,
    RandomBeaconContent,
    RandomBeacon,
    RandomBeaconShare,
    CertificationContent,
    Certification,
    CertificationShare,
    DealingContent,
    DkgMessage,
    HttpCanisterUpdate,
    SignedRequestBytes,
    MessageId,
    // TODO: remove once NET-1501 is done
    _IcOnchainObservabilityReport,
    /// The domain separator to be used when calculating the signature for a
    /// query response from a replica.
    /// [interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
    QueryResponse,
    RandomTapeContent,
    RandomTape,
    RandomTapeShare,
    CatchUpContent,
    CatchUpContentProto,
    CatchUpShareContent,
    CatchUpPackage,
    CatchUpPackageShare,
    _StateSyncMessage,
    ConsensusMessage,
    CertificationMessage,
    IDkgMessage,
    IdkgDealing,
    SignedIdkgDealing,
    IdkgDealingSupport,
    IDkgTranscript,
    EcdsaSigShare,
    SchnorrSigShare,
    VetKdKeyShare,
    VetKdEncryptedKeyShareContent,
    IDkgComplaintContent,
    SignedIDkgComplaint,
    IDkgOpeningContent,
    SignedIDkgOpening,
    CanisterHttpResponse,
    CryptoHashOfCanisterHttpResponseMetadata,
    CanisterHttpResponseShare,
}

impl DomainSeparator {
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            DomainSeparator::IcRequest => "ic-request",
            DomainSeparator::IcRequestAuthDelegation => "ic-request-auth-delegation",
            DomainSeparator::NotarizationContent => "notarization_content_domain",
            DomainSeparator::Notarization => "notarization_domain",
            DomainSeparator::NotarizationShare => "notarization_share_domain",
            DomainSeparator::FinalizationContent => "finalization_content_domain",
            DomainSeparator::Finalization => "finalization_domain",
            DomainSeparator::FinalizationShare => "finalization_share_domain",
            DomainSeparator::Block => "block_domain",
            DomainSeparator::_BlockProposal => "block_proposal_domain",
            DomainSeparator::BlockMetadata => "block_metadata_domain",
            DomainSeparator::BlockMetadataProposal => "block_metadata_proposal_domain",
            DomainSeparator::EquivocationProof => "equivocation_proof_domain",
            DomainSeparator::InmemoryPayload => "inmemory_payload_domain",
            DomainSeparator::RandomBeaconContent => "random_beacon_content_domain",
            DomainSeparator::RandomBeacon => "random_beacon_domain",
            DomainSeparator::RandomBeaconShare => "random_beacon_share_domain",
            DomainSeparator::CertificationContent => "ic-state-root",
            DomainSeparator::Certification => "certification_domain",
            DomainSeparator::CertificationShare => "certification_share_domain",
            DomainSeparator::DealingContent => "dealing_content_non_interactive",
            DomainSeparator::DkgMessage => "dkg_message_non_interactive",
            DomainSeparator::HttpCanisterUpdate => "http_canister_update_domain",
            DomainSeparator::SignedRequestBytes => "signed_request_bytes_domain",
            DomainSeparator::MessageId => "messageid_domain",
            DomainSeparator::_IcOnchainObservabilityReport => {
                "ic-onchain-observability-report-domain"
            }
            DomainSeparator::QueryResponse => "ic-response",
            DomainSeparator::RandomTapeContent => "random_tape_content_domain",
            DomainSeparator::RandomTape => "random_tape_domain",
            DomainSeparator::RandomTapeShare => "random_tape_share_domain",
            DomainSeparator::CatchUpContent => "catch_up_content_domain",
            DomainSeparator::CatchUpContentProto => "catch_up_content_proto_domain",
            DomainSeparator::CatchUpShareContent => "catch_up_share_content_domain",
            DomainSeparator::CatchUpPackage => "catch_up_package_domain",
            DomainSeparator::CatchUpPackageShare => "catch_up_package_share_domain",
            DomainSeparator::_StateSyncMessage => "state_sync_message_domain",
            DomainSeparator::ConsensusMessage => "consensus_message_domain",
            DomainSeparator::CertificationMessage => "certification_message_domain",
            DomainSeparator::IDkgMessage => "ic-threshold-ecdsa-message-domain",
            DomainSeparator::IdkgDealing => "ic-idkg-dealing-domain",
            DomainSeparator::SignedIdkgDealing => "ic-idkg-signed-dealing-domain",
            DomainSeparator::IdkgDealingSupport => "ic-idkg-dealing-support-domain",
            DomainSeparator::IDkgTranscript => "ic-idkg-transcript-domain",
            DomainSeparator::EcdsaSigShare => "ic-threshold-ecdsa-sig-share-domain",
            DomainSeparator::SchnorrSigShare => "ic-threshold-schnorr-sig-share-domain",
            DomainSeparator::VetKdKeyShare => "ic-vetkd-key-share-domain",
            DomainSeparator::VetKdEncryptedKeyShareContent => {
                "ic-vetkd-encrypted-key-share-content-domain"
            }
            DomainSeparator::IDkgComplaintContent => "ic-threshold-ecdsa-complaint-content-domain",
            DomainSeparator::SignedIDkgComplaint => "ic-threshold-ecdsa-complaint-domain",
            DomainSeparator::IDkgOpeningContent => "ic-threshold-ecdsa-opening-content-domain",
            DomainSeparator::SignedIDkgOpening => "ic-threshold-ecdsa-opening-domain",
            DomainSeparator::CanisterHttpResponse => "ic-canister-http-response-domain",
            DomainSeparator::CryptoHashOfCanisterHttpResponseMetadata => {
                "ic-crypto-hash-of-canister-http-response-metadata-domain"
            }
            DomainSeparator::CanisterHttpResponseShare => "ic-canister-http-response-share-domain",
        }
    }
}

impl std::fmt::Display for DomainSeparator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[test]
fn domain_separators_are_unique() {
    use strum::IntoEnumIterator;

    let mut unique_separators = std::collections::BTreeSet::<&str>::new();

    for s in DomainSeparator::iter() {
        assert!(
            unique_separators.insert(s.as_str()),
            "Another domain separator with the same name exists: {}",
            s.as_str()
        );
    }
}

#[test]
fn ic_request_domain_variable_is_sound_and_consistent_with_the_enum_variant() {
    use crate::crypto::DOMAIN_IC_REQUEST;
    assert_eq!(
        DOMAIN_IC_REQUEST[1..],
        *DomainSeparator::IcRequest.as_str().as_bytes()
    );
    assert_eq!(
        DOMAIN_IC_REQUEST[0] as usize,
        DomainSeparator::IcRequest.as_str().len()
    );
}

/// Stability test for domain separators used in crypto_hash.
///
/// This test ensures that the domain separator strings returned by each type
/// implementing CryptoHashDomain remain stable. Changing these strings would
/// change the hash output for all instances of that type, potentially breaking
/// consensus or other cryptographic protocols.
///
/// If you need to add a new type, add its expected domain string here.
/// DO NOT modify existing domain strings unless you understand the full impact.
#[test]
fn domain_separators_are_stable() {
    use super::domain_separator::DomainSeparator;
    use strum::IntoEnumIterator;

    // Expected domain separator strings - these MUST NOT change
    let expected_domains: Vec<(&str, &str)> = vec![
        ("IcRequest", "ic-request"),
        ("IcRequestAuthDelegation", "ic-request-auth-delegation"),
        ("NotarizationContent", "notarization_content_domain"),
        ("Notarization", "notarization_domain"),
        ("NotarizationShare", "notarization_share_domain"),
        ("FinalizationContent", "finalization_content_domain"),
        ("Finalization", "finalization_domain"),
        ("FinalizationShare", "finalization_share_domain"),
        ("Block", "block_domain"),
        ("_BlockProposal", "block_proposal_domain"),
        ("BlockMetadata", "block_metadata_domain"),
        ("BlockMetadataProposal", "block_metadata_proposal_domain"),
        ("EquivocationProof", "equivocation_proof_domain"),
        ("InmemoryPayload", "inmemory_payload_domain"),
        ("RandomBeaconContent", "random_beacon_content_domain"),
        ("RandomBeacon", "random_beacon_domain"),
        ("RandomBeaconShare", "random_beacon_share_domain"),
        ("CertificationContent", "ic-state-root"),
        ("Certification", "certification_domain"),
        ("CertificationShare", "certification_share_domain"),
        ("DealingContent", "dealing_content_non_interactive"),
        ("DkgMessage", "dkg_message_non_interactive"),
        ("HttpCanisterUpdate", "http_canister_update_domain"),
        ("SignedRequestBytes", "signed_request_bytes_domain"),
        ("MessageId", "messageid_domain"),
        (
            "_IcOnchainObservabilityReport",
            "ic-onchain-observability-report-domain",
        ),
        ("QueryResponse", "ic-response"),
        ("RandomTapeContent", "random_tape_content_domain"),
        ("RandomTape", "random_tape_domain"),
        ("RandomTapeShare", "random_tape_share_domain"),
        ("CatchUpContent", "catch_up_content_domain"),
        ("CatchUpContentProto", "catch_up_content_proto_domain"),
        ("CatchUpShareContent", "catch_up_share_content_domain"),
        ("CatchUpPackage", "catch_up_package_domain"),
        ("CatchUpPackageShare", "catch_up_package_share_domain"),
        ("_StateSyncMessage", "state_sync_message_domain"),
        ("ConsensusMessage", "consensus_message_domain"),
        ("CertificationMessage", "certification_message_domain"),
        ("IDkgMessage", "ic-threshold-ecdsa-message-domain"),
        ("IdkgDealing", "ic-idkg-dealing-domain"),
        ("SignedIdkgDealing", "ic-idkg-signed-dealing-domain"),
        ("IdkgDealingSupport", "ic-idkg-dealing-support-domain"),
        ("IDkgTranscript", "ic-idkg-transcript-domain"),
        ("EcdsaSigShare", "ic-threshold-ecdsa-sig-share-domain"),
        ("SchnorrSigShare", "ic-threshold-schnorr-sig-share-domain"),
        ("VetKdKeyShare", "ic-vetkd-key-share-domain"),
        (
            "VetKdEncryptedKeyShareContent",
            "ic-vetkd-encrypted-key-share-content-domain",
        ),
        (
            "IDkgComplaintContent",
            "ic-threshold-ecdsa-complaint-content-domain",
        ),
        ("SignedIDkgComplaint", "ic-threshold-ecdsa-complaint-domain"),
        (
            "IDkgOpeningContent",
            "ic-threshold-ecdsa-opening-content-domain",
        ),
        ("SignedIDkgOpening", "ic-threshold-ecdsa-opening-domain"),
        ("CanisterHttpResponse", "ic-canister-http-response-domain"),
        (
            "CryptoHashOfCanisterHttpResponseMetadata",
            "ic-crypto-hash-of-canister-http-response-metadata-domain",
        ),
        (
            "CanisterHttpResponseShare",
            "ic-canister-http-response-share-domain",
        ),
    ];

    // Build a map from variant name to expected domain string
    let expected_map: std::collections::HashMap<&str, &str> =
        expected_domains.iter().cloned().collect();

    // Verify all DomainSeparator variants have stable domain strings
    for variant in DomainSeparator::iter() {
        let variant_name = format!("{:?}", variant);
        let actual_domain = variant.as_str();

        let expected_domain = expected_map.get(variant_name.as_str()).unwrap_or_else(|| {
            panic!(
                "Missing expected domain for variant '{}'. \
                If this is a new variant, add it to expected_domains with value: \"{}\"",
                variant_name, actual_domain
            )
        });

        assert_eq!(
            actual_domain, *expected_domain,
            "Domain separator for {:?} has changed from '{}' to '{}'. \
            This is a breaking change that affects hash outputs!",
            variant, expected_domain, actual_domain
        );
    }

    // Also verify we haven't removed any expected domains
    assert_eq!(
        expected_domains.len(),
        DomainSeparator::iter().count(),
        "Number of domain separators changed. Expected {}, got {}. \
        If you removed a variant, remove it from expected_domains too.",
        expected_domains.len(),
        DomainSeparator::iter().count()
    );
}
