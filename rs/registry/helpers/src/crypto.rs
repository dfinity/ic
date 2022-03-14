use crate::deserialize_registry_value;
use ic_interfaces::registry::{
    RegistryClient, RegistryClientResult, RegistryClientVersionedResult, RegistryVersionedRecord,
};
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::{
    crypto::v1::X509PublicKeyCert,
    subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord},
};
use ic_registry_keys::make_crypto_node_key;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_crypto_tls_cert_key,
};
use ic_types::crypto::threshold_sig::{
    ni_dkg::{
        config::{receivers::NiDkgReceivers, NiDkgThreshold},
        NiDkgId, NiDkgTranscript,
    },
    ThresholdSigPublicKey,
};
use ic_types::{crypto::KeyPurpose, NodeId, NumberOfNodes, PrincipalId, RegistryVersion, SubnetId};
use std::collections::BTreeSet;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Contains initial DKG transcripts used to bootstrap a subnet.
pub struct DkgTranscripts {
    pub low_threshold: NiDkgTranscript,
    pub high_threshold: NiDkgTranscript,
}

pub trait CryptoRegistry {
    fn get_crypto_key_for_node(
        &self,
        node_id: NodeId,
        key_purpose: KeyPurpose,
        version: RegistryVersion,
    ) -> RegistryClientResult<PublicKeyProto>;

    fn get_threshold_signing_public_key_for_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ThresholdSigPublicKey>;

    fn get_tls_certificate(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<X509PublicKeyCert>;

    /// Returns initial DKG key material for the subnet and the registry
    /// version, at which this key material was inserted. This registry
    /// version will be used in the genesis summary.
    fn get_initial_dkg_transcripts(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<DkgTranscripts>;
}

impl<T: RegistryClient + ?Sized> CryptoRegistry for T {
    fn get_crypto_key_for_node(
        &self,
        node_id: NodeId,
        key_purpose: KeyPurpose,
        version: RegistryVersion,
    ) -> RegistryClientResult<PublicKeyProto> {
        let bytes = self.get_value(&make_crypto_node_key(node_id, key_purpose), version);
        deserialize_registry_value::<PublicKeyProto>(bytes)
    }

    fn get_threshold_signing_public_key_for_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ThresholdSigPublicKey> {
        let bytes = self.get_value(
            &make_crypto_threshold_signing_pubkey_key(subnet_id),
            version,
        );
        let option_public_key_proto = deserialize_registry_value::<PublicKeyProto>(bytes)?;
        let option_threshold_sig_pubkey = option_public_key_proto.map(|public_key_proto| {
            ThresholdSigPublicKey::try_from(public_key_proto).unwrap_or_else(|e| {
                panic!(
                    "Failed to convert registry data to threshold signing public key: {:?}. \
                     This indicates that the key was not (properly) checked to be well-formed \
                     and valid as part of the process that added the key to registry.",
                    e
                )
            })
        });
        Ok(option_threshold_sig_pubkey)
    }

    fn get_tls_certificate(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<X509PublicKeyCert> {
        let bytes = self.get_value(&make_crypto_tls_cert_key(node_id), version);
        deserialize_registry_value::<X509PublicKeyCert>(bytes)
    }

    fn get_initial_dkg_transcripts(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<DkgTranscripts> {
        let record =
            self.get_versioned_value(&make_catch_up_package_contents_key(subnet_id), version)?;
        let bytes = Ok(record.value);
        let version = record.version;
        let value =
            deserialize_registry_value::<CatchUpPackageContents>(bytes).map(|maybe_value| {
                maybe_value.map(|value| DkgTranscripts {
                    low_threshold: value
                        .initial_ni_dkg_transcript_low_threshold
                        .map(initial_ni_dkg_transcript_from_registry_record)
                        .expect("Missing initial low-threshold DKG transcript"),
                    high_threshold: value
                        .initial_ni_dkg_transcript_high_threshold
                        .map(initial_ni_dkg_transcript_from_registry_record)
                        .expect("Missing initial high-threshold DKG transcript"),
                })
            })?;
        Ok(RegistryVersionedRecord {
            key: record.key,
            version,
            value,
        })
    }
}

pub fn initial_ni_dkg_transcript_from_registry_record(
    dkg_transcript_record: InitialNiDkgTranscriptRecord,
) -> NiDkgTranscript {
    let dkg_id_record = dkg_transcript_record.id.expect("missing NI-DKG ID");
    let dkg_id = NiDkgId::try_from(dkg_id_record).expect("invalid dkg id");
    let committee: BTreeSet<NodeId> = dkg_transcript_record
        .committee
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).expect("invalid principal ID")))
        .collect();
    NiDkgTranscript {
        dkg_id,
        threshold: NiDkgThreshold::new(NumberOfNodes::new(dkg_transcript_record.threshold))
            .expect("invalid threshold"),
        committee: NiDkgReceivers::new(committee).expect("invalid committee"),
        registry_version: RegistryVersion::new(dkg_transcript_record.registry_version),
        internal_csp_transcript: serde_cbor::from_slice(
            dkg_transcript_record.internal_csp_transcript.as_slice(),
        )
        .expect("failed to deserialize CSP NI-DKG transcript from CBOR"),
    }
}
