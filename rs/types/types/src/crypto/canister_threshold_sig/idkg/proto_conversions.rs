use crate::crypto::ExtendedDerivationPath;
use crate::crypto::canister_threshold_sig::error::InitialIDkgDealingsValidationError;
use crate::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealing, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType, InitialIDkgDealings,
    SignedIDkgDealing,
};
use crate::crypto::canister_threshold_sig::{
    EcdsaPreSignatureQuadruple, SchnorrPreSignatureTranscript,
};
use crate::crypto::{AlgorithmId, BasicSig, BasicSigOf, CryptoHashOf};
use crate::signature::{BasicSignature, BasicSignatureBatch};
use crate::{Height, NodeIndex, node_id_into_protobuf, node_id_try_from_option};
use ic_base_types::{NodeId, RegistryVersion, subnet_id_into_protobuf, subnet_id_try_from_option};
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::registry::subnet::v1::ExtendedDerivationPath as ExtendedDerivationPathProto;
use ic_protobuf::registry::subnet::v1::IDkgComplaint as IDkgComplaintProto;
use ic_protobuf::registry::subnet::v1::IDkgDealing as IDkgDealingProto;
use ic_protobuf::registry::subnet::v1::IDkgOpening as IDkgOpeningProto;
use ic_protobuf::registry::subnet::v1::IDkgSignedDealingTuple as IDkgSignedDealingTupleProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscript as IDkgTranscriptProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptId as IDkgTranscriptIdProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptOperation as IDkgTranscriptOperationProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptParams as IDkgTranscriptParamsProto;
use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
use ic_protobuf::registry::subnet::v1::VerifiedIDkgDealing as VerifiedIDkgDealingProto;
use ic_protobuf::registry::subnet::v1::{DealerTuple as DealerTupleProto, SignatureTuple};
use ic_protobuf::types::v1::BasicSignature as BasicSignatureProto;
use ic_protobuf::types::v1::EcdsaPreSignatureQuadruple as EcdsaPreSignatureQuadrupleProto;
use ic_protobuf::types::v1::IDkgDealingSupport as IDkgDealingSupportProto;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use ic_protobuf::types::v1::SchnorrPreSignatureTranscript as SchnorrPreSignatureTranscriptProto;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::Arc;

use super::{IDkgComplaint, IDkgDealingSupport, IDkgOpening};

const CURRENT_INITIAL_IDKG_DEALINGS_VERSION: u32 = 0;

impl From<&IDkgTranscriptId> for IDkgTranscriptIdProto {
    fn from(transcript_id: &IDkgTranscriptId) -> Self {
        IDkgTranscriptIdProto {
            id: transcript_id.id(),
            subnet_id: Some(subnet_id_into_protobuf(*transcript_id.source_subnet())),
            source_height: transcript_id.source_height().get(),
        }
    }
}

impl TryFrom<&IDkgTranscriptIdProto> for IDkgTranscriptId {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgTranscriptIdProto) -> Result<Self, Self::Error> {
        Ok(IDkgTranscriptId::new(
            subnet_id_try_from_option(proto.subnet_id.clone(), "IDkgTranscriptId::subnet_id")?,
            proto.id,
            Height::from(proto.source_height),
        ))
    }
}

impl From<&IDkgTranscript> for IDkgTranscriptProto {
    fn from(transcript: &IDkgTranscript) -> Self {
        idkg_transcript_proto(transcript)
    }
}

impl TryFrom<&IDkgTranscriptProto> for IDkgTranscript {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgTranscriptProto) -> Result<Self, Self::Error> {
        idkg_transcript_struct(proto)
    }
}

impl From<&InitialIDkgDealings> for InitialIDkgDealingsProto {
    fn from(initial_dealings: &InitialIDkgDealings) -> Self {
        let signed_dealings = initial_dealings
            .dealings()
            .iter()
            .map(signed_idkg_dealing_tuple_proto)
            .collect();
        InitialIDkgDealingsProto {
            version: CURRENT_INITIAL_IDKG_DEALINGS_VERSION,
            params: Some(idkg_transcript_params_proto(initial_dealings.params())),
            signed_dealings,
        }
    }
}

impl TryFrom<&InitialIDkgDealingsProto> for InitialIDkgDealings {
    type Error = ProxyDecodeError;

    fn try_from(proto: &InitialIDkgDealingsProto) -> Result<Self, Self::Error> {
        let params_proto = proto.params.as_ref().ok_or(
            InitialIDkgDealingsValidationError::DeserializationError {
                error: "Missing IDkgTranscriptParams.".to_string(),
            },
        )?;
        let params = idkg_transcript_params_struct(params_proto)?;
        let dealings = initial_dealings_vec(&proto.signed_dealings)?;
        Ok(InitialIDkgDealings::new(params, dealings)?)
    }
}

impl From<&IDkgOpening> for IDkgOpeningProto {
    fn from(value: &IDkgOpening) -> Self {
        Self {
            transcript_id: Some(IDkgTranscriptIdProto::from(&value.transcript_id)),
            dealer: Some(node_id_into_protobuf(value.dealer_id)),
            raw_opening: value.internal_opening_raw.clone(),
        }
    }
}

impl TryFrom<&IDkgOpeningProto> for IDkgOpening {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgOpeningProto) -> Result<Self, Self::Error> {
        Ok(Self {
            transcript_id: try_from_option_field(
                proto.transcript_id.as_ref(),
                "IDkgOpening::transcript_id",
            )?,
            dealer_id: node_id_try_from_option(proto.dealer.clone())?,
            internal_opening_raw: proto.raw_opening.clone(),
        })
    }
}

impl From<&IDkgComplaint> for IDkgComplaintProto {
    fn from(value: &IDkgComplaint) -> Self {
        Self {
            transcript_id: Some(IDkgTranscriptIdProto::from(&value.transcript_id)),
            dealer: Some(node_id_into_protobuf(value.dealer_id)),
            raw_complaint: value.internal_complaint_raw.clone(),
        }
    }
}

impl TryFrom<&IDkgComplaintProto> for IDkgComplaint {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgComplaintProto) -> Result<Self, Self::Error> {
        Ok(Self {
            transcript_id: try_from_option_field(
                proto.transcript_id.as_ref(),
                "IDkgComplaint::transcript_id",
            )?,
            dealer_id: node_id_try_from_option(proto.dealer.clone())?,
            internal_complaint_raw: proto.raw_complaint.clone(),
        })
    }
}

impl From<ExtendedDerivationPath> for ExtendedDerivationPathProto {
    fn from(path: ExtendedDerivationPath) -> Self {
        ExtendedDerivationPathProto {
            caller: Some(PrincipalIdProto::from(path.caller)),
            derivation_path: path.derivation_path,
        }
    }
}

impl TryFrom<ExtendedDerivationPathProto> for ExtendedDerivationPath {
    type Error = ProxyDecodeError;
    fn try_from(proto: ExtendedDerivationPathProto) -> Result<Self, Self::Error> {
        Ok(ExtendedDerivationPath {
            caller: try_from_option_field(proto.caller, "ExtendedDerivationPath::caller")?,
            derivation_path: proto.derivation_path,
        })
    }
}

impl From<&IDkgDealingSupport> for IDkgDealingSupportProto {
    fn from(value: &IDkgDealingSupport) -> Self {
        Self {
            transcript_id: Some(IDkgTranscriptIdProto::from(&value.transcript_id)),
            dealer: Some(node_id_into_protobuf(value.dealer_id)),
            dealing_hash: value.dealing_hash.clone().get().0,
            sig_share: Some(BasicSignatureProto::from(value.sig_share.clone())),
        }
    }
}

impl TryFrom<&IDkgDealingSupportProto> for IDkgDealingSupport {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgDealingSupportProto) -> Result<Self, Self::Error> {
        Ok(Self {
            transcript_id: try_from_option_field(
                proto.transcript_id.as_ref(),
                "IDkgDealingSupport::transcript_id",
            )?,
            dealer_id: node_id_try_from_option(proto.dealer.clone())?,
            dealing_hash: CryptoHashOf::new(crate::crypto::CryptoHash(proto.dealing_hash.clone())),
            sig_share: try_from_option_field(
                proto.sig_share.clone(),
                "IDkgDealingSupport::sig_share",
            )?,
        })
    }
}

impl From<&SignedIDkgDealing> for IDkgSignedDealingTupleProto {
    fn from(value: &SignedIDkgDealing) -> Self {
        signed_idkg_dealing_tuple_proto(value)
    }
}

impl TryFrom<&IDkgSignedDealingTupleProto> for SignedIDkgDealing {
    type Error = ProxyDecodeError;

    fn try_from(proto: &IDkgSignedDealingTupleProto) -> Result<Self, Self::Error> {
        let idkg_dealing_proto = proto
            .dealing
            .as_ref()
            .ok_or(ProxyDecodeError::Other("Missing IDkgDealing.".to_string()))?;
        let idkg_dealing = IDkgDealing {
            transcript_id: try_from_option_field(
                idkg_dealing_proto.transcript_id.as_ref(),
                "IDkgDealing::transcript_id",
            )?,
            internal_dealing_raw: idkg_dealing_proto.raw_dealing.clone(),
        };
        let basic_signature = BasicSignature {
            signature: BasicSigOf::new(BasicSig(proto.signature.clone())),
            signer: node_id_try_from_option(proto.dealer.clone())?,
        };
        Ok(SignedIDkgDealing {
            content: idkg_dealing,
            signature: basic_signature,
        })
    }
}

impl From<&EcdsaPreSignatureQuadruple> for EcdsaPreSignatureQuadrupleProto {
    fn from(value: &EcdsaPreSignatureQuadruple) -> Self {
        Self {
            kappa_unmasked: Some(idkg_transcript_proto(&value.kappa_unmasked)),
            lambda_masked: Some(idkg_transcript_proto(&value.lambda_masked)),
            kappa_times_lambda: Some(idkg_transcript_proto(&value.kappa_times_lambda)),
            key_times_lambda: Some(idkg_transcript_proto(&value.key_times_lambda)),
        }
    }
}

impl TryFrom<&EcdsaPreSignatureQuadrupleProto> for EcdsaPreSignatureQuadruple {
    type Error = ProxyDecodeError;

    fn try_from(proto: &EcdsaPreSignatureQuadrupleProto) -> Result<Self, Self::Error> {
        Ok(Self {
            kappa_unmasked: try_from_option_field(
                proto.kappa_unmasked.as_ref(),
                "EcdsaPreSignatureQuadruple::kappa_unmasked",
            )?,
            lambda_masked: try_from_option_field(
                proto.lambda_masked.as_ref(),
                "EcdsaPreSignatureQuadruple::lambda_masked",
            )?,
            kappa_times_lambda: try_from_option_field(
                proto.kappa_times_lambda.as_ref(),
                "EcdsaPreSignatureQuadruple::kappa_times_lambda",
            )?,
            key_times_lambda: try_from_option_field(
                proto.key_times_lambda.as_ref(),
                "EcdsaPreSignatureQuadruple::key_times_lambda",
            )?,
        })
    }
}

impl From<&SchnorrPreSignatureTranscript> for SchnorrPreSignatureTranscriptProto {
    fn from(value: &SchnorrPreSignatureTranscript) -> Self {
        Self {
            blinder_unmasked: Some(idkg_transcript_proto(&value.blinder_unmasked)),
        }
    }
}

impl TryFrom<&SchnorrPreSignatureTranscriptProto> for SchnorrPreSignatureTranscript {
    type Error = ProxyDecodeError;

    fn try_from(proto: &SchnorrPreSignatureTranscriptProto) -> Result<Self, Self::Error> {
        Ok(Self {
            blinder_unmasked: try_from_option_field(
                proto.blinder_unmasked.as_ref(),
                "SchnorrPreSignatureTranscript::blinder_unmasked",
            )?,
        })
    }
}

// ----- Conversion helpers.
fn idkg_transcript_params_proto(params: &IDkgTranscriptParams) -> IDkgTranscriptParamsProto {
    let idkg_transcript_operation_args = match params.operation_type() {
        IDkgTranscriptOperation::Random => vec![],
        IDkgTranscriptOperation::RandomUnmasked => vec![],
        IDkgTranscriptOperation::ReshareOfMasked(idkg_transcript) => {
            vec![idkg_transcript_proto(idkg_transcript)]
        }
        IDkgTranscriptOperation::ReshareOfUnmasked(idkg_transcript) => {
            vec![idkg_transcript_proto(idkg_transcript)]
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(idkg_transcript_1, idkg_transcript_2) => vec![
            idkg_transcript_proto(idkg_transcript_1),
            idkg_transcript_proto(idkg_transcript_2),
        ],
    };
    IDkgTranscriptParamsProto {
        transcript_id: Some(IDkgTranscriptIdProto::from(&params.transcript_id())),
        dealers: params
            .dealers()
            .iter()
            .map(|(dealer_index, dealer_id)| DealerTupleProto {
                dealer_id: Some(node_id_into_protobuf(dealer_id)),
                dealer_index,
            })
            .collect(),
        receivers: params
            .receivers()
            .iter()
            .map(|(_node_index, node_id)| node_id_into_protobuf(node_id))
            .collect(),
        registry_version: params.registry_version().get(),
        algorithm_id: params.algorithm_id() as i32,
        idkg_transcript_operation: idkg_transcript_operation_type_proto(params.operation_type())
            as i32,
        idkg_transcript_operation_args,
    }
}

fn idkg_transcript_operation_type_proto(
    op_type: &IDkgTranscriptOperation,
) -> IDkgTranscriptOperationProto {
    match op_type {
        IDkgTranscriptOperation::Random => IDkgTranscriptOperationProto::Random,
        IDkgTranscriptOperation::RandomUnmasked => IDkgTranscriptOperationProto::RandomUnmasked,
        IDkgTranscriptOperation::ReshareOfMasked(_) => {
            IDkgTranscriptOperationProto::ReshareOfMasked
        }
        IDkgTranscriptOperation::ReshareOfUnmasked(_) => {
            IDkgTranscriptOperationProto::ReshareOfUnmasked
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(_, _) => {
            IDkgTranscriptOperationProto::UnmaskedTimesMasked
        }
    }
}

fn idkg_transcript_operation_enum(
    op: i32,
    op_args: &[IDkgTranscriptProto],
) -> Result<IDkgTranscriptOperation, ProxyDecodeError> {
    match op {
        // IDkgTranscriptOperationProto::Random
        1 => Ok(IDkgTranscriptOperation::Random),
        // IDkgTranscriptOperationProto::ReshareOfMasked
        2 => {
            if op_args.len() != 1 {
                return Err(ProxyDecodeError::Other(format!(
                    "Wrong number of arguments for operation ReshareOfMasked: {}",
                    op_args.len()
                )));
            };
            let transcript = idkg_transcript_struct(&op_args[0])?;
            Ok(IDkgTranscriptOperation::ReshareOfMasked(transcript))
        }
        // IDkgTranscriptOperationProto::ReshareOfUnmasked
        3 => {
            if op_args.len() != 1 {
                return Err(ProxyDecodeError::Other(format!(
                    "Wrong number of arguments for operation ReshareOfUnmasked: {}",
                    op_args.len()
                )));
            };
            let transcript = idkg_transcript_struct(&op_args[0])?;
            Ok(IDkgTranscriptOperation::ReshareOfUnmasked(transcript))
        }
        // IDkgTranscriptOperationProto::UnmaskedTimesMasked
        4 => {
            if op_args.len() != 2 {
                return Err(ProxyDecodeError::Other(format!(
                    "Wrong number of arguments for operation UnmaskedTimesMasked: {}",
                    op_args.len()
                )));
            };
            let transcript_1 = idkg_transcript_struct(&op_args[0])?;
            let transcript_2 = idkg_transcript_struct(&op_args[1])?;
            Ok(IDkgTranscriptOperation::UnmaskedTimesMasked(
                transcript_1,
                transcript_2,
            ))
        }
        // IDkgTranscriptOperationProto::Unspecified, other
        _ => Err(ProxyDecodeError::Other(
            "Unspecified transcript operation in IDkgTranscriptParams".to_string(),
        )),
    }
}

fn idkg_transcript_params_struct(
    proto: &IDkgTranscriptParamsProto,
) -> Result<IDkgTranscriptParams, ProxyDecodeError> {
    let transcript_id: IDkgTranscriptId = try_from_option_field(
        proto.transcript_id.as_ref(),
        "IDkgTranscriptParams::transcript_id",
    )?;

    let dealers: Result<Vec<_>, _> = proto
        .dealers
        .iter()
        .map(|tuple| node_id_try_from_option(tuple.dealer_id.clone()))
        .collect();
    let dealers = BTreeSet::from_iter(dealers?.iter().cloned());

    let receivers: Result<Vec<_>, _> = proto
        .receivers
        .iter()
        .map(|node_id| node_id_try_from_option(Some(node_id.clone())))
        .collect();
    let receivers = BTreeSet::from_iter(receivers?.iter().cloned());
    let params = IDkgTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        RegistryVersion::new(proto.registry_version),
        AlgorithmId::from(proto.algorithm_id),
        idkg_transcript_operation_enum(
            proto.idkg_transcript_operation,
            &proto.idkg_transcript_operation_args,
        )?,
    )
    .map_err(
        |e| InitialIDkgDealingsValidationError::DeserializationError {
            error: format!("Error deserializing transcript params: {e}"),
        },
    )?;
    Ok(params)
}

fn idkg_transcript_proto(idkg_transcript: &IDkgTranscript) -> IDkgTranscriptProto {
    let verified_dealings = idkg_transcript
        .verified_dealings
        .iter()
        .map(|(node_index, signed_dealing)| verified_idkg_dealing_proto(node_index, signed_dealing))
        .collect();
    // TODO(CRP-1403): construct real `dealers` once `IDkgTranscript.dealers` exists.
    let dealers = vec![];
    IDkgTranscriptProto {
        transcript_id: Some(IDkgTranscriptIdProto::from(&idkg_transcript.transcript_id)),
        receivers: idkg_transcript
            .receivers
            .iter()
            .map(|(_node_index, node_id)| node_id_into_protobuf(node_id))
            .collect(),
        dealers,
        registry_version: idkg_transcript.registry_version.get(),
        verified_dealings,
        transcript_type: serde_cbor::to_vec(&idkg_transcript.transcript_type)
            .expect("failed to serialize IDkgTranscriptType to CBOR"),
        algorithm_id: idkg_transcript.algorithm_id as i32,
        raw_transcript: idkg_transcript.internal_transcript_raw.clone(),
    }
}

fn idkg_transcript_struct(proto: &IDkgTranscriptProto) -> Result<IDkgTranscript, ProxyDecodeError> {
    let transcript_id: IDkgTranscriptId = try_from_option_field(
        proto.transcript_id.as_ref(),
        "IDkgTranscript::transcript_id",
    )?;

    let receivers: Result<Vec<_>, _> = proto
        .receivers
        .iter()
        .map(|node_id| node_id_try_from_option(Some(node_id.clone())))
        .collect();
    let receivers = BTreeSet::from_iter(receivers?.iter().cloned());
    let receivers = IDkgReceivers::new(receivers).map_err(|e| {
        InitialIDkgDealingsValidationError::DeserializationError {
            error: format!("Error deserializing receivers: {e}"),
        }
    })?;
    let transcript_type: IDkgTranscriptType = serde_cbor::from_slice(&proto.transcript_type)
        .map_err(
            |e| InitialIDkgDealingsValidationError::DeserializationError {
                error: format!("Error deserializing IDkgTranscriptType: {e}"),
            },
        )?;
    let verified_dealings = verified_dealings_map(&proto.verified_dealings)?;
    Ok(IDkgTranscript {
        transcript_id,
        receivers,
        registry_version: RegistryVersion::new(proto.registry_version),
        verified_dealings: Arc::new(verified_dealings),
        transcript_type,
        algorithm_id: AlgorithmId::from(proto.algorithm_id),
        internal_transcript_raw: proto.raw_transcript.clone(),
    })
}

fn signed_idkg_dealing_tuple_proto(
    signed_dealing: &SignedIDkgDealing,
) -> IDkgSignedDealingTupleProto {
    let idkg_dealing = signed_dealing.idkg_dealing();
    let dealing = IDkgDealingProto {
        transcript_id: Some(IDkgTranscriptIdProto::from(&idkg_dealing.transcript_id)),
        raw_dealing: idkg_dealing.internal_dealing_raw.clone(),
    };
    IDkgSignedDealingTupleProto {
        dealer: Some(node_id_into_protobuf(signed_dealing.dealer_id())),
        dealing: Some(dealing),
        signature: signed_dealing.signature.signature.as_ref().0.clone(),
    }
}

fn verified_idkg_dealing_proto(
    dealer_index: &NodeIndex,
    signed_dealing: &BatchSignedIDkgDealing,
) -> VerifiedIDkgDealingProto {
    VerifiedIDkgDealingProto {
        dealer_index: *dealer_index,
        signed_dealing_tuple: Some(signed_idkg_dealing_tuple_proto(
            signed_dealing.signed_idkg_dealing(),
        )),
        support_tuples: signed_dealing
            .signature
            .signatures_map
            .iter()
            .map(|(signer, signature)| signature_tuple_proto(*signer, signature.clone()))
            .collect(),
    }
}

fn signature_tuple_proto(
    signer: NodeId,
    signature: BasicSigOf<SignedIDkgDealing>,
) -> SignatureTuple {
    SignatureTuple {
        signer: Some(node_id_into_protobuf(signer)),
        signature: signature.get().0,
    }
}

fn verified_dealings_map(
    verified_protos: &[VerifiedIDkgDealingProto],
) -> Result<BTreeMap<NodeIndex, BatchSignedIDkgDealing>, ProxyDecodeError> {
    let mut result = BTreeMap::new();
    for proto in verified_protos {
        let node_index = proto.dealer_index;
        let signed_dealing: SignedIDkgDealing = try_from_option_field(
            proto.signed_dealing_tuple.as_ref(),
            "VerifiedIDkgDealing::signed_dealing_tuple",
        )?;
        let batch_signed_dealing = BatchSignedIDkgDealing {
            content: signed_dealing,
            signature: basic_signature_batch_struct(&proto.support_tuples)?,
        };
        result.insert(node_index, batch_signed_dealing);
    }
    Ok(result)
}

fn basic_signature_batch_struct(
    signature_batch: &[SignatureTuple],
) -> Result<BasicSignatureBatch<SignedIDkgDealing>, ProxyDecodeError> {
    let mut signatures_map = BTreeMap::new();
    for tuple in signature_batch {
        let signer = node_id_try_from_option(tuple.signer.clone())?;
        let signature = BasicSigOf::new(BasicSig(tuple.signature.clone()));
        if signatures_map.insert(signer, signature).is_some() {
            return Err(
                InitialIDkgDealingsValidationError::MultipleSupportSharesFromSameReceiver {
                    node_id: signer,
                }
                .into(),
            );
        };
    }
    Ok(BasicSignatureBatch { signatures_map })
}

fn initial_dealings_vec(
    dealing_tuple_protos: &[IDkgSignedDealingTupleProto],
) -> Result<Vec<SignedIDkgDealing>, ProxyDecodeError> {
    let mut result = Vec::new();
    for proto in dealing_tuple_protos {
        result.push(SignedIDkgDealing::try_from(proto)?);
    }
    Ok(result)
}
