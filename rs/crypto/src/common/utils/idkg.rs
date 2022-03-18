use ic_base_types::{
    subnet_id_into_protobuf, subnet_id_try_from_protobuf, NodeId, RegistryVersion,
};
use ic_protobuf::registry::subnet::v1::DealerTuple as DealerTupleProto;
use ic_protobuf::registry::subnet::v1::IDkgDealing as IDkgDealingProto;
use ic_protobuf::registry::subnet::v1::IDkgDealingTuple as IDkgDealingTupleProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscript as IDkgTranscriptProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptId as IDkgTranscriptIdProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptOperation as IDkgTranscriptOperationProto;
use ic_protobuf::registry::subnet::v1::IDkgTranscriptParams as IDkgTranscriptParamsProto;
use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
use ic_protobuf::registry::subnet::v1::VerifiedIDkgDealing as VerifiedIDkgDealingProto;
use ic_protobuf::types::v1::NodeId as NodeIdProto;
use ic_types::consensus::ecdsa::EcdsaDealing;
use ic_types::crypto::canister_threshold_sig::error::InitialIDkgDealingsValidationError;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgMultiSignedDealing, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType, InitialIDkgDealings,
};
use ic_types::crypto::{AlgorithmId, CombinedMultiSig, CombinedMultiSigOf};
use ic_types::{node_id_into_protobuf, node_id_try_from_protobuf, Height, NodeIndex};
use std::collections::{BTreeMap, BTreeSet};
use std::iter::FromIterator;

#[cfg(test)]
mod tests;

const CURRENT_INITIAL_IDKG_DEALINGS_VERSION: u32 = 0;

/// Converts InitialIDkgDealings into the corresponding protobuf representation.
pub fn idkg_initial_dealings_to_proto(
    initial_dealings: InitialIDkgDealings,
) -> InitialIDkgDealingsProto {
    let dealings = initial_dealings
        .dealings()
        .iter()
        .map(|(dealer_id, idkg_dealing)| idkg_dealing_tuple_proto(dealer_id, idkg_dealing))
        .collect();
    InitialIDkgDealingsProto {
        version: CURRENT_INITIAL_IDKG_DEALINGS_VERSION,
        params: Some(idkg_transcript_params_proto(&initial_dealings.params())),
        dealings,
    }
}

/// Converts InitialIDkgDealings-proto into the corresponding Rust-struct representation.
pub fn idkg_initial_dealings_from_proto(
    initial_dealings_proto: InitialIDkgDealingsProto,
) -> Result<InitialIDkgDealings, InitialIDkgDealingsValidationError> {
    let params_proto = initial_dealings_proto.params.ok_or(
        InitialIDkgDealingsValidationError::DeserializationError {
            error: "Missing IDkgTranscriptParams.".to_string(),
        },
    )?;
    let params = idkg_transcript_params_struct(&params_proto)?;
    let dealings = initial_dealings_map(&initial_dealings_proto.dealings)?;
    InitialIDkgDealings::new(params, dealings)
}

// ----- Conversion helpers.
fn idkg_transcript_id_proto(idkg_transcript_id: &IDkgTranscriptId) -> IDkgTranscriptIdProto {
    IDkgTranscriptIdProto {
        id: idkg_transcript_id.id() as u64,
        subnet_id: Some(subnet_id_into_protobuf(*idkg_transcript_id.subnet())),
    }
}

fn idkg_transcript_id_struct(
    maybe_proto: &Option<IDkgTranscriptIdProto>,
) -> Result<IDkgTranscriptId, InitialIDkgDealingsValidationError> {
    let proto =
        maybe_proto
            .as_ref()
            .ok_or(InitialIDkgDealingsValidationError::DeserializationError {
                error: "Missing IDkgTranscriptId.".to_string(),
            })?;
    let subnet_id_proto = proto.subnet_id.as_ref().ok_or(
        InitialIDkgDealingsValidationError::DeserializationError {
            error: "Missing subnet id in IDkgTranscriptId.".to_string(),
        },
    )?;
    let subnet_id = subnet_id_try_from_protobuf(subnet_id_proto.clone()).map_err(|e| {
        InitialIDkgDealingsValidationError::DeserializationError {
            error: format!("Failure parsing subnet id in IDkgTranscriptId: {:?}", e),
        }
    })?;
    Ok(IDkgTranscriptId::new(subnet_id, proto.id as usize))
}

fn idkg_transcript_params_proto(params: &IDkgTranscriptParams) -> IDkgTranscriptParamsProto {
    let idkg_transcript_operation_args = match params.operation_type() {
        IDkgTranscriptOperation::Random => vec![],
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
        transcript_id: Some(idkg_transcript_id_proto(&params.transcript_id())),
        dealers: params
            .dealers()
            .iter()
            .map(|(dealer_index, dealer_id)| DealerTupleProto {
                dealer_id: Some(node_id_into_protobuf(dealer_id)),
                dealer_index: dealer_index as u32,
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
) -> Result<IDkgTranscriptOperation, InitialIDkgDealingsValidationError> {
    match op {
        // IDkgTranscriptOperationProto::Random
        1 => Ok(IDkgTranscriptOperation::Random),
        // IDkgTranscriptOperationProto::ReshareOfMasked
        2 => {
            if op_args.len() != 1 {
                return Err(InitialIDkgDealingsValidationError::DeserializationError {
                    error: format!(
                        "Wrong number of arguments for operation ReshareOfMasked: {}",
                        op_args.len()
                    ),
                });
            };
            let transcript = idkg_transcript_struct(&op_args[0])?;
            Ok(IDkgTranscriptOperation::ReshareOfMasked(transcript))
        }
        // IDkgTranscriptOperationProto::ReshareOfUnmasked
        3 => {
            if op_args.len() != 1 {
                return Err(InitialIDkgDealingsValidationError::DeserializationError {
                    error: format!(
                        "Wrong number of arguments for operation ReshareOfUnmasked: {}",
                        op_args.len()
                    ),
                });
            };
            let transcript = idkg_transcript_struct(&op_args[0])?;
            Ok(IDkgTranscriptOperation::ReshareOfUnmasked(transcript))
        }
        // IDkgTranscriptOperationProto::UnmaskedTimesMasked
        4 => {
            if op_args.len() != 2 {
                return Err(InitialIDkgDealingsValidationError::DeserializationError {
                    error: format!(
                        "Wrong number of arguments for operation UnmaskedTimesMasked: {}",
                        op_args.len()
                    ),
                });
            };
            let transcript_1 = idkg_transcript_struct(&op_args[0])?;
            let transcript_2 = idkg_transcript_struct(&op_args[1])?;
            Ok(IDkgTranscriptOperation::UnmaskedTimesMasked(
                transcript_1,
                transcript_2,
            ))
        }
        // IDkgTranscriptOperationProto::Unspecified, other
        _ => Err(InitialIDkgDealingsValidationError::DeserializationError {
            error: "Unspecified transcript operation in IDkgTranscriptParams".to_string(),
        }),
    }
}

fn node_id_struct(
    maybe_node_id_proto: &Option<NodeIdProto>,
) -> Result<NodeId, InitialIDkgDealingsValidationError> {
    if let Some(node_id_proto) = maybe_node_id_proto {
        Ok(
            node_id_try_from_protobuf(node_id_proto.clone()).map_err(|e| {
                InitialIDkgDealingsValidationError::DeserializationError {
                    error: e.to_string(),
                }
            })?,
        )
    } else {
        Err(InitialIDkgDealingsValidationError::DeserializationError {
            error: "Missing NodeId".to_string(),
        })
    }
}

fn idkg_transcript_params_struct(
    proto: &IDkgTranscriptParamsProto,
) -> Result<IDkgTranscriptParams, InitialIDkgDealingsValidationError> {
    let transcript_id = idkg_transcript_id_struct(&proto.transcript_id)?;

    let dealers: Result<Vec<_>, _> = proto
        .dealers
        .iter()
        .map(|tuple| node_id_struct(&tuple.dealer_id))
        .collect();
    let dealers = BTreeSet::from_iter(dealers?.iter().cloned());

    let receivers: Result<Vec<_>, _> = proto
        .receivers
        .iter()
        .map(|node_id| node_id_struct(&Some(node_id.clone())))
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
            error: format!("Error deserializing transcript params: {}", e),
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
        transcript_id: Some(idkg_transcript_id_proto(&idkg_transcript.transcript_id)),
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

fn idkg_transcript_struct(
    proto: &IDkgTranscriptProto,
) -> Result<IDkgTranscript, InitialIDkgDealingsValidationError> {
    let transcript_id = idkg_transcript_id_struct(&proto.transcript_id)?;

    let receivers: Result<Vec<_>, _> = proto
        .receivers
        .iter()
        .map(|node_id| node_id_struct(&Some(node_id.clone())))
        .collect();
    let receivers = BTreeSet::from_iter(receivers?.iter().cloned());
    let receivers = IDkgReceivers::new(receivers).map_err(|e| {
        InitialIDkgDealingsValidationError::DeserializationError {
            error: format!("Error deserializing receivers: {}", e),
        }
    })?;
    let transcript_type: IDkgTranscriptType = serde_cbor::from_slice(&proto.transcript_type)
        .map_err(
            |e| InitialIDkgDealingsValidationError::DeserializationError {
                error: format!("Error deserializing IDkgTranscriptType: {}", e),
            },
        )?;
    let verified_dealings = verified_dealings_map(&proto.verified_dealings)?;
    Ok(IDkgTranscript {
        transcript_id,
        receivers,
        registry_version: RegistryVersion::new(proto.registry_version),
        verified_dealings,
        transcript_type,
        algorithm_id: AlgorithmId::from(proto.algorithm_id),
        internal_transcript_raw: proto.raw_transcript.clone(),
    })
}

fn idkg_dealing_tuple_proto(
    dealer_id: &NodeId,
    idkg_dealing: &IDkgDealing,
) -> IDkgDealingTupleProto {
    let dealing = IDkgDealingProto {
        transcript_id: Some(idkg_transcript_id_proto(&idkg_dealing.transcript_id)),
        raw_dealing: idkg_dealing.internal_dealing_raw.clone(),
    };
    IDkgDealingTupleProto {
        dealer: Some(node_id_into_protobuf(*dealer_id)),
        dealing: Some(dealing),
    }
}

fn verified_idkg_dealing_proto(
    dealer_index: &NodeIndex,
    signed_dealing: &IDkgMultiSignedDealing,
) -> VerifiedIDkgDealingProto {
    VerifiedIDkgDealingProto {
        dealer_index: *dealer_index as u32,
        signature: signed_dealing.signature.as_ref().0.clone(),
        signers: signed_dealing
            .signers
            .iter()
            .map(|node_id| node_id_into_protobuf(*node_id))
            .collect(),
        requested_height: signed_dealing.dealing.requested_height.get(),
        dealing_tuple: Some(idkg_dealing_tuple_proto(
            &signed_dealing.dealing.idkg_dealing.dealer_id,
            &signed_dealing.dealing.idkg_dealing,
        )),
    }
}

fn idkg_dealing_struct(
    maybe_proto: &Option<IDkgDealingTupleProto>,
) -> Result<IDkgDealing, InitialIDkgDealingsValidationError> {
    let proto =
        maybe_proto
            .as_ref()
            .ok_or(InitialIDkgDealingsValidationError::DeserializationError {
                error: "Missing IDkgDealingTuple.".to_string(),
            })?;
    let dealing_proto =
        proto
            .dealing
            .as_ref()
            .ok_or(InitialIDkgDealingsValidationError::DeserializationError {
                error: "Missing IDkgDealing.".to_string(),
            })?;
    Ok(IDkgDealing {
        transcript_id: idkg_transcript_id_struct(&dealing_proto.transcript_id)?,
        dealer_id: node_id_struct(&proto.dealer)?,
        internal_dealing_raw: dealing_proto.raw_dealing.clone(),
    })
}

fn verified_dealings_map(
    verified_protos: &[VerifiedIDkgDealingProto],
) -> Result<BTreeMap<NodeIndex, IDkgMultiSignedDealing>, InitialIDkgDealingsValidationError> {
    let mut result = BTreeMap::new();
    for proto in verified_protos.iter() {
        let node_index = proto.dealer_index;
        let dealing = EcdsaDealing {
            requested_height: Height::from(proto.requested_height),
            idkg_dealing: idkg_dealing_struct(&proto.dealing_tuple)?,
        };
        let signers: Result<Vec<_>, _> = proto
            .signers
            .iter()
            .map(|node_id| node_id_struct(&Some(node_id.clone())))
            .collect();
        let signers = BTreeSet::from_iter(signers?.iter().cloned());
        let signed_dealing = IDkgMultiSignedDealing {
            signature: CombinedMultiSigOf::new(CombinedMultiSig(proto.signature.clone())),
            signers,
            dealing,
        };
        result.insert(node_index, signed_dealing);
    }
    Ok(result)
}

fn initial_dealings_map(
    dealing_tuple_protos: &[IDkgDealingTupleProto],
) -> Result<BTreeMap<NodeId, IDkgDealing>, InitialIDkgDealingsValidationError> {
    let mut result = BTreeMap::new();
    for proto in dealing_tuple_protos.iter() {
        let dealing = idkg_dealing_struct(&Some(proto.clone()))?;
        result.insert(dealing.dealer_id, dealing);
    }
    Ok(result)
}
