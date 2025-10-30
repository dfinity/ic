use super::*;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    registry::subnet::v1 as pb_subnet,
    state::queues::v1 as pb_queues,
    state::system_metadata::v1 as pb_metadata,
    types::v1 as pb_types,
};

impl From<&SubnetCallContextManager> for pb_metadata::SubnetCallContextManager {
    fn from(item: &SubnetCallContextManager) -> Self {
        Self {
            next_callback_id: item.next_callback_id,
            setup_initial_dkg_contexts: item
                .setup_initial_dkg_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::SetupInitialDkgContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
            sign_with_threshold_contexts: item
                .sign_with_threshold_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::SignWithThresholdContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
            pre_signature_stashes: item
                .pre_signature_stashes
                .iter()
                .map(
                    |(key_id, pre_signature_stash)| pb_metadata::PreSignatureStashTree {
                        key_id: Some(key_id.inner().into()),
                        key_transcript: Some(pre_signature_stash.key_transcript.as_ref().into()),
                        pre_signatures: pre_signature_stash
                            .pre_signatures
                            .iter()
                            .map(|(id, pre_sig)| pb_metadata::PreSignatureIdPair {
                                pre_sig_id: id.0,
                                pre_signature: Some(pre_sig.into()),
                            })
                            .collect(),
                    },
                )
                .collect(),
            canister_http_request_contexts: item
                .canister_http_request_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::CanisterHttpRequestContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
            bitcoin_get_successors_contexts: item
                .bitcoin_get_successors_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::BitcoinGetSuccessorsContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
            bitcoin_send_transaction_internal_contexts: item
                .bitcoin_send_transaction_internal_contexts
                .iter()
                .map(|(callback_id, context)| {
                    pb_metadata::BitcoinSendTransactionInternalContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    }
                })
                .collect(),
            install_code_calls: item
                .canister_management_calls
                .install_code_call_manager
                .install_code_calls
                .iter()
                .map(|(call_id, call)| pb_metadata::InstallCodeCallTree {
                    call_id: call_id.get(),
                    call: Some(call.into()),
                })
                .collect(),
            install_code_requests: vec![],
            next_install_code_call_id: item
                .canister_management_calls
                .install_code_call_manager
                .next_call_id,

            stop_canister_calls: item
                .canister_management_calls
                .stop_canister_call_manager
                .stop_canister_calls
                .iter()
                .map(|(call_id, call)| pb_metadata::StopCanisterCallTree {
                    call_id: call_id.get(),
                    call: Some(call.into()),
                })
                .collect(),
            next_stop_canister_call_id: item
                .canister_management_calls
                .stop_canister_call_manager
                .next_call_id,
            raw_rand_contexts: item
                .raw_rand_contexts
                .iter()
                .map(|context| context.into())
                .collect(),
            reshare_chain_key_contexts: item
                .reshare_chain_key_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::ReshareChainKeyContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
        }
    }
}

impl TryFrom<(Time, pb_metadata::SubnetCallContextManager)> for SubnetCallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, item): (Time, pb_metadata::SubnetCallContextManager),
    ) -> Result<Self, Self::Error> {
        let mut setup_initial_dkg_contexts = BTreeMap::<CallbackId, SetupInitialDkgContext>::new();
        for entry in item.setup_initial_dkg_contexts {
            let pb_context =
                try_from_option_field(entry.context, "SystemMetadata::SetupInitialDkgContext")?;
            let context = SetupInitialDkgContext::try_from((time, pb_context))?;
            setup_initial_dkg_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut sign_with_threshold_contexts =
            BTreeMap::<CallbackId, SignWithThresholdContext>::new();
        for entry in item.sign_with_threshold_contexts {
            let context: SignWithThresholdContext =
                try_from_option_field(entry.context, "SystemMetadata::SignWithThresholdContext")?;
            sign_with_threshold_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut pre_signature_stashes = BTreeMap::<IDkgMasterPublicKeyId, PreSignatureStash>::new();
        for entry in item.pre_signature_stashes {
            let master_key_id: MasterPublicKeyId = try_from_option_field(
                entry.key_id,
                "SystemMetadata::PreSignatureStash::MasterPublicKeyId",
            )?;
            let key_id =
                IDkgMasterPublicKeyId::try_from(master_key_id).map_err(ProxyDecodeError::Other)?;
            let key_transcript: IDkgTranscript = try_from_option_field(
                entry.key_transcript.as_ref(),
                "SystemMetadata::PreSignatureStash::IDkgTranscript",
            )?;
            let mut pre_signatures = BTreeMap::new();
            for pre_signature in entry.pre_signatures {
                pre_signatures.insert(
                    PreSigId(pre_signature.pre_sig_id),
                    try_from_option_field(
                        pre_signature.pre_signature.as_ref(),
                        "SystemMetadata::PreSignatureStash::PreSignature",
                    )?,
                );
            }
            pre_signature_stashes.insert(
                key_id,
                PreSignatureStash {
                    key_transcript: Arc::new(key_transcript),
                    pre_signatures,
                },
            );
        }

        let mut canister_http_request_contexts =
            BTreeMap::<CallbackId, CanisterHttpRequestContext>::new();
        for entry in item.canister_http_request_contexts {
            let context: CanisterHttpRequestContext =
                try_from_option_field(entry.context, "SystemMetadata::CanisterHttpRequestContext")?;
            canister_http_request_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut reshare_chain_key_contexts = BTreeMap::<CallbackId, ReshareChainKeyContext>::new();
        for entry in item.reshare_chain_key_contexts {
            let pb_context =
                try_from_option_field(entry.context, "SystemMetadata::ReshareChainKeyContext")?;
            let context = ReshareChainKeyContext::try_from((time, pb_context))?;
            reshare_chain_key_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut bitcoin_get_successors_contexts =
            BTreeMap::<CallbackId, BitcoinGetSuccessorsContext>::new();
        for entry in item.bitcoin_get_successors_contexts {
            let pb_context = try_from_option_field(
                entry.context,
                "SystemMetadata::BitcoinGetSuccessorsContext",
            )?;
            let context = BitcoinGetSuccessorsContext::try_from((time, pb_context))?;
            bitcoin_get_successors_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut bitcoin_send_transaction_internal_contexts =
            BTreeMap::<CallbackId, BitcoinSendTransactionInternalContext>::new();
        for entry in item.bitcoin_send_transaction_internal_contexts {
            let pb_context = try_from_option_field(
                entry.context,
                "SystemMetadata::BitcoinSendTransactionInternalContext",
            )?;
            let context = BitcoinSendTransactionInternalContext::try_from((time, pb_context))?;
            bitcoin_send_transaction_internal_contexts
                .insert(CallbackId::new(entry.callback_id), context);
        }

        let mut install_code_calls = BTreeMap::<InstallCodeCallId, InstallCodeCall>::new();
        // TODO(EXC-1454): Remove when `install_code_requests` field is not needed.
        for entry in item.install_code_requests {
            let pb_request = entry.request.ok_or(ProxyDecodeError::MissingField(
                "InstallCodeRequest::request",
            ))?;
            let call = InstallCodeCall::try_from((time, pb_request))?;
            install_code_calls.insert(InstallCodeCallId::new(entry.request_id), call);
        }
        for entry in item.install_code_calls {
            let pb_call = entry.call.ok_or(ProxyDecodeError::MissingField(
                "SystemMetadata::InstallCodeCall",
            ))?;
            let call = InstallCodeCall::try_from((time, pb_call))?;
            install_code_calls.insert(InstallCodeCallId::new(entry.call_id), call);
        }
        let install_code_call_manager: InstallCodeCallManager = InstallCodeCallManager {
            next_call_id: item.next_install_code_call_id,
            install_code_calls,
        };

        let mut stop_canister_calls = BTreeMap::<StopCanisterCallId, StopCanisterCall>::new();
        for entry in item.stop_canister_calls {
            let pb_call = try_from_option_field(entry.call, "SystemMetadata::StopCanisterCall")?;
            let call = StopCanisterCall::try_from((time, pb_call))?;
            stop_canister_calls.insert(StopCanisterCallId::new(entry.call_id), call);
        }
        let stop_canister_call_manager = StopCanisterCallManager {
            next_call_id: item.next_stop_canister_call_id,
            stop_canister_calls,
        };
        let mut raw_rand_contexts = VecDeque::<RawRandContext>::new();
        for pb_context in item.raw_rand_contexts {
            let context = RawRandContext::try_from((time, pb_context))?;
            raw_rand_contexts.push_back(context);
        }

        Ok(Self {
            next_callback_id: item.next_callback_id,
            setup_initial_dkg_contexts,
            sign_with_threshold_contexts,
            canister_http_request_contexts,
            bitcoin_get_successors_contexts,
            bitcoin_send_transaction_internal_contexts,
            canister_management_calls: CanisterManagementCalls {
                install_code_call_manager,
                stop_canister_call_manager,
            },
            raw_rand_contexts,
            reshare_chain_key_contexts,
            pre_signature_stashes,
        })
    }
}

impl From<&SetupInitialDkgContext> for pb_metadata::SetupInitialDkgContext {
    fn from(context: &SetupInitialDkgContext) -> Self {
        Self {
            request: Some((&context.request).into()),
            nodes_in_subnet: context
                .nodes_in_target_subnet
                .iter()
                .map(|node_id| node_id_into_protobuf(*node_id))
                .collect(),
            target_id: context.target_id.to_vec(),
            registry_version: context.registry_version.get(),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::SetupInitialDkgContext)> for SetupInitialDkgContext {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, context): (Time, pb_metadata::SetupInitialDkgContext),
    ) -> Result<Self, Self::Error> {
        let mut nodes_in_target_subnet = BTreeSet::<NodeId>::new();
        for node_id in context.nodes_in_subnet {
            nodes_in_target_subnet.insert(node_id_try_from_option(Some(node_id))?);
        }
        Ok(SetupInitialDkgContext {
            request: try_from_option_field(context.request, "SetupInitialDkgContext::request")?,
            nodes_in_target_subnet,
            target_id: match ni_dkg_target_id(context.target_id.as_slice()) {
                Ok(target_id) => target_id,
                Err(_) => return Err(Self::Error::Other("target_id is not 32 bytes.".to_string())),
            },
            registry_version: RegistryVersion::from(context.registry_version),
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

/// Tries to convert a vector of bytes into an array of N bytes.
fn try_into_array<const N: usize>(bytes: Vec<u8>, name: &str) -> Result<[u8; N], ProxyDecodeError> {
    if bytes.len() != N {
        return Err(ProxyDecodeError::Other(format!("{name} is not {N} bytes.")));
    }
    let mut id = [0; N];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn try_into_array_message_hash(
    bytes: Vec<u8>,
) -> Result<[u8; MESSAGE_HASH_SIZE], ProxyDecodeError> {
    try_into_array::<MESSAGE_HASH_SIZE>(bytes, "message_hash")
}

fn try_into_array_pseudo_random_id(
    bytes: Vec<u8>,
) -> Result<[u8; PSEUDO_RANDOM_ID_SIZE], ProxyDecodeError> {
    try_into_array::<PSEUDO_RANDOM_ID_SIZE>(bytes, "pseudo_random_id")
}

fn try_into_array_nonce(bytes: Vec<u8>) -> Result<[u8; NONCE_SIZE], ProxyDecodeError> {
    try_into_array::<NONCE_SIZE>(bytes, "nonce")
}

impl From<&EcdsaMatchedPreSignature> for pb_types::EcdsaMatchedPreSignature {
    fn from(value: &EcdsaMatchedPreSignature) -> Self {
        Self {
            pre_signature_id: value.id.0,
            height: value.height.get(),
            pre_signature: Some(pb_types::EcdsaPreSignatureQuadruple::from(
                value.pre_signature.as_ref(),
            )),
            key_transcript: Some(pb_subnet::IDkgTranscript::from(
                value.key_transcript.as_ref(),
            )),
        }
    }
}

impl TryFrom<pb_types::EcdsaMatchedPreSignature> for EcdsaMatchedPreSignature {
    type Error = ProxyDecodeError;
    fn try_from(proto: pb_types::EcdsaMatchedPreSignature) -> Result<Self, Self::Error> {
        Ok(EcdsaMatchedPreSignature {
            id: PreSigId(proto.pre_signature_id),
            height: Height::from(proto.height),
            pre_signature: Arc::new(try_from_option_field(
                proto.pre_signature.as_ref(),
                "EcdsaMatchedPreSignature::pre_signature",
            )?),
            key_transcript: Arc::new(try_from_option_field(
                proto.key_transcript.as_ref(),
                "EcdsaMatchedPreSignature::key_transcript",
            )?),
        })
    }
}

impl From<&EcdsaArguments> for pb_metadata::EcdsaArguments {
    fn from(args: &EcdsaArguments) -> Self {
        Self {
            key_id: Some((&args.key_id).into()),
            message_hash: args.message_hash.to_vec(),
            pre_signature: args
                .pre_signature
                .as_ref()
                .map(pb_types::EcdsaMatchedPreSignature::from),
        }
    }
}

impl TryFrom<pb_metadata::EcdsaArguments> for EcdsaArguments {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::EcdsaArguments) -> Result<Self, Self::Error> {
        Ok(EcdsaArguments {
            key_id: try_from_option_field(context.key_id, "EcdsaArguments::key_id")?,
            message_hash: try_into_array_message_hash(context.message_hash)?,
            pre_signature: context
                .pre_signature
                .map(EcdsaMatchedPreSignature::try_from)
                .transpose()?,
        })
    }
}

impl From<&SchnorrMatchedPreSignature> for pb_types::SchnorrMatchedPreSignature {
    fn from(value: &SchnorrMatchedPreSignature) -> Self {
        Self {
            pre_signature_id: value.id.0,
            height: value.height.get(),
            pre_signature: Some(pb_types::SchnorrPreSignatureTranscript::from(
                value.pre_signature.as_ref(),
            )),
            key_transcript: Some(pb_subnet::IDkgTranscript::from(
                value.key_transcript.as_ref(),
            )),
        }
    }
}

impl TryFrom<pb_types::SchnorrMatchedPreSignature> for SchnorrMatchedPreSignature {
    type Error = ProxyDecodeError;
    fn try_from(proto: pb_types::SchnorrMatchedPreSignature) -> Result<Self, Self::Error> {
        Ok(SchnorrMatchedPreSignature {
            id: PreSigId(proto.pre_signature_id),
            height: Height::from(proto.height),
            pre_signature: Arc::new(try_from_option_field(
                proto.pre_signature.as_ref(),
                "SchnorrMatchedPreSignature::pre_signature",
            )?),
            key_transcript: Arc::new(try_from_option_field(
                proto.key_transcript.as_ref(),
                "SchnorrMatchedPreSignature::key_transcript",
            )?),
        })
    }
}

impl From<&SchnorrArguments> for pb_metadata::SchnorrArguments {
    fn from(args: &SchnorrArguments) -> Self {
        Self {
            key_id: Some((&args.key_id).into()),
            message: args.message.to_vec(),
            taproot_tree_root: args.taproot_tree_root.as_ref().map(|v| v.to_vec()),
            pre_signature: args
                .pre_signature
                .as_ref()
                .map(pb_types::SchnorrMatchedPreSignature::from),
        }
    }
}

impl TryFrom<pb_metadata::SchnorrArguments> for SchnorrArguments {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::SchnorrArguments) -> Result<Self, Self::Error> {
        Ok(SchnorrArguments {
            key_id: try_from_option_field(context.key_id, "SchnorrArguments::key_id")?,
            message: Arc::new(context.message),
            taproot_tree_root: context.taproot_tree_root.map(Arc::new),
            pre_signature: context
                .pre_signature
                .map(SchnorrMatchedPreSignature::try_from)
                .transpose()?,
        })
    }
}

impl From<&VetKdArguments> for pb_metadata::VetKdArguments {
    fn from(args: &VetKdArguments) -> Self {
        Self {
            key_id: Some((&args.key_id).into()),
            input: args.input.to_vec(),
            transport_public_key: args.transport_public_key.to_vec(),
            ni_dkg_id: Some((args.ni_dkg_id.clone()).into()),
            height: args.height.get(),
        }
    }
}

impl TryFrom<pb_metadata::VetKdArguments> for VetKdArguments {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::VetKdArguments) -> Result<Self, Self::Error> {
        Ok(VetKdArguments {
            key_id: try_from_option_field(context.key_id, "VetKdArguments::key_id")?,
            input: Arc::new(context.input),
            transport_public_key: context.transport_public_key,
            ni_dkg_id: try_from_option_field(context.ni_dkg_id, "VetKdArguments::ni_dkg_id")?,
            height: Height::from(context.height),
        })
    }
}

impl From<&ThresholdArguments> for pb_metadata::ThresholdArguments {
    fn from(context: &ThresholdArguments) -> Self {
        let threshold_scheme = match context {
            ThresholdArguments::Ecdsa(args) => {
                pb_metadata::threshold_arguments::ThresholdScheme::Ecdsa(args.into())
            }
            ThresholdArguments::Schnorr(args) => {
                pb_metadata::threshold_arguments::ThresholdScheme::Schnorr(args.into())
            }
            ThresholdArguments::VetKd(args) => {
                pb_metadata::threshold_arguments::ThresholdScheme::Vetkd(args.into())
            }
        };
        Self {
            threshold_scheme: Some(threshold_scheme),
        }
    }
}

impl TryFrom<pb_metadata::ThresholdArguments> for ThresholdArguments {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::ThresholdArguments) -> Result<Self, Self::Error> {
        let threshold_scheme = try_from_option_field(
            context.threshold_scheme,
            "ThresholdArguments::threshold_scheme",
        )?;
        match threshold_scheme {
            pb_metadata::threshold_arguments::ThresholdScheme::Ecdsa(args) => {
                Ok(ThresholdArguments::Ecdsa(EcdsaArguments::try_from(args)?))
            }
            pb_metadata::threshold_arguments::ThresholdScheme::Schnorr(args) => Ok(
                ThresholdArguments::Schnorr(SchnorrArguments::try_from(args)?),
            ),
            pb_metadata::threshold_arguments::ThresholdScheme::Vetkd(args) => {
                Ok(ThresholdArguments::VetKd(VetKdArguments::try_from(args)?))
            }
        }
    }
}

impl From<&SignWithThresholdContext> for pb_metadata::SignWithThresholdContext {
    fn from(context: &SignWithThresholdContext) -> Self {
        Self {
            request: Some((&context.request).into()),
            args: Some((&context.args).into()),
            derivation_path_vec: context.derivation_path.to_vec(),
            pseudo_random_id: context.pseudo_random_id.to_vec(),
            batch_time: context.batch_time.as_nanos_since_unix_epoch(),
            pre_signature_id: context.matched_pre_signature.as_ref().map(|q| q.0.id()),
            height: context.matched_pre_signature.as_ref().map(|q| q.1.get()),
            nonce: context.nonce.map(|n| n.to_vec()),
        }
    }
}

impl TryFrom<pb_metadata::SignWithThresholdContext> for SignWithThresholdContext {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::SignWithThresholdContext) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "SignWithThresholdContext::request")?;
        let args: ThresholdArguments =
            try_from_option_field(context.args, "SignWithThresholdContext::args")?;
        Ok(SignWithThresholdContext {
            request,
            args,
            derivation_path: Arc::new(context.derivation_path_vec),
            pseudo_random_id: try_into_array_pseudo_random_id(context.pseudo_random_id)?,
            batch_time: Time::from_nanos_since_unix_epoch(context.batch_time),
            matched_pre_signature: context
                .pre_signature_id
                .map(PreSigId)
                .zip(context.height)
                .map(|(q, h)| (q, Height::from(h))),
            nonce: context.nonce.map(try_into_array_nonce).transpose()?,
        })
    }
}

impl From<&ReshareChainKeyContext> for pb_metadata::ReshareChainKeyContext {
    fn from(context: &ReshareChainKeyContext) -> Self {
        Self {
            request: Some(pb_queues::Request::from(&context.request)),
            key_id: Some(pb_types::MasterPublicKeyId::from(&context.key_id)),
            nodes: context
                .nodes
                .iter()
                .map(|node_id| node_id_into_protobuf(*node_id))
                .collect(),
            registry_version: context.registry_version.get(),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
            target_id: context.target_id.to_vec(),
        }
    }
}

impl TryFrom<(Time, pb_metadata::ReshareChainKeyContext)> for ReshareChainKeyContext {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, context): (Time, pb_metadata::ReshareChainKeyContext),
    ) -> Result<Self, Self::Error> {
        let key_id: MasterPublicKeyId =
            try_from_option_field(context.key_id, "ReshareChainKeyContext::key_id")?;

        Ok(Self {
            request: try_from_option_field(context.request, "ReshareChainKeyContext::request")?,
            key_id,
            nodes: context
                .nodes
                .into_iter()
                .map(|node_id| node_id_try_from_option(Some(node_id)))
                .collect::<Result<_, _>>()?,
            registry_version: RegistryVersion::from(context.registry_version),
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
            target_id: {
                match ni_dkg_target_id(context.target_id.as_slice()) {
                    Ok(target_id) => target_id,
                    Err(_) => {
                        return Err(Self::Error::Other("target_id is not 32 bytes.".to_string()));
                    }
                }
            },
        })
    }
}

impl From<&BitcoinGetSuccessorsContext> for pb_metadata::BitcoinGetSuccessorsContext {
    fn from(context: &BitcoinGetSuccessorsContext) -> Self {
        Self {
            request: Some((&context.request).into()),
            payload: Some((&context.payload).into()),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::BitcoinGetSuccessorsContext)> for BitcoinGetSuccessorsContext {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, context): (Time, pb_metadata::BitcoinGetSuccessorsContext),
    ) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "BitcoinGetSuccessorsContext::request")?;
        let payload: GetSuccessorsRequestInitial =
            try_from_option_field(context.payload, "BitcoinGetSuccessorsContext::payload")?;
        Ok(BitcoinGetSuccessorsContext {
            request,
            payload,
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

impl From<&BitcoinSendTransactionInternalContext>
    for pb_metadata::BitcoinSendTransactionInternalContext
{
    fn from(context: &BitcoinSendTransactionInternalContext) -> Self {
        Self {
            request: Some((&context.request).into()),
            payload: Some((&context.payload).into()),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::BitcoinSendTransactionInternalContext)>
    for BitcoinSendTransactionInternalContext
{
    type Error = ProxyDecodeError;
    fn try_from(
        (time, context): (Time, pb_metadata::BitcoinSendTransactionInternalContext),
    ) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "BitcoinGetSuccessorsContext::request")?;
        let payload: SendTransactionRequest =
            try_from_option_field(context.payload, "BitcoinGetSuccessorsContext::payload")?;
        Ok(BitcoinSendTransactionInternalContext {
            request,
            payload,
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

impl From<&InstallCodeCall> for pb_metadata::InstallCodeCall {
    fn from(install_code_call: &InstallCodeCall) -> Self {
        use pb_metadata::install_code_call::CanisterCall as PbCanisterCall;
        let call = match &install_code_call.call {
            CanisterCall::Request(request) => PbCanisterCall::Request(request.as_ref().into()),
            CanisterCall::Ingress(ingress) => PbCanisterCall::Ingress(ingress.as_ref().into()),
        };
        Self {
            canister_call: Some(call),
            effective_canister_id: Some((install_code_call.effective_canister_id).into()),
            time: Some(pb_metadata::Time {
                time_nanos: install_code_call.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::InstallCodeRequest)> for InstallCodeCall {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, install_code_request): (Time, pb_metadata::InstallCodeRequest),
    ) -> Result<Self, Self::Error> {
        let pb_call = install_code_request
            .request
            .ok_or(ProxyDecodeError::MissingField(
                "InstallCodeRequest::request",
            ))?;
        let effective_canister_id: CanisterId = try_from_option_field(
            install_code_request.effective_canister_id,
            "InstallCodeRequest::effective_canister_id",
        )?;
        Ok(InstallCodeCall {
            call: CanisterCall::Request(Arc::new(pb_call.try_into()?)),
            effective_canister_id,
            time: install_code_request
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

impl TryFrom<(Time, pb_metadata::InstallCodeCall)> for InstallCodeCall {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, install_code_call): (Time, pb_metadata::InstallCodeCall),
    ) -> Result<Self, Self::Error> {
        use pb_metadata::install_code_call::CanisterCall as PbCanisterCall;
        let pb_call = install_code_call
            .canister_call
            .ok_or(ProxyDecodeError::MissingField(
                "InstallCodeCall::canister_call",
            ))?;

        let call = match pb_call {
            PbCanisterCall::Request(request) => {
                CanisterCall::Request(Arc::new(request.try_into()?))
            }
            PbCanisterCall::Ingress(ingress) => {
                CanisterCall::Ingress(Arc::new(ingress.try_into()?))
            }
        };

        let effective_canister_id: CanisterId = try_from_option_field(
            install_code_call.effective_canister_id,
            "InstallCodeCall::effective_canister_id",
        )?;
        Ok(InstallCodeCall {
            call,
            effective_canister_id,
            time: install_code_call
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

impl From<&StopCanisterCall> for pb_metadata::StopCanisterCall {
    fn from(stop_canister_call: &StopCanisterCall) -> Self {
        use pb_metadata::stop_canister_call::CanisterCall as PbCanisterCall;
        let call = match &stop_canister_call.call {
            CanisterCall::Request(request) => PbCanisterCall::Request(request.as_ref().into()),
            CanisterCall::Ingress(ingress) => PbCanisterCall::Ingress(ingress.as_ref().into()),
        };
        Self {
            canister_call: Some(call),
            effective_canister_id: Some((stop_canister_call.effective_canister_id).into()),
            time: Some(pb_metadata::Time {
                time_nanos: stop_canister_call.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::StopCanisterCall)> for StopCanisterCall {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, stop_canister_call): (Time, pb_metadata::StopCanisterCall),
    ) -> Result<Self, Self::Error> {
        use pb_metadata::stop_canister_call::CanisterCall as PbCanisterCall;
        let pb_call = stop_canister_call
            .canister_call
            .ok_or(ProxyDecodeError::MissingField(
                "StopCanisterCall::canister_call",
            ))?;

        let call = match pb_call {
            PbCanisterCall::Request(request) => {
                CanisterCall::Request(Arc::new(request.try_into()?))
            }
            PbCanisterCall::Ingress(ingress) => {
                CanisterCall::Ingress(Arc::new(ingress.try_into()?))
            }
        };
        let effective_canister_id = try_from_option_field(
            stop_canister_call.effective_canister_id,
            "StopCanisterCall::effective_canister_id",
        )?;
        Ok(StopCanisterCall {
            call,
            effective_canister_id,
            time: stop_canister_call
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

impl From<&RawRandContext> for pb_metadata::RawRandContext {
    fn from(context: &RawRandContext) -> Self {
        Self {
            request: Some((&context.request).into()),
            execution_round_id: context.execution_round_id.get(),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::RawRandContext)> for RawRandContext {
    type Error = ProxyDecodeError;
    fn try_from((time, context): (Time, pb_metadata::RawRandContext)) -> Result<Self, Self::Error> {
        let request: Request = try_from_option_field(context.request, "RawRandContext::request")?;

        Ok(RawRandContext {
            request,
            execution_round_id: ExecutionRound::new(context.execution_round_id),
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}
