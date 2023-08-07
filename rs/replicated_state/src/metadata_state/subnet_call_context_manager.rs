use ic_btc_types_internal::{GetSuccessorsRequestInitial, SendTransactionRequest};
use ic_ic00_types::EcdsaKeyId;
use ic_logger::{info, ReplicaLogger};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::system_metadata::v1 as pb_metadata,
};
use ic_types::{
    canister_http::CanisterHttpRequestContext,
    crypto::threshold_sig::ni_dkg::{id::ni_dkg_target_id, NiDkgTargetId},
    messages::{CallbackId, Request},
    node_id_into_protobuf, node_id_try_from_option, CanisterId, NodeId, RegistryVersion, Time,
};
use phantom_newtype::Id;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{From, TryFrom},
};

pub enum SubnetCallContext {
    SetupInitialDKG(SetupInitialDkgContext),
    SignWithEcsda(SignWithEcdsaContext),
    CanisterHttpRequest(CanisterHttpRequestContext),
    EcdsaDealings(EcdsaDealingsContext),
    BitcoinGetSuccessors(BitcoinGetSuccessorsContext),
    BitcoinSendTransactionInternal(BitcoinSendTransactionInternalContext),
}

impl SubnetCallContext {
    pub fn get_request(&self) -> &Request {
        match &self {
            SubnetCallContext::SetupInitialDKG(context) => &context.request,
            SubnetCallContext::SignWithEcsda(context) => &context.request,
            SubnetCallContext::CanisterHttpRequest(context) => &context.request,
            SubnetCallContext::EcdsaDealings(context) => &context.request,
            SubnetCallContext::BitcoinGetSuccessors(context) => &context.request,
            SubnetCallContext::BitcoinSendTransactionInternal(context) => &context.request,
        }
    }

    pub fn get_time(&self) -> Time {
        match &self {
            SubnetCallContext::SetupInitialDKG(context) => context.time,
            SubnetCallContext::SignWithEcsda(context) => context.batch_time,
            SubnetCallContext::CanisterHttpRequest(context) => context.time,
            SubnetCallContext::EcdsaDealings(context) => context.time,
            SubnetCallContext::BitcoinGetSuccessors(context) => context.time,
            SubnetCallContext::BitcoinSendTransactionInternal(context) => context.time,
        }
    }
}

pub struct InstallCodeRequestIdTag;
pub type InstallCodeRequestId = Id<InstallCodeRequestIdTag, u64>;

/// It is responsible for keeping track of all install code messages that
/// cannot complete execution in a single round.
///
/// During a subnet split, these messages will be autmatically rejected if
/// the targeted canister is moved to a new subnet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct InstallCodeRequestManager {
    next_request_id: u64,
    install_code_requests: BTreeMap<InstallCodeRequestId, InstallCodeRequest>,
}

impl InstallCodeRequestManager {
    fn push_request(&mut self, request: InstallCodeRequest) -> InstallCodeRequestId {
        let request_id = InstallCodeRequestId::new(self.next_request_id);
        self.next_request_id += 1;
        self.install_code_requests.insert(request_id, request);

        request_id
    }

    fn retrieve_request(&mut self, request_id: InstallCodeRequestId) -> Option<InstallCodeRequest> {
        self.install_code_requests.remove(&request_id)
    }

    fn install_code_requests_len(&self) -> usize {
        self.install_code_requests.len()
    }
}

/// It is responsible for keeping track of all subnet messages that
/// do not require work to be done by another IC layer and
/// cannot finalize the execution in a single round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CanisterManagementRequests {
    install_code_request_manager: InstallCodeRequestManager,
}

impl CanisterManagementRequests {
    fn push_request(&mut self, request: InstallCodeRequest) -> InstallCodeRequestId {
        self.install_code_request_manager.push_request(request)
    }

    fn retrieve_request(&mut self, request_id: InstallCodeRequestId) -> Option<InstallCodeRequest> {
        self.install_code_request_manager
            .retrieve_request(request_id)
    }

    pub fn install_code_requests_len(&self) -> usize {
        self.install_code_request_manager
            .install_code_requests_len()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubnetCallContextManager {
    next_callback_id: u64,
    pub setup_initial_dkg_contexts: BTreeMap<CallbackId, SetupInitialDkgContext>,
    pub sign_with_ecdsa_contexts: BTreeMap<CallbackId, SignWithEcdsaContext>,
    pub canister_http_request_contexts: BTreeMap<CallbackId, CanisterHttpRequestContext>,
    pub ecdsa_dealings_contexts: BTreeMap<CallbackId, EcdsaDealingsContext>,
    pub bitcoin_get_successors_contexts: BTreeMap<CallbackId, BitcoinGetSuccessorsContext>,
    pub bitcoin_send_transaction_internal_contexts:
        BTreeMap<CallbackId, BitcoinSendTransactionInternalContext>,
    canister_management_requests: CanisterManagementRequests,
}

impl SubnetCallContextManager {
    pub fn push_context(&mut self, context: SubnetCallContext) -> CallbackId {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;

        match context {
            SubnetCallContext::SetupInitialDKG(context) => {
                self.setup_initial_dkg_contexts.insert(callback_id, context);
            }
            SubnetCallContext::SignWithEcsda(context) => {
                self.sign_with_ecdsa_contexts.insert(callback_id, context);
            }
            SubnetCallContext::CanisterHttpRequest(context) => {
                self.canister_http_request_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::EcdsaDealings(context) => {
                self.ecdsa_dealings_contexts.insert(callback_id, context);
            }
            SubnetCallContext::BitcoinGetSuccessors(context) => {
                self.bitcoin_get_successors_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::BitcoinSendTransactionInternal(context) => {
                self.bitcoin_send_transaction_internal_contexts
                    .insert(callback_id, context);
            }
        };

        callback_id
    }

    pub fn retrieve_context(
        &mut self,
        callback_id: CallbackId,
        logger: &ReplicaLogger,
    ) -> Option<SubnetCallContext> {
        self.setup_initial_dkg_contexts
            .remove(&callback_id)
            .map(|context| {
                info!(
                    logger,
                    "Received the response for SetupInitialDKG request for target {:?}",
                    context.target_id
                );
                SubnetCallContext::SetupInitialDKG(context)
            })
            .or_else(|| {
                self.sign_with_ecdsa_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for SignWithECDSA request with id {:?} from {:?}",
                            context.pseudo_random_id,
                            context.request.sender
                        );
                        SubnetCallContext::SignWithEcsda(context)
                    })
            })
            .or_else(|| {
                self.ecdsa_dealings_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for ComputeInitialEcdsaDealings request with key_id {:?} from {:?}",
                            context.key_id,
                            context.request.sender
                        );
                        SubnetCallContext::EcdsaDealings(context)
                    })
            })
            .or_else(|| {
                self.canister_http_request_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for HttpRequest with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::CanisterHttpRequest(context)
                    })
            })
            .or_else(|| {
                self.bitcoin_get_successors_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for BitcoinGetSuccessors with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::BitcoinGetSuccessors(context)
                    })
            })
            .or_else(|| {
                self.bitcoin_send_transaction_internal_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for BitcoinSendTransactionInternal with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::BitcoinSendTransactionInternal(context)
                    })
            })
    }

    pub fn push_install_code_request(
        &mut self,
        request: InstallCodeRequest,
    ) -> InstallCodeRequestId {
        self.canister_management_requests.push_request(request)
    }

    pub fn retrieve_install_code_request(
        &mut self,
        request_id: InstallCodeRequestId,
    ) -> Option<InstallCodeRequest> {
        self.canister_management_requests
            .retrieve_request(request_id)
    }

    pub fn install_code_contexts_len(&self) -> usize {
        self.canister_management_requests
            .install_code_requests_len()
    }
}

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
            sign_with_ecdsa_contexts: item
                .sign_with_ecdsa_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::SignWithEcdsaContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
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
            ecdsa_dealings_contexts: item
                .ecdsa_dealings_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::EcdsaDealingsContextTree {
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
            install_code_requests: item
                .canister_management_requests
                .install_code_request_manager
                .install_code_requests
                .iter()
                .map(
                    |(request_id, request)| pb_metadata::InstallCodeRequestTree {
                        request_id: request_id.get(),
                        request: Some(request.into()),
                    },
                )
                .collect(),
            next_install_code_request_id: item
                .canister_management_requests
                .install_code_request_manager
                .next_request_id,
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

        let mut sign_with_ecdsa_contexts = BTreeMap::<CallbackId, SignWithEcdsaContext>::new();
        for entry in item.sign_with_ecdsa_contexts {
            let context: SignWithEcdsaContext =
                try_from_option_field(entry.context, "SystemMetadata::SignWithEcdsaContext")?;
            sign_with_ecdsa_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut canister_http_request_contexts =
            BTreeMap::<CallbackId, CanisterHttpRequestContext>::new();
        for entry in item.canister_http_request_contexts {
            let context: CanisterHttpRequestContext =
                try_from_option_field(entry.context, "SystemMetadata::CanisterHttpRequestContext")?;
            canister_http_request_contexts.insert(CallbackId::new(entry.callback_id), context);
        }

        let mut ecdsa_dealings_contexts = BTreeMap::<CallbackId, EcdsaDealingsContext>::new();
        for entry in item.ecdsa_dealings_contexts {
            let pb_context =
                try_from_option_field(entry.context, "SystemMetadata::EcdsaDealingsContext")?;
            let context = EcdsaDealingsContext::try_from((time, pb_context))?;
            ecdsa_dealings_contexts.insert(CallbackId::new(entry.callback_id), context);
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

        let mut install_code_requests = BTreeMap::<InstallCodeRequestId, InstallCodeRequest>::new();
        for entry in item.install_code_requests {
            let pb_request =
                try_from_option_field(entry.request, "SystemMetadata::InstallCodeRequest")?;
            let request = InstallCodeRequest::try_from((time, pb_request))?;
            install_code_requests.insert(InstallCodeRequestId::new(entry.request_id), request);
        }
        let install_code_request_manager = InstallCodeRequestManager {
            next_request_id: item.next_install_code_request_id,
            install_code_requests,
        };

        Ok(Self {
            next_callback_id: item.next_callback_id,
            setup_initial_dkg_contexts,
            sign_with_ecdsa_contexts,
            canister_http_request_contexts,
            ecdsa_dealings_contexts,
            bitcoin_get_successors_contexts,
            bitcoin_send_transaction_internal_contexts,
            canister_management_requests: CanisterManagementRequests {
                install_code_request_manager,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupInitialDkgContext {
    pub request: Request,
    pub nodes_in_target_subnet: BTreeSet<NodeId>,
    pub target_id: NiDkgTargetId,
    pub registry_version: RegistryVersion,
    pub time: Time,
}

impl From<&SetupInitialDkgContext> for pb_metadata::SetupInitialDkgContext {
    fn from(context: &SetupInitialDkgContext) -> Self {
        pb_metadata::SetupInitialDkgContext {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignWithEcdsaContext {
    pub request: Request,
    pub key_id: EcdsaKeyId,
    pub message_hash: [u8; 32],
    pub derivation_path: Vec<Vec<u8>>,
    pub pseudo_random_id: [u8; 32],
    pub batch_time: Time,
}

impl From<&SignWithEcdsaContext> for pb_metadata::SignWithEcdsaContext {
    fn from(context: &SignWithEcdsaContext) -> Self {
        pb_metadata::SignWithEcdsaContext {
            request: Some((&context.request).into()),
            key_id: Some((&context.key_id).into()),
            message_hash: context.message_hash.to_vec(),
            derivation_path_vec: context.derivation_path.clone(),
            pseudo_random_id: context.pseudo_random_id.to_vec(),
            batch_time: context.batch_time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_metadata::SignWithEcdsaContext> for SignWithEcdsaContext {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::SignWithEcdsaContext) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "SignWithEcdsaContext::request")?;
        let key_id = try_from_option_field(context.key_id, "SignWithEcdsaContext::key_id")?;
        Ok(SignWithEcdsaContext {
            message_hash: {
                if context.message_hash.len() != 32 {
                    return Err(Self::Error::Other(
                        "message_hash is not 32 bytes.".to_string(),
                    ));
                }
                let mut id = [0; NiDkgTargetId::SIZE];
                id.copy_from_slice(&context.message_hash);
                id
            },
            derivation_path: context.derivation_path_vec,
            request,
            key_id,
            pseudo_random_id: {
                if context.pseudo_random_id.len() != 32 {
                    return Err(Self::Error::Other(
                        "pseudo_random_id is not 32 bytes.".to_string(),
                    ));
                }
                let mut id = [0; NiDkgTargetId::SIZE];
                id.copy_from_slice(&context.pseudo_random_id);
                id
            },
            batch_time: Time::from_nanos_since_unix_epoch(context.batch_time),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaDealingsContext {
    pub request: Request,
    pub key_id: EcdsaKeyId,
    pub nodes: BTreeSet<NodeId>,
    pub registry_version: RegistryVersion,
    pub time: Time,
}

impl From<&EcdsaDealingsContext> for pb_metadata::EcdsaDealingsContext {
    fn from(context: &EcdsaDealingsContext) -> Self {
        pb_metadata::EcdsaDealingsContext {
            request: Some((&context.request).into()),
            key_id: Some((&context.key_id).into()),
            nodes: context
                .nodes
                .iter()
                .map(|node_id| node_id_into_protobuf(*node_id))
                .collect(),
            registry_version: context.registry_version.get(),
            time: Some(pb_metadata::Time {
                time_nanos: context.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::EcdsaDealingsContext)> for EcdsaDealingsContext {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, context): (Time, pb_metadata::EcdsaDealingsContext),
    ) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "EcdsaDealingsContext::request")?;
        let key_id: EcdsaKeyId =
            try_from_option_field(context.key_id, "EcdsaDealingsContext::key_id")?;
        let mut nodes = BTreeSet::<NodeId>::new();
        for node_id in context.nodes {
            nodes.insert(node_id_try_from_option(Some(node_id))?);
        }
        Ok(EcdsaDealingsContext {
            request,
            key_id,
            nodes,
            registry_version: RegistryVersion::from(context.registry_version),
            time: context
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinGetSuccessorsContext {
    pub request: Request,
    pub payload: GetSuccessorsRequestInitial,
    pub time: Time,
}

impl From<&BitcoinGetSuccessorsContext> for pb_metadata::BitcoinGetSuccessorsContext {
    fn from(context: &BitcoinGetSuccessorsContext) -> Self {
        pb_metadata::BitcoinGetSuccessorsContext {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinSendTransactionInternalContext {
    pub request: Request,
    pub payload: SendTransactionRequest,
    pub time: Time,
}

impl From<&BitcoinSendTransactionInternalContext>
    for pb_metadata::BitcoinSendTransactionInternalContext
{
    fn from(context: &BitcoinSendTransactionInternalContext) -> Self {
        pb_metadata::BitcoinSendTransactionInternalContext {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallCodeRequest {
    pub request: Request,
    pub time: Time,
    pub effective_canister_id: CanisterId,
}

impl From<&InstallCodeRequest> for pb_metadata::InstallCodeRequest {
    fn from(install_code_request: &InstallCodeRequest) -> Self {
        pb_metadata::InstallCodeRequest {
            request: Some((&install_code_request.request).into()),
            effective_canister_id: Some((install_code_request.effective_canister_id).into()),
            time: Some(pb_metadata::Time {
                time_nanos: install_code_request.time.as_nanos_since_unix_epoch(),
            }),
        }
    }
}

impl TryFrom<(Time, pb_metadata::InstallCodeRequest)> for InstallCodeRequest {
    type Error = ProxyDecodeError;
    fn try_from(
        (time, install_code_request): (Time, pb_metadata::InstallCodeRequest),
    ) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(install_code_request.request, "InstallCodeRequest::request")?;
        let effective_canister_id: CanisterId = try_from_option_field(
            install_code_request.effective_canister_id,
            "InstallCodeRequest::effective_canister_id",
        )?;
        Ok(InstallCodeRequest {
            request,
            effective_canister_id,
            time: install_code_request
                .time
                .map_or(time, |t| Time::from_nanos_since_unix_epoch(t.time_nanos)),
        })
    }
}
