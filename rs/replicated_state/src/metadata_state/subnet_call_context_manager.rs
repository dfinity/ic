use ic_logger::{info, ReplicaLogger};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::system_metadata::v1 as pb_metadata,
};
use ic_types::{
    crypto::threshold_sig::ni_dkg::{id::ni_dkg_target_id, NiDkgTargetId},
    messages::{CallbackId, Request},
    node_id_into_protobuf, node_id_try_from_protobuf, NodeId, RegistryVersion, Time,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{From, TryFrom},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubnetCallContextManager {
    next_callback_id: u64,
    pub setup_initial_dkg_contexts: BTreeMap<CallbackId, SetupInitialDkgContext>,
    pub sign_with_ecdsa_contexts: BTreeMap<CallbackId, SignWithEcdsaContext>,
    pub sign_with_mock_ecdsa_contexts: BTreeMap<CallbackId, SignWithEcdsaContext>,
}

impl SubnetCallContextManager {
    pub fn push_setup_initial_dkg_request(&mut self, context: SetupInitialDkgContext) {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;

        self.setup_initial_dkg_contexts.insert(callback_id, context);
    }

    pub fn push_sign_with_ecdsa_request(&mut self, context: SignWithEcdsaContext, is_mock: bool) {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;
        match is_mock {
            true => self
                .sign_with_mock_ecdsa_contexts
                .insert(callback_id, context),
            false => self.sign_with_ecdsa_contexts.insert(callback_id, context),
        };
    }

    pub fn retrieve_request(
        &mut self,
        callback_id: CallbackId,
        logger: &ReplicaLogger,
    ) -> Option<Request> {
        self.setup_initial_dkg_contexts
            .remove(&callback_id)
            .map(|context| {
                info!(
                    logger,
                    "Received the response for SetupInitialDKG request for target {:?}",
                    context.target_id
                );
                context.request
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
                        context.request
                    })
            })
            .or_else(|| {
                self.sign_with_mock_ecdsa_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                    logger,
                    "Received the response for SignWithMockECDSA request with id {:?} from {:?}",
                    context.pseudo_random_id,
                    context.request.sender
                );
                        context.request
                    })
            })
    }
}

impl From<&SubnetCallContextManager> for pb_metadata::SubnetCallContextManager {
    fn from(item: &SubnetCallContextManager) -> Self {
        Self {
            next_callback_id: item.next_callback_id,
            // [CON-564] Remove the deprecated SubnetCallContext from the protobuf
            contexts: vec![],
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
            sign_with_mock_ecdsa_contexts: item
                .sign_with_mock_ecdsa_contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::SignWithEcdsaContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::SubnetCallContextManager> for SubnetCallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetCallContextManager) -> Result<Self, Self::Error> {
        let mut setup_initial_dkg_contexts = BTreeMap::<CallbackId, SetupInitialDkgContext>::new();
        for entry in item.contexts {
            if let Some(context) = entry.context {
                let context: SetupInitialDkgContext = try_from_option_field(
                    context.setup_initial_dkg_context,
                    "SystemMetadata::SubnetCallContextManager::SetupInitialDkgContext",
                )?;
                setup_initial_dkg_contexts.insert(CallbackId::new(entry.callback_id), context);
            }
        }
        for entry in item.setup_initial_dkg_contexts {
            let context: SetupInitialDkgContext =
                try_from_option_field(entry.context, "SystemMetadata::SetupInitialDkgContext")?;
            setup_initial_dkg_contexts.insert(CallbackId::new(entry.callback_id), context);
        }
        let mut sign_with_ecdsa_contexts = BTreeMap::<CallbackId, SignWithEcdsaContext>::new();
        for entry in item.sign_with_ecdsa_contexts {
            let context: SignWithEcdsaContext =
                try_from_option_field(entry.context, "SystemMetadata::SignWithEcdsaContext")?;
            sign_with_ecdsa_contexts.insert(CallbackId::new(entry.callback_id), context);
        }
        let mut sign_with_mock_ecdsa_contexts = BTreeMap::<CallbackId, SignWithEcdsaContext>::new();
        for entry in item.sign_with_mock_ecdsa_contexts {
            let context: SignWithEcdsaContext =
                try_from_option_field(entry.context, "SystemMetadata::SignWithMockEcdsaContext")?;
            sign_with_mock_ecdsa_contexts.insert(CallbackId::new(entry.callback_id), context);
        }
        Ok(Self {
            next_callback_id: item.next_callback_id,
            setup_initial_dkg_contexts,
            sign_with_ecdsa_contexts,
            sign_with_mock_ecdsa_contexts,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupInitialDkgContext {
    pub request: Request,
    pub nodes_in_target_subnet: BTreeSet<NodeId>,
    pub target_id: NiDkgTargetId,
    pub registry_version: RegistryVersion,
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
        }
    }
}

impl TryFrom<pb_metadata::SetupInitialDkgContext> for SetupInitialDkgContext {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::SetupInitialDkgContext) -> Result<Self, Self::Error> {
        let mut nodes_in_target_subnet = BTreeSet::<NodeId>::new();
        for node_id in context.nodes_in_subnet {
            nodes_in_target_subnet.insert(node_id_try_from_protobuf(node_id)?);
        }
        Ok(SetupInitialDkgContext {
            request: try_from_option_field(context.request, "SetupInitialDkgContext::request")?,
            nodes_in_target_subnet,
            target_id: match ni_dkg_target_id(context.target_id.as_slice()) {
                Ok(target_id) => target_id,
                Err(_) => return Err(Self::Error::Other("target_id is not 32 bytes.".to_string())),
            },
            registry_version: RegistryVersion::from(context.registry_version),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignWithEcdsaContext {
    pub request: Request,
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<u8>,
    pub pseudo_random_id: [u8; 32],
    pub batch_time: Time,
}

impl From<&SignWithEcdsaContext> for pb_metadata::SignWithEcdsaContext {
    fn from(context: &SignWithEcdsaContext) -> Self {
        pb_metadata::SignWithEcdsaContext {
            request: Some((&context.request).into()),
            message_hash: context.message_hash.to_vec(),
            derivation_path: context.derivation_path.to_vec(),
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
        Ok(SignWithEcdsaContext {
            message_hash: context.message_hash,
            derivation_path: context.derivation_path,
            request,
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
