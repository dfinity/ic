pub mod proto;

use ic_btc_replica_types::{GetSuccessorsRequestInitial, SendTransactionRequest};
use ic_logger::{ReplicaLogger, info};
use ic_management_canister_types_private::{
    EcdsaKeyId, MasterPublicKeyId, SchnorrKeyId, VetKdKeyId,
};
use ic_types::{
    CanisterId, ExecutionRound, Height, NodeId, RegistryVersion, Time,
    canister_http::CanisterHttpRequestContext,
    consensus::idkg::{IDkgMasterPublicKeyId, PreSigId, common::PreSignature},
    crypto::{
        canister_threshold_sig::{
            EcdsaPreSignatureQuadruple, SchnorrPreSignatureTranscript, idkg::IDkgTranscript,
        },
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTargetId, id::ni_dkg_target_id},
    },
    messages::{CallbackId, CanisterCall, Request, StopCanisterCallId},
    node_id_into_protobuf, node_id_try_from_option,
};
use phantom_newtype::Id;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::{From, TryFrom},
    sync::Arc,
};

/// ECDSA message hash size in bytes.
const MESSAGE_HASH_SIZE: usize = 32;

/// Threshold algorithm pseudo-random ID size in bytes.
const PSEUDO_RANDOM_ID_SIZE: usize = 32;

/// Threshold algorithm nonce size in bytes.
const NONCE_SIZE: usize = 32;

pub enum SubnetCallContext {
    SetupInitialDKG(SetupInitialDkgContext),
    CanisterHttpRequest(CanisterHttpRequestContext),
    ReshareChainKey(ReshareChainKeyContext),
    BitcoinGetSuccessors(BitcoinGetSuccessorsContext),
    BitcoinSendTransactionInternal(BitcoinSendTransactionInternalContext),
    SignWithThreshold(SignWithThresholdContext),
}

impl SubnetCallContext {
    pub fn get_request(&self) -> &Request {
        match &self {
            SubnetCallContext::SetupInitialDKG(context) => &context.request,
            SubnetCallContext::CanisterHttpRequest(context) => &context.request,
            SubnetCallContext::ReshareChainKey(context) => &context.request,
            SubnetCallContext::BitcoinGetSuccessors(context) => &context.request,
            SubnetCallContext::BitcoinSendTransactionInternal(context) => &context.request,
            SubnetCallContext::SignWithThreshold(context) => &context.request,
        }
    }

    pub fn get_time(&self) -> Time {
        match &self {
            SubnetCallContext::SetupInitialDKG(context) => context.time,
            SubnetCallContext::CanisterHttpRequest(context) => context.time,
            SubnetCallContext::ReshareChainKey(context) => context.time,
            SubnetCallContext::BitcoinGetSuccessors(context) => context.time,
            SubnetCallContext::BitcoinSendTransactionInternal(context) => context.time,
            SubnetCallContext::SignWithThreshold(context) => context.batch_time,
        }
    }
}

pub struct InstallCodeCallIdTag;
pub type InstallCodeCallId = Id<InstallCodeCallIdTag, u64>;

/// Collection of install code call messages whose execution is paused at the
/// end of the round.
///
/// During a subnet split, these messages will be automatically rejected if
/// the targeted canister has moved to a new subnet.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
struct InstallCodeCallManager {
    next_call_id: u64,
    install_code_calls: BTreeMap<InstallCodeCallId, InstallCodeCall>,
}

impl InstallCodeCallManager {
    fn push_call(&mut self, call: InstallCodeCall) -> InstallCodeCallId {
        let call_id = InstallCodeCallId::new(self.next_call_id);
        self.next_call_id += 1;
        self.install_code_calls.insert(call_id, call);

        call_id
    }

    fn remove_call(&mut self, call_id: InstallCodeCallId) -> Option<InstallCodeCall> {
        self.install_code_calls.remove(&call_id)
    }

    /// Removes and returns all `InstallCodeCalls` not targeted to local canisters.
    ///
    /// Used for rejecting all calls targeting migrated canisters after a subnet
    /// split.
    fn remove_non_local_calls(
        &mut self,
        is_local_canister: impl Fn(CanisterId) -> bool,
    ) -> Vec<InstallCodeCall> {
        let mut removed = Vec::new();
        self.install_code_calls.retain(|_call_id, call| {
            if is_local_canister(call.effective_canister_id) {
                true
            } else {
                removed.push(call.clone());
                false
            }
        });
        removed
    }
}

/// Collection of stop canister messages whose execution is paused at the
/// end of the round.
///
/// During a subnet split, these messages will be automatically rejected if
/// the target canister has moved to a new subnet.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
struct StopCanisterCallManager {
    next_call_id: u64,
    stop_canister_calls: BTreeMap<StopCanisterCallId, StopCanisterCall>,
}

impl StopCanisterCallManager {
    fn push_call(&mut self, call: StopCanisterCall) -> StopCanisterCallId {
        let call_id = StopCanisterCallId::new(self.next_call_id);
        self.next_call_id += 1;
        self.stop_canister_calls.insert(call_id, call);

        call_id
    }

    fn remove_call(&mut self, call_id: StopCanisterCallId) -> Option<StopCanisterCall> {
        self.stop_canister_calls.remove(&call_id)
    }

    fn get_time(&self, call_id: &StopCanisterCallId) -> Option<Time> {
        self.stop_canister_calls.get(call_id).map(|x| x.time)
    }

    /// Removes and returns all `StopCanisterCalls` not targeted to local canisters.
    ///
    /// Used for rejecting all calls targeting migrated canisters after a subnet
    /// split.
    fn remove_non_local_calls(
        &mut self,
        is_local_canister: impl Fn(CanisterId) -> bool,
    ) -> Vec<StopCanisterCall> {
        let mut removed = Vec::new();
        self.stop_canister_calls.retain(|_call_id, call| {
            if is_local_canister(call.effective_canister_id) {
                true
            } else {
                removed.push(call.clone());
                false
            }
        });
        removed
    }
}

/// It is responsible for keeping track of all subnet messages that
/// do not require work to be done by another IC layer and
/// cannot finalize the execution in a single round.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
struct CanisterManagementCalls {
    install_code_call_manager: InstallCodeCallManager,
    stop_canister_call_manager: StopCanisterCallManager,
}

impl CanisterManagementCalls {
    fn push_install_code_call(&mut self, call: InstallCodeCall) -> InstallCodeCallId {
        self.install_code_call_manager.push_call(call)
    }

    fn push_stop_canister_call(&mut self, call: StopCanisterCall) -> StopCanisterCallId {
        self.stop_canister_call_manager.push_call(call)
    }

    fn remove_install_code_call(&mut self, call_id: InstallCodeCallId) -> Option<InstallCodeCall> {
        self.install_code_call_manager.remove_call(call_id)
    }

    fn remove_stop_canister_call(
        &mut self,
        call_id: StopCanisterCallId,
    ) -> Option<StopCanisterCall> {
        self.stop_canister_call_manager.remove_call(call_id)
    }

    fn get_time_for_stop_canister_call(&self, call_id: &StopCanisterCallId) -> Option<Time> {
        self.stop_canister_call_manager.get_time(call_id)
    }

    pub fn install_code_calls_len(&self) -> usize {
        self.install_code_call_manager.install_code_calls.len()
    }

    pub fn stop_canister_calls_len(&self) -> usize {
        self.stop_canister_call_manager.stop_canister_calls.len()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PreSignatureStash {
    pub key_transcript: Arc<IDkgTranscript>,
    pub pre_signatures: BTreeMap<PreSigId, PreSignature>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct SubnetCallContextManager {
    /// Should increase monotonically. This property is used to determine if a request
    /// corresponds to a future state.
    next_callback_id: u64,
    pub setup_initial_dkg_contexts: BTreeMap<CallbackId, SetupInitialDkgContext>,
    pub sign_with_threshold_contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
    pub canister_http_request_contexts: BTreeMap<CallbackId, CanisterHttpRequestContext>,
    pub reshare_chain_key_contexts: BTreeMap<CallbackId, ReshareChainKeyContext>,
    pub bitcoin_get_successors_contexts: BTreeMap<CallbackId, BitcoinGetSuccessorsContext>,
    pub bitcoin_send_transaction_internal_contexts:
        BTreeMap<CallbackId, BitcoinSendTransactionInternalContext>,
    canister_management_calls: CanisterManagementCalls,
    pub raw_rand_contexts: VecDeque<RawRandContext>,
    pub pre_signature_stashes: BTreeMap<IDkgMasterPublicKeyId, PreSignatureStash>,
}

impl SubnetCallContextManager {
    pub fn next_callback_id(&self) -> CallbackId {
        CallbackId::from(self.next_callback_id)
    }

    pub fn push_context(&mut self, context: SubnetCallContext) -> CallbackId {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;

        match context {
            SubnetCallContext::SetupInitialDKG(context) => {
                self.setup_initial_dkg_contexts.insert(callback_id, context);
            }
            SubnetCallContext::SignWithThreshold(context) => {
                self.sign_with_threshold_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::CanisterHttpRequest(context) => {
                self.canister_http_request_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::ReshareChainKey(context) => {
                self.reshare_chain_key_contexts.insert(callback_id, context);
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
                self.sign_with_threshold_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for SignWithThreshold request with id {:?} from {:?}",
                            context.pseudo_random_id,
                            context.request.sender
                        );
                        SubnetCallContext::SignWithThreshold(context)
                    })
            })
            .or_else(|| {
                self.reshare_chain_key_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for ReshareChainKey request with key_id {:?} and callback id {:?} from {:?}",
                            context.key_id,
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::ReshareChainKey(context)
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

    pub fn push_install_code_call(&mut self, call: InstallCodeCall) -> InstallCodeCallId {
        self.canister_management_calls.push_install_code_call(call)
    }

    pub fn remove_install_code_call(
        &mut self,
        call_id: InstallCodeCallId,
    ) -> Option<InstallCodeCall> {
        self.canister_management_calls
            .remove_install_code_call(call_id)
    }

    pub fn remove_non_local_install_code_calls(
        &mut self,
        is_local_canister: impl Fn(CanisterId) -> bool,
    ) -> Vec<InstallCodeCall> {
        self.canister_management_calls
            .install_code_call_manager
            .remove_non_local_calls(is_local_canister)
    }

    pub fn install_code_calls_len(&self) -> usize {
        self.canister_management_calls.install_code_calls_len()
    }

    pub fn push_stop_canister_call(&mut self, call: StopCanisterCall) -> StopCanisterCallId {
        self.canister_management_calls.push_stop_canister_call(call)
    }

    pub fn remove_stop_canister_call(
        &mut self,
        call_id: StopCanisterCallId,
    ) -> Option<StopCanisterCall> {
        self.canister_management_calls
            .remove_stop_canister_call(call_id)
    }

    pub fn get_time_for_stop_canister_call(&self, call_id: &StopCanisterCallId) -> Option<Time> {
        self.canister_management_calls
            .get_time_for_stop_canister_call(call_id)
    }

    pub fn remove_non_local_stop_canister_calls(
        &mut self,
        is_local_canister: impl Fn(CanisterId) -> bool,
    ) -> Vec<StopCanisterCall> {
        self.canister_management_calls
            .stop_canister_call_manager
            .remove_non_local_calls(is_local_canister)
    }

    pub fn stop_canister_calls_len(&self) -> usize {
        self.canister_management_calls.stop_canister_calls_len()
    }

    pub fn push_raw_rand_request(
        &mut self,
        request: Request,
        execution_round_id: ExecutionRound,
        time: Time,
    ) {
        self.raw_rand_contexts.push_back(RawRandContext {
            request,
            execution_round_id,
            time,
        });
    }

    pub fn remove_non_local_raw_rand_calls(
        &mut self,
        is_local_canister: impl Fn(CanisterId) -> bool,
    ) -> Vec<RawRandContext> {
        let mut removed = Vec::new();
        self.raw_rand_contexts.retain(|context| {
            if is_local_canister(context.request.sender()) {
                true
            } else {
                removed.push(context.clone());
                false
            }
        });
        removed
    }

    /// Returns the number of `sign_with_threshold_contexts` per key id.
    pub fn sign_with_threshold_contexts_count(&self, key_id: &MasterPublicKeyId) -> usize {
        self.sign_with_threshold_contexts
            .iter()
            .filter(|(_, context)| match (key_id, &context.args) {
                (MasterPublicKeyId::Ecdsa(ecdsa_key_id), ThresholdArguments::Ecdsa(args)) => {
                    args.key_id == *ecdsa_key_id
                }
                (MasterPublicKeyId::Schnorr(schnorr_key_id), ThresholdArguments::Schnorr(args)) => {
                    args.key_id == *schnorr_key_id
                }
                (MasterPublicKeyId::VetKd(vetkd_key_id), ThresholdArguments::VetKd(args)) => {
                    args.key_id == *vetkd_key_id
                }
                _ => false,
            })
            .count()
    }

    pub fn sign_with_ecdsa_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        self.sign_with_threshold_contexts
            .iter()
            .filter(|(_, context)| context.is_ecdsa())
            .map(|(cid, context)| (*cid, context.clone()))
            .collect()
    }

    pub fn sign_with_schnorr_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        self.sign_with_threshold_contexts
            .iter()
            .filter(|(_, context)| context.is_schnorr())
            .map(|(cid, context)| (*cid, context.clone()))
            .collect()
    }

    pub fn vetkd_derive_key_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        self.sign_with_threshold_contexts
            .iter()
            .filter(|(_, context)| context.is_vetkd())
            .map(|(cid, context)| (*cid, context.clone()))
            .collect()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SetupInitialDkgContext {
    pub request: Request,
    pub nodes_in_target_subnet: BTreeSet<NodeId>,
    pub target_id: NiDkgTargetId,
    pub registry_version: RegistryVersion,
    pub time: Time,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EcdsaMatchedPreSignature {
    pub id: PreSigId,
    pub height: Height,
    pub pre_signature: Arc<EcdsaPreSignatureQuadruple>,
    pub key_transcript: Arc<IDkgTranscript>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EcdsaArguments {
    pub key_id: EcdsaKeyId,
    pub message_hash: [u8; MESSAGE_HASH_SIZE],
    pub pre_signature: Option<EcdsaMatchedPreSignature>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SchnorrMatchedPreSignature {
    pub id: PreSigId,
    pub height: Height,
    pub pre_signature: Arc<SchnorrPreSignatureTranscript>,
    pub key_transcript: Arc<IDkgTranscript>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SchnorrArguments {
    pub key_id: SchnorrKeyId,
    pub message: Arc<Vec<u8>>,
    pub taproot_tree_root: Option<Arc<Vec<u8>>>,
    pub pre_signature: Option<SchnorrMatchedPreSignature>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VetKdArguments {
    pub key_id: VetKdKeyId,
    pub input: Arc<Vec<u8>>,
    pub transport_public_key: Vec<u8>,
    pub ni_dkg_id: NiDkgId,
    pub height: Height,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ThresholdArguments {
    Ecdsa(EcdsaArguments),
    Schnorr(SchnorrArguments),
    VetKd(VetKdArguments),
}

impl ThresholdArguments {
    /// Returns the generic key id.
    pub fn key_id(&self) -> MasterPublicKeyId {
        match self {
            ThresholdArguments::Ecdsa(args) => MasterPublicKeyId::Ecdsa(args.key_id.clone()),
            ThresholdArguments::Schnorr(args) => MasterPublicKeyId::Schnorr(args.key_id.clone()),
            ThresholdArguments::VetKd(args) => MasterPublicKeyId::VetKd(args.key_id.clone()),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct IDkgSignWithThresholdContext<'a>(&'a SignWithThresholdContext);

impl<'a> TryFrom<&'a SignWithThresholdContext> for IDkgSignWithThresholdContext<'a> {
    type Error = ();

    fn try_from(val: &'a SignWithThresholdContext) -> Result<Self, Self::Error> {
        if !val.is_idkg() {
            Err(())
        } else {
            Ok(Self(val))
        }
    }
}

impl<'a> From<IDkgSignWithThresholdContext<'a>> for &'a SignWithThresholdContext {
    fn from(val: IDkgSignWithThresholdContext<'a>) -> Self {
        val.0
    }
}

impl IDkgSignWithThresholdContext<'_> {
    pub fn inner(&self) -> &SignWithThresholdContext {
        self.0
    }
}

impl std::ops::Deref for IDkgSignWithThresholdContext<'_> {
    type Target = SignWithThresholdContext;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        self.inner()
    }
}

impl std::borrow::Borrow<SignWithThresholdContext> for IDkgSignWithThresholdContext<'_> {
    fn borrow(&self) -> &SignWithThresholdContext {
        self.inner()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignWithThresholdContext {
    pub request: Request,
    pub args: ThresholdArguments,
    pub derivation_path: Arc<Vec<Vec<u8>>>,
    pub pseudo_random_id: [u8; PSEUDO_RANDOM_ID_SIZE],
    pub batch_time: Time,
    pub matched_pre_signature: Option<(PreSigId, Height)>,
    pub nonce: Option<[u8; NONCE_SIZE]>,
}

impl SignWithThresholdContext {
    /// Returns the key id of the master public key.
    pub fn key_id(&self) -> MasterPublicKeyId {
        match &self.args {
            ThresholdArguments::Ecdsa(args) => MasterPublicKeyId::Ecdsa(args.key_id.clone()),
            ThresholdArguments::Schnorr(args) => MasterPublicKeyId::Schnorr(args.key_id.clone()),
            ThresholdArguments::VetKd(args) => MasterPublicKeyId::VetKd(args.key_id.clone()),
        }
    }

    pub fn requires_pre_signature(&self) -> bool {
        match &self.args {
            ThresholdArguments::Ecdsa(args) => {
                self.matched_pre_signature.is_none() && args.pre_signature.is_none()
            }
            ThresholdArguments::Schnorr(args) => {
                self.matched_pre_signature.is_none() && args.pre_signature.is_none()
            }
            ThresholdArguments::VetKd(_) => false,
        }
    }

    /// Returns true if arguments are for ECDSA.
    pub fn is_ecdsa(&self) -> bool {
        matches!(&self.args, ThresholdArguments::Ecdsa(_))
    }

    /// Returns true if arguments are for Schnorr.
    pub fn is_schnorr(&self) -> bool {
        matches!(&self.args, ThresholdArguments::Schnorr(_))
    }

    /// Returns true if arguments are for VetKd.
    pub fn is_vetkd(&self) -> bool {
        matches!(&self.args, ThresholdArguments::VetKd(_))
    }

    /// Returns true if arguments are for a context handled by IDKG.
    pub fn is_idkg(&self) -> bool {
        match &self.args {
            ThresholdArguments::Ecdsa(_) | ThresholdArguments::Schnorr(_) => true,
            ThresholdArguments::VetKd(_) => false,
        }
    }

    /// Returns ECDSA arguments.
    /// Panics if arguments are not for ECDSA.
    /// Should only be called if `is_ecdsa` returns true.
    pub fn ecdsa_args(&self) -> &EcdsaArguments {
        match &self.args {
            ThresholdArguments::Ecdsa(args) => args,
            _ => panic!("ECDSA arguments not found."),
        }
    }

    /// Returns Schnorr arguments.
    /// Panics if arguments are not for Schnorr
    /// Should only be called if `is_schnorr` returns true.
    pub fn schnorr_args(&self) -> &SchnorrArguments {
        match &self.args {
            ThresholdArguments::Schnorr(args) => args,
            _ => panic!("Schnorr arguments not found."),
        }
    }

    /// Returns VetKd arguments.
    /// Panics if arguments are not for VetKd
    /// Should only be called if `is_vetkd` returns true.
    pub fn vetkd_args(&self) -> &VetKdArguments {
        match &self.args {
            ThresholdArguments::VetKd(args) => args,
            _ => panic!("VetKd arguments not found."),
        }
    }

    /// Return all IDkgTranscripts included in this context
    pub fn iter_idkg_transcripts(&self) -> impl Iterator<Item = &IDkgTranscript> {
        let refs = match &self.args {
            ThresholdArguments::Ecdsa(args) => args
                .pre_signature
                .as_ref()
                .map(|pre_sig| {
                    vec![
                        pre_sig.pre_signature.kappa_unmasked(),
                        pre_sig.pre_signature.lambda_masked(),
                        pre_sig.pre_signature.kappa_times_lambda(),
                        pre_sig.pre_signature.key_times_lambda(),
                        &pre_sig.key_transcript,
                    ]
                })
                .unwrap_or_default(),
            ThresholdArguments::Schnorr(args) => args
                .pre_signature
                .as_ref()
                .map(|pre_sig| {
                    vec![
                        pre_sig.pre_signature.blinder_unmasked(),
                        &pre_sig.key_transcript,
                    ]
                })
                .unwrap_or_default(),
            ThresholdArguments::VetKd(_) => vec![],
        };
        refs.into_iter()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ReshareChainKeyContext {
    pub request: Request,
    pub key_id: MasterPublicKeyId,
    pub nodes: BTreeSet<NodeId>,
    pub registry_version: RegistryVersion,
    pub time: Time,
    pub target_id: NiDkgTargetId,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BitcoinGetSuccessorsContext {
    pub request: Request,
    pub payload: GetSuccessorsRequestInitial,
    pub time: Time,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BitcoinSendTransactionInternalContext {
    pub request: Request,
    pub payload: SendTransactionRequest,
    pub time: Time,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct InstallCodeCall {
    pub call: CanisterCall,
    pub time: Time,
    pub effective_canister_id: CanisterId,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StopCanisterCall {
    pub call: CanisterCall,
    pub effective_canister_id: CanisterId,
    pub time: Time,
}

/// Struct for tracking the required information needed for creating a response.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RawRandContext {
    pub request: Request,
    pub time: Time,
    pub execution_round_id: ExecutionRound,
}

mod testing {
    use super::*;

    /// Early warning system / stumbling block forcing the authors of changes adding
    /// or removing replicated state fields to think about and/or ask the Message
    /// Routing team to think about any repercussions to the subnet splitting logic.
    ///
    /// If you do find yourself having to make changes to this function, it is quite
    /// possible that you have not broken anything. But there is a non-zero chance
    /// for changes to the structure of the replicated state to also require changes
    /// to the subnet splitting logic or risk breaking it. Which is why this brute
    /// force check exists.
    ///
    /// See `ReplicatedState::split()` and `ReplicatedState::after_split()` for more
    /// context.
    #[allow(dead_code)]
    fn subnet_splitting_change_guard_do_not_modify_without_reading_doc_comment() {
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let canister_management_calls = CanisterManagementCalls {
            install_code_call_manager: Default::default(),
            stop_canister_call_manager: Default::default(),
        };
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let _subnet_call_context_manager = SubnetCallContextManager {
            next_callback_id: 0,
            setup_initial_dkg_contexts: Default::default(),
            sign_with_threshold_contexts: Default::default(),
            canister_http_request_contexts: Default::default(),
            reshare_chain_key_contexts: Default::default(),
            bitcoin_get_successors_contexts: Default::default(),
            bitcoin_send_transaction_internal_contexts: Default::default(),
            canister_management_calls,
            raw_rand_contexts: Default::default(),
            pre_signature_stashes: Default::default(),
        };
    }
}
