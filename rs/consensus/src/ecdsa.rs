//! This module provides the component responsible for generating and validating
//! payloads relevant to threshold ECDSA signatures.
//!
//! # Goal of threshold ECDSA
//! We want canisters to be able to hold BTC, ETH, and for them to create
//! bitcoin and ethereum transactions. Since those networks use ECDSA, a
//! canister must be able to create ECDSA signatures. Since a canister cannot
//! hold the secret key itself, the secret key will be shared among the replicas
//! of the subnet, and they must be able to collaboratively create ECDSA
//! signatures.
//!
//! # High level implementation design
//! Each subnet will have a single threshold ECDSA key. From this key, we will
//! derive per-canister keys. A canister can via a system API request an ECDSA
//! signature, and this request is stored in the replicated state. Consensus
//! will observe these requests and store in blocks which signatures should be
//! created.
//!
//! ## Distributed Key Generation & Transcripts
//! To create threshold ECDSA signatures we need a `Transcript` that gives all
//! replicas shares of an ECDSA secret key. However, this is not sufficient: we
//! need additional transcripts to share the ephemeral values used in an ECDSA
//! signature. The creation of one ECDSA signature requires a transcript that
//! shares the ECDSA signing key `x`, and additionally four DKG transcripts,
//! with a special structure: we need transcripts `t1`, `t2`, `t3`, `t4`, such
//! that `t1` and `t2` share a random values `r1` and `r2` respectively, `t3`
//! shares the product `r1 * r2`, and `t4` shares `r2 * x`.
//!
//! Such transcripts are created via a distributed key generation (DKG)
//! protocol. The DKG for these transcripts must be computationally efficient,
//! because we need four transcripts per signature, and we want to be able to
//! create many signatures. This means that we need interactive DKG for ECDSA
//! related things, instead of non-interactive DKG like we do for our threshold
//! BLS signatures.
//!
//! Consensus orchestrates the creation of these transcripts. Blocks contain
//! configs indicating which transcripts should be created. Such configs come in
//! different types, because some transcripts should share a random value, while
//! others need to share the product of two other transcripts. Complete
//! transcripts will be included in blocks via the functions
//! [create_tecdsa_payload] and [validate_tecdsa_payload].
//!
//! # [EcdsaImpl] behavior
//! The ECDSA component is responsible for adding artifacts to the ECDSA
//! artifact pool, and validating artifacts in that pool, by exposing a function
//! `on_state_change`. This function behaves as follows, where `finalized_tip`
//! denotes the latest finalized consensus block.
//!
//! ## add DKG dealings
//! for every config in `finalized_tip.ecdsa.configs`, do the following: if this
//! replica is a dealer in this config, and no dealing for this config created
//! by this replica is in the validated pool,then create a dealing for this
//! config, and add it to the validated pool
//!
//! ## validate DKG dealings
//! for every unvalidated dealing d, do the following. If `d.config_id` is an
//! element of `finalized_tip.ecdsa.configs`, the validated pool does not yet
//! contain a dealing from `d.dealer` for `d.config_id`, then cryptographically
//! validate the dealing, and move it to the validated pool if valid, or remove
//! it from the unvalidated pool if invalid.
//!
//! ## Remove stale dealings
//! for every validated or unvalidated dealing d, do the following. If
//! `d.config_id` is not an element of `finalized_tip.ecdsa.configs`, and
//! `d.config_id` is older than `finalized_tip`, remove `d` from the pool.
//!
//! ## add signature shares
//! for every signature request `req` in
//! `finalized_tip.ecdsa.signature_requests`, do the following: if this replica
//! is a signer for `req` and no signature share by this replica is in the
//! validated pool, create a signature share for `req` and add it to the
//! validated pool.
//!
//! ## validate signature shares
//! for every unvalidated signature share s, do the following: if `s.config_id`
//! is an element of `finalized_tip.ecdsa.configs`, and there is no signature
//! share by `s.signer` for `s.config_id` in the validated pool yet, then
//! cryptographically validate the signature share. If valid, move `s` to
//! validated, and if invalid, remove `s` from unvalidated.
//!
//! ## aggregate ECDSA signatures
//! For every signature request `req` in
//! `finalized_tip.ecdsa.signature_requests` for which no signature is present
//! in the validated pool, do the following: if there are at least
//! `req.threshold` signature shares wrt `req.config` from distinct signers in
//! the validated pool, aggregate the shares into a full ECDSA signature, and
//! add this signature to the validated pool.
//!
//! ## validate full ECDSA signature
//! // TODO
//!
//! ## complaints & openings
//! // TODO

// TODO: Remove after implementing functionality
#![allow(dead_code)]

use ic_interfaces::ecdsa::{Ecdsa, EcdsaChangeSet, EcdsaGossip};
use ic_logger::ReplicaLogger;
use ic_types::{
    artifact::{EcdsaMessageAttribute, EcdsaMessageId, PriorityFn},
    consensus::ecdsa::EcdsaPayload,
};

/// `EcdsaImpl` is the consensus component responsible for processing threshold
/// ECDSA payloads.
pub struct EcdsaImpl {
    logger: ReplicaLogger,
}

impl EcdsaImpl {
    /// Build a new threshold ECDSA component
    pub fn new(logger: ReplicaLogger) -> Self {
        Self { logger }
    }
}

impl Ecdsa for EcdsaImpl {
    fn on_state_change(&self, _ecdsa_pool: &dyn ic_interfaces::ecdsa::EcdsaPool) -> EcdsaChangeSet {
        todo!()
    }
}

impl EcdsaGossip for EcdsaImpl {
    fn get_priority_function(
        &self,
        _ecdsa_pool: &dyn ic_interfaces::ecdsa::EcdsaPool,
    ) -> PriorityFn<EcdsaMessageId, EcdsaMessageAttribute> {
        todo!()
    }
}

impl EcdsaImpl {}

/// Creates a threshold ECDSA payload.
pub fn create_tecdsa_payload() -> Result<EcdsaPayload, EcdsaPayloadError> {
    todo!()
}

/// Validates a threshold ECDSA payload.
pub fn validate_tecdsa_payload(_payload: EcdsaPayload) -> Result<(), EcdsaPayloadError> {
    todo!()
}

// TODO: Implement an appropriate Error type
type EcdsaPayloadError = String;
