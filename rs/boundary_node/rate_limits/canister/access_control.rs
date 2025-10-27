use candid::Principal;
use mockall::automock;

use crate::{
    add_config::AddsConfig,
    disclose::DisclosesRules,
    state::CanisterApi,
    types::{AddConfigError, DiscloseRulesError, Timestamp},
};

#[automock]
pub trait ResolveAccessLevel {
    fn get_access_level(&self) -> AccessLevel;
}

#[derive(Clone, PartialEq, Eq)]
pub enum AccessLevel {
    FullAccess,
    FullRead,
    RestrictedRead,
}

#[derive(Clone)]
pub struct AccessLevelResolver<R: CanisterApi> {
    pub caller_id: Principal,
    pub canister_api: R,
}

impl<R: CanisterApi> AccessLevelResolver<R> {
    pub fn new(caller_id: Principal, canister_api: R) -> Self {
        Self {
            caller_id,
            canister_api,
        }
    }
}

impl<R: CanisterApi> ResolveAccessLevel for AccessLevelResolver<R> {
    fn get_access_level(&self) -> AccessLevel {
        if let Some(authorized_principal) = self.canister_api.get_authorized_principal()
            && self.caller_id == authorized_principal
        {
            return AccessLevel::FullAccess;
        }

        let has_full_read_access = self
            .canister_api
            .is_api_boundary_node_principal(&self.caller_id);

        if has_full_read_access {
            return AccessLevel::FullRead;
        }

        AccessLevel::RestrictedRead
    }
}

pub struct WithAuthorization<T, R> {
    inner: T,
    access_resolver: R,
}

impl<T, R> WithAuthorization<T, R> {
    pub fn new(inner: T, access_resolver: R) -> Self {
        Self {
            inner,
            access_resolver,
        }
    }
}

impl<T: AddsConfig, R: ResolveAccessLevel> AddsConfig for WithAuthorization<T, R> {
    fn add_config(
        &self,
        input_config: rate_limits_api::InputConfig,
        time: Timestamp,
    ) -> Result<(), AddConfigError> {
        // Only privileged users can perform this operation
        if self.access_resolver.get_access_level() == AccessLevel::FullAccess {
            // Perform the inner call only if authorized.
            return self.inner.add_config(input_config, time);
        }
        Err(AddConfigError::Unauthorized)
    }
}

impl<T: DisclosesRules, R: ResolveAccessLevel> DisclosesRules for WithAuthorization<T, R> {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        current_time: Timestamp,
    ) -> Result<(), DiscloseRulesError> {
        // Only privileged users can perform this operation
        if self.access_resolver.get_access_level() == AccessLevel::FullAccess {
            return self.inner.disclose_rules(arg, current_time);
        }
        Err(DiscloseRulesError::Unauthorized)
    }
}
