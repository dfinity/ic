///! This module provides an abstraction of the dependencies of the ckBTC Minter.
///!
///! The [`Runtime`] trait is the abstraction and has two implementations:
///! - [`MockRuntime`] provides a mocked implementation of the runtime
///! - [`CanisterRuntime`] provides the real implementation of the runtime
use async_trait::async_trait;
use bitcoin::AddressType;
use candid::Principal;

/// Represents all the dependencies of the ckBTC Minter.
#[async_trait]
pub trait Runtime {
    /// The principal of this canister
    fn id(&self) -> Principal;

    /// The principal of the caller
    fn caller(&self) -> Principal;

    /// Return the Bitcoin address for the given path and type
    fn address(&self, derivation_path: Vec<Vec<u8>>, address_type: &AddressType) -> String;
}

/// [`Runtime`] implementation calling the real ic primitives.
pub struct CanisterRuntime {}

#[async_trait]
impl Runtime for CanisterRuntime {
    fn id(&self) -> Principal {
        ic_cdk::id()
    }

    fn caller(&self) -> Principal {
        ic_cdk::caller()
    }

    fn address(&self, _derivation_path: Vec<Vec<u8>>, _address_type: &AddressType) -> String {
        todo!()
    }
}

#[derive(Clone)]
pub struct MockRuntime {
    pub id_result: Option<Principal>,
    pub caller_result: Option<Principal>,
    pub address_result: Option<String>,
}

/// [`Runtime`] mocked implementation.
///
/// The return of each function can be set a-priori.
impl MockRuntime {
    pub fn new() -> MockRuntime {
        Self {
            id_result: None,
            caller_result: None,
            address_result: None,
        }
    }

    pub fn set_id_result(mut self, id: Principal) -> Self {
        self.id_result = Some(id);
        self
    }

    pub fn set_caller_result(mut self, caller: Principal) -> Self {
        self.caller_result = Some(caller);
        self
    }

    pub fn set_address_result(mut self, address: String) -> Self {
        self.address_result = Some(address);
        self
    }
}

impl Default for MockRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Runtime for MockRuntime {
    fn id(&self) -> Principal {
        self.id_result.expect("id result not set")
    }

    fn caller(&self) -> Principal {
        self.caller_result.expect("caller result not set")
    }

    fn address(&self, _derivation_path: Vec<Vec<u8>>, _address_type: &AddressType) -> String {
        self.address_result.clone().expect("address not set")
    }
}
