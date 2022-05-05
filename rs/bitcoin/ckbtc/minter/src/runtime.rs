///! This module provides an abstraction of the dependencies of the ckBTC Minter.
///!
///! The [`Runtime`] trait is the abstraction and has two implementations:
///! - [`MockRuntime`] provides a mocked implementation of the runtime
///! - [`CanisterRuntime`] provides the real implementation of the runtime
use async_trait::async_trait;

/// Represents all the dependencies of the ckBTC Minter.
#[async_trait]
pub trait Runtime {}

/// [`Runtime`] implementation calling the real ic primitives.
pub struct CanisterRuntime {}

#[async_trait]
impl Runtime for CanisterRuntime {}

#[derive(Clone)]
pub struct MockRuntime {}

/// [`Runtime`] mocked implementation.
///
/// The return of each function can be set a-priori.
impl MockRuntime {
    pub fn new() -> MockRuntime {
        Self {}
    }
}

impl Default for MockRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Runtime for MockRuntime {}
