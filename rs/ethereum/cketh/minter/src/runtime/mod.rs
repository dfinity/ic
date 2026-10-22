use crate::eth_rpc_client::rpc_client;
use crate::management::CallError;
use crate::state::read_state;
use crate::time::{IC_TIME_PROVIDER, TimeProvider};
use async_trait::async_trait;
use evm_rpc_client::{CandidResponseConverter, DoubleCycles, EvmRpcClient};
use ic_canister_runtime::{IcRuntime, Runtime};
use ic_cdk_management_canister::EcdsaPublicKeyResult;
use ic_management_canister_types_private::DerivationPath;
use serde_bytes::ByteBuf;

/// The canister capabilities the minter needs from its environment.
///
/// Abstracting them away lets the logic that drives them be exercised without a canister.
#[async_trait]
pub trait CanisterRuntime: TimeProvider {
    /// The runtime the EVM RPC client makes its canister calls through.
    type Rpc: Runtime;

    /// A client of the EVM RPC canister, set up for the Ethereum network the minter runs against.
    fn evm_rpc_client(&self) -> EvmRpcClient<Self::Rpc, CandidResponseConverter, DoubleCycles>;

    /// Signs a message hash with the tECDSA key `key_name` derived along `derivation_path`.
    async fn sign_with_ecdsa(
        &self,
        key_name: String,
        derivation_path: Vec<Vec<u8>>,
        message_hash: [u8; 32],
    ) -> Result<[u8; 64], CallError>;

    /// The tECDSA public key `key_name` derived along `derivation_path`, with its chain code.
    async fn ecdsa_public_key(
        &self,
        key_name: String,
        derivation_path: Vec<Vec<u8>>,
    ) -> Result<EcdsaPublicKeyResult, CallError>;
}

/// The [`CanisterRuntime`] used in production, backed by the Internet Computer system API.
pub const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IcCanisterRuntime;

impl TimeProvider for IcCanisterRuntime {
    fn time(&self) -> u64 {
        IC_TIME_PROVIDER.time()
    }
}

#[async_trait]
impl CanisterRuntime for IcCanisterRuntime {
    type Rpc = IcRuntime;

    fn evm_rpc_client(&self) -> EvmRpcClient<IcRuntime, CandidResponseConverter, DoubleCycles> {
        read_state(rpc_client)
    }

    async fn sign_with_ecdsa(
        &self,
        key_name: String,
        derivation_path: Vec<Vec<u8>>,
        message_hash: [u8; 32],
    ) -> Result<[u8; 64], CallError> {
        crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(derivation_path.into_iter().map(ByteBuf::from).collect()),
            message_hash,
        )
        .await
    }

    async fn ecdsa_public_key(
        &self,
        key_name: String,
        derivation_path: Vec<Vec<u8>>,
    ) -> Result<EcdsaPublicKeyResult, CallError> {
        crate::management::ecdsa_public_key(
            key_name,
            DerivationPath::new(derivation_path.into_iter().map(ByteBuf::from).collect()),
        )
        .await
    }
}
