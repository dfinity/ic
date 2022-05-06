// Annotations related to the use of hardware wallets. The annotated messages are
// parsed on hardware wallets and marked fields are displayed in a trusted user
// interface (TUI). We must not, for instance, add fields that would change the
// semantics of the message such that old hardware wallets would not display
// appropriate information to users.

// ** LEDGER CANISTER ENDPOINTS

/// Initialise the ledger canister
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LedgerInit {
    #[prost(message, optional, tag="1")]
    pub minting_account: ::core::option::Option<AccountIdentifier>,
    #[prost(message, repeated, tag="2")]
    pub initial_values: ::prost::alloc::vec::Vec<Account>,
    #[prost(message, optional, tag="3")]
    pub archive_canister: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(uint32, tag="4")]
    pub max_message_size_bytes: u32,
}
/// The format of values serialized to/from the stable memory during and upgrade
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LedgerUpgrade {
}
/// Make a payment
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendRequest {
    #[prost(message, optional, tag="1")]
    pub memo: ::core::option::Option<Memo>,
    #[prost(message, optional, tag="2")]
    pub payment: ::core::option::Option<Payment>,
    #[prost(message, optional, tag="3")]
    pub max_fee: ::core::option::Option<Tokens>,
    #[prost(message, optional, tag="4")]
    pub from_subaccount: ::core::option::Option<Subaccount>,
    #[prost(message, optional, tag="5")]
    pub to: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="6")]
    pub created_at: ::core::option::Option<BlockHeight>,
    #[prost(message, optional, tag="7")]
    pub created_at_time: ::core::option::Option<TimeStamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendResponse {
    #[prost(message, optional, tag="1")]
    pub resulting_height: ::core::option::Option<BlockHeight>,
}
/// Notify a canister that it has received a payment
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyRequest {
    #[prost(message, optional, tag="1")]
    pub block_height: ::core::option::Option<BlockHeight>,
    #[prost(message, optional, tag="2")]
    pub max_fee: ::core::option::Option<Tokens>,
    #[prost(message, optional, tag="3")]
    pub from_subaccount: ::core::option::Option<Subaccount>,
    #[prost(message, optional, tag="4")]
    pub to_canister: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag="5")]
    pub to_subaccount: ::core::option::Option<Subaccount>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionNotificationRequest {
    #[prost(message, optional, tag="1")]
    pub from: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag="2")]
    pub from_subaccount: ::core::option::Option<Subaccount>,
    #[prost(message, optional, tag="3")]
    pub to: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag="4")]
    pub to_subaccount: ::core::option::Option<Subaccount>,
    #[prost(message, optional, tag="5")]
    pub block_height: ::core::option::Option<BlockHeight>,
    #[prost(message, optional, tag="6")]
    pub amount: ::core::option::Option<Tokens>,
    #[prost(message, optional, tag="7")]
    pub memo: ::core::option::Option<Memo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionNotificationResponse {
    #[prost(bytes="vec", tag="1")]
    pub response: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CyclesNotificationResponse {
    #[prost(oneof="cycles_notification_response::Response", tags="1, 2, 3")]
    pub response: ::core::option::Option<cycles_notification_response::Response>,
}
/// Nested message and enum types in `CyclesNotificationResponse`.
pub mod cycles_notification_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag="1")]
        CreatedCanisterId(::ic_base_types::PrincipalId),
        #[prost(message, tag="2")]
        Refund(super::Refund),
        #[prost(message, tag="3")]
        ToppedUp(super::ToppedUp),
    }
}
/// Get the balance of an account
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountBalanceRequest {
    #[prost(message, optional, tag="1")]
    pub account: ::core::option::Option<AccountIdentifier>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountBalanceResponse {
    #[prost(message, optional, tag="1")]
    pub balance: ::core::option::Option<Tokens>,
}
/// Get the length of the chain with a certification
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TipOfChainRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TipOfChainResponse {
    #[prost(message, optional, tag="1")]
    pub certification: ::core::option::Option<Certification>,
    #[prost(message, optional, tag="2")]
    pub chain_length: ::core::option::Option<BlockHeight>,
}
/// How many Tokens are there not in the minting account
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TotalSupplyRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TotalSupplyResponse {
    #[prost(message, optional, tag="1")]
    pub total_supply: ::core::option::Option<Tokens>,
}
/// Archive any blocks older than this
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LedgerArchiveRequest {
    #[prost(message, optional, tag="1")]
    pub timestamp: ::core::option::Option<TimeStamp>,
}
// * Shared Endpoints *

/// Get a single block
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockRequest {
    #[prost(uint64, tag="1")]
    pub block_height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncodedBlock {
    #[prost(bytes="vec", tag="1")]
    pub block: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockResponse {
    #[prost(oneof="block_response::BlockContent", tags="1, 2")]
    pub block_content: ::core::option::Option<block_response::BlockContent>,
}
/// Nested message and enum types in `BlockResponse`.
pub mod block_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum BlockContent {
        #[prost(message, tag="1")]
        Block(super::EncodedBlock),
        #[prost(message, tag="2")]
        CanisterId(::ic_base_types::PrincipalId),
    }
}
/// Get a set of blocks
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBlocksRequest {
    #[prost(uint64, tag="1")]
    pub start: u64,
    #[prost(uint64, tag="2")]
    pub length: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Refund {
    #[prost(message, optional, tag="2")]
    pub refund: ::core::option::Option<BlockHeight>,
    #[prost(string, tag="3")]
    pub error: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToppedUp {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncodedBlocks {
    #[prost(message, repeated, tag="1")]
    pub blocks: ::prost::alloc::vec::Vec<EncodedBlock>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBlocksResponse {
    #[prost(oneof="get_blocks_response::GetBlocksContent", tags="1, 2")]
    pub get_blocks_content: ::core::option::Option<get_blocks_response::GetBlocksContent>,
}
/// Nested message and enum types in `GetBlocksResponse`.
pub mod get_blocks_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum GetBlocksContent {
        #[prost(message, tag="1")]
        Blocks(super::EncodedBlocks),
        #[prost(string, tag="2")]
        Error(::prost::alloc::string::String),
    }
}
/// Iterate through blocks
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IterBlocksRequest {
    #[prost(uint64, tag="1")]
    pub start: u64,
    #[prost(uint64, tag="2")]
    pub length: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IterBlocksResponse {
    #[prost(message, repeated, tag="1")]
    pub blocks: ::prost::alloc::vec::Vec<EncodedBlock>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchiveIndexEntry {
    #[prost(uint64, tag="1")]
    pub height_from: u64,
    #[prost(uint64, tag="2")]
    pub height_to: u64,
    #[prost(message, optional, tag="3")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchiveIndexResponse {
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<ArchiveIndexEntry>,
}
// ** ARCHIVE CANISTER ENDPOINTS **

/// * Archive canister *
/// Init the archive canister
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchiveInit {
    #[prost(uint32, tag="1")]
    pub node_max_memory_size_bytes: u32,
    #[prost(uint32, tag="2")]
    pub max_message_size_bytes: u32,
}
/// Add blocks to the archive canister
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchiveAddRequest {
    #[prost(message, repeated, tag="1")]
    pub blocks: ::prost::alloc::vec::Vec<Block>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArchiveAddResponse {
}
/// Fetch a list of all of the archive nodes
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNodesRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNodesResponse {
    #[prost(message, repeated, tag="1")]
    pub nodes: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// ** BASIC TYPES **
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tokens {
    #[prost(uint64, tag="1")]
    pub e8s: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Payment {
    #[prost(message, optional, tag="1")]
    pub receiver_gets: ::core::option::Option<Tokens>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeight {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
/// This is the
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(message, optional, tag="1")]
    pub parent_hash: ::core::option::Option<Hash>,
    #[prost(message, optional, tag="2")]
    pub timestamp: ::core::option::Option<TimeStamp>,
    #[prost(message, optional, tag="3")]
    pub transaction: ::core::option::Option<Transaction>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hash {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Account {
    #[prost(message, optional, tag="1")]
    pub identifier: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="2")]
    pub balance: ::core::option::Option<Tokens>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(message, optional, tag="4")]
    pub memo: ::core::option::Option<Memo>,
    /// obsolete
    #[prost(message, optional, tag="5")]
    pub created_at: ::core::option::Option<BlockHeight>,
    #[prost(message, optional, tag="6")]
    pub created_at_time: ::core::option::Option<TimeStamp>,
    #[prost(oneof="transaction::Transfer", tags="1, 2, 3")]
    pub transfer: ::core::option::Option<transaction::Transfer>,
}
/// Nested message and enum types in `Transaction`.
pub mod transaction {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transfer {
        #[prost(message, tag="1")]
        Burn(super::Burn),
        #[prost(message, tag="2")]
        Mint(super::Mint),
        #[prost(message, tag="3")]
        Send(super::Send),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Send {
    #[prost(message, optional, tag="1")]
    pub from: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="2")]
    pub to: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="3")]
    pub amount: ::core::option::Option<Tokens>,
    #[prost(message, optional, tag="4")]
    pub max_fee: ::core::option::Option<Tokens>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Mint {
    #[prost(message, optional, tag="2")]
    pub to: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="3")]
    pub amount: ::core::option::Option<Tokens>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Burn {
    #[prost(message, optional, tag="1")]
    pub from: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag="3")]
    pub amount: ::core::option::Option<Tokens>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountIdentifier {
    /// Can contain either:
    ///  * the 32 byte identifier (4 byte checksum + 28 byte hash)
    ///  * the 28 byte hash
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Subaccount {
    #[prost(bytes="vec", tag="1")]
    pub sub_account: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Memo {
    #[prost(uint64, tag="1")]
    pub memo: u64,
}
#[derive(Eq, PartialOrd, Ord, Hash, Copy, candid::CandidType, serde::Deserialize, serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeStamp {
    #[prost(uint64, tag="1")]
    pub timestamp_nanos: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Certification {
    #[prost(bytes="vec", tag="1")]
    pub certification: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferFeeRequest {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferFeeResponse {
    #[prost(message, optional, tag="1")]
    pub transfer_fee: ::core::option::Option<Tokens>,
}
