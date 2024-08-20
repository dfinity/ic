#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes = "vec", tag = "1")]
    pub raw: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
/// A non-interactive distributed key generation (NI-DKG) ID.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgId {
    #[prost(uint64, tag = "1")]
    pub start_block_height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub dealer_subnet: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "NiDkgTag", tag = "4")]
    pub dkg_tag: i32,
    #[prost(message, optional, tag = "5")]
    pub remote_target_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NominalCycles {
    #[prost(uint64, tag = "1")]
    pub high: u64,
    #[prost(uint64, tag = "2")]
    pub low: u64,
}
/// A non-interactive distributed key generation (NI-DKG) tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NiDkgTag {
    Unspecified = 0,
    LowThreshold = 1,
    HighThreshold = 2,
}
impl NiDkgTag {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NiDkgTag::Unspecified => "NI_DKG_TAG_UNSPECIFIED",
            NiDkgTag::LowThreshold => "NI_DKG_TAG_LOW_THRESHOLD",
            NiDkgTag::HighThreshold => "NI_DKG_TAG_HIGH_THRESHOLD",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NI_DKG_TAG_UNSPECIFIED" => Some(Self::Unspecified),
            "NI_DKG_TAG_LOW_THRESHOLD" => Some(Self::LowThreshold),
            "NI_DKG_TAG_HIGH_THRESHOLD" => Some(Self::HighThreshold),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectCode {
    Unspecified = 0,
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}
impl RejectCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RejectCode::Unspecified => "REJECT_CODE_UNSPECIFIED",
            RejectCode::SysFatal => "REJECT_CODE_SYS_FATAL",
            RejectCode::SysTransient => "REJECT_CODE_SYS_TRANSIENT",
            RejectCode::DestinationInvalid => "REJECT_CODE_DESTINATION_INVALID",
            RejectCode::CanisterReject => "REJECT_CODE_CANISTER_REJECT",
            RejectCode::CanisterError => "REJECT_CODE_CANISTER_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "REJECT_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "REJECT_CODE_SYS_FATAL" => Some(Self::SysFatal),
            "REJECT_CODE_SYS_TRANSIENT" => Some(Self::SysTransient),
            "REJECT_CODE_DESTINATION_INVALID" => Some(Self::DestinationInvalid),
            "REJECT_CODE_CANISTER_REJECT" => Some(Self::CanisterReject),
            "REJECT_CODE_CANISTER_ERROR" => Some(Self::CanisterError),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterUpgradeOptions {
    #[prost(bool, optional, tag = "1")]
    pub skip_pre_upgrade: ::core::option::Option<bool>,
    #[prost(enumeration = "WasmMemoryPersistence", optional, tag = "2")]
    pub wasm_memory_persistence: ::core::option::Option<i32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterInstallModeV2 {
    #[prost(
        oneof = "canister_install_mode_v2::CanisterInstallModeV2",
        tags = "1, 2"
    )]
    pub canister_install_mode_v2:
        ::core::option::Option<canister_install_mode_v2::CanisterInstallModeV2>,
}
/// Nested message and enum types in `CanisterInstallModeV2`.
pub mod canister_install_mode_v2 {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterInstallModeV2 {
        #[prost(enumeration = "super::CanisterInstallMode", tag = "1")]
        Mode(i32),
        #[prost(message, tag = "2")]
        Mode2(super::CanisterUpgradeOptions),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CanisterInstallMode {
    Unspecified = 0,
    Install = 1,
    Reinstall = 2,
    Upgrade = 3,
}
impl CanisterInstallMode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CanisterInstallMode::Unspecified => "CANISTER_INSTALL_MODE_UNSPECIFIED",
            CanisterInstallMode::Install => "CANISTER_INSTALL_MODE_INSTALL",
            CanisterInstallMode::Reinstall => "CANISTER_INSTALL_MODE_REINSTALL",
            CanisterInstallMode::Upgrade => "CANISTER_INSTALL_MODE_UPGRADE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CANISTER_INSTALL_MODE_UNSPECIFIED" => Some(Self::Unspecified),
            "CANISTER_INSTALL_MODE_INSTALL" => Some(Self::Install),
            "CANISTER_INSTALL_MODE_REINSTALL" => Some(Self::Reinstall),
            "CANISTER_INSTALL_MODE_UPGRADE" => Some(Self::Upgrade),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum WasmMemoryPersistence {
    Unspecified = 0,
    Keep = 1,
    Replace = 2,
}
impl WasmMemoryPersistence {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            WasmMemoryPersistence::Unspecified => "WASM_MEMORY_PERSISTENCE_UNSPECIFIED",
            WasmMemoryPersistence::Keep => "WASM_MEMORY_PERSISTENCE_KEEP",
            WasmMemoryPersistence::Replace => "WASM_MEMORY_PERSISTENCE_REPLACE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "WASM_MEMORY_PERSISTENCE_UNSPECIFIED" => Some(Self::Unspecified),
            "WASM_MEMORY_PERSISTENCE_KEEP" => Some(Self::Keep),
            "WASM_MEMORY_PERSISTENCE_REPLACE" => Some(Self::Replace),
            _ => None,
        }
    }
}
