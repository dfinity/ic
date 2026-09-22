/// The reason why an upgrade payload was determined to be invalid.
#[derive(Debug, Eq, PartialEq)]
pub enum InvalidUpgradePayloadReason {
    /// Failed to decode the upgrade payload from protobuf.
    DecodeFailed(String),
}
