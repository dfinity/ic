/// The reason why an upgrade payload was determined to be invalid.
#[derive(Debug, Eq, PartialEq)]
pub enum InvalidUpgradePayloadReason {
    NonEmpty,
}
