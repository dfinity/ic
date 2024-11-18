#[derive(Clone, Debug, candid::CandidType, candid::Deserialize)]
pub struct RootCanisterInitPayload {}

pub struct RootCanisterInitPayloadBuilder {}

#[allow(clippy::new_without_default)]
impl RootCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        RootCanisterInitPayloadBuilder {}
    }

    pub fn build(&self) -> RootCanisterInitPayload {
        RootCanisterInitPayload {}
    }
}
