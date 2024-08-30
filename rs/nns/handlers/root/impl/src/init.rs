#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
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
