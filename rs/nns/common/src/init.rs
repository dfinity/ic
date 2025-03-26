#[derive(Clone, Debug, candid::CandidType, candid::Deserialize)]
pub struct LifelineCanisterInitPayload {}

pub struct LifelineCanisterInitPayloadBuilder {}

#[allow(clippy::new_without_default)]
impl LifelineCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        LifelineCanisterInitPayloadBuilder {}
    }

    pub fn build(&self) -> LifelineCanisterInitPayload {
        LifelineCanisterInitPayload {}
    }
}
