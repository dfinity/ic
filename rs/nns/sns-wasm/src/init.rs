use ic_base_types::SubnetId;

#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct SnsWasmCanisterInitPayload {
    pub sns_subnet_ids: Vec<SubnetId>,
}

pub struct SnsWasmCanisterInitPayloadBuilder {
    payload: SnsWasmCanisterInitPayload,
}

#[allow(clippy::new_without_default)]
impl SnsWasmCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        SnsWasmCanisterInitPayloadBuilder {
            payload: SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![],
            },
        }
    }

    pub fn with_sns_subnet_ids(&mut self, subnet_ids: Vec<SubnetId>) {
        self.payload.sns_subnet_ids = subnet_ids;
    }

    pub fn build(self) -> SnsWasmCanisterInitPayload {
        self.payload
    }
}
