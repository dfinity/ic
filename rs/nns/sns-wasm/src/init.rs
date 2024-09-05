use ic_base_types::{PrincipalId, SubnetId};

#[derive(Clone, Debug, candid::CandidType, candid::Deserialize)]
pub struct SnsWasmCanisterInitPayload {
    pub sns_subnet_ids: Vec<SubnetId>,
    pub access_controls_enabled: bool,
    pub allowed_principals: Vec<PrincipalId>,
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
                access_controls_enabled: false,
                allowed_principals: vec![],
            },
        }
    }

    pub fn with_sns_subnet_ids(&mut self, subnet_ids: Vec<SubnetId>) -> &mut Self {
        self.payload.sns_subnet_ids = subnet_ids;
        self
    }

    pub fn with_allowed_principals(&mut self, allowed_principals: Vec<PrincipalId>) -> &mut Self {
        self.payload.allowed_principals = allowed_principals;
        self
    }

    pub fn with_access_controls_enabled(&mut self, access_controls_enabled: bool) -> &mut Self {
        self.payload.access_controls_enabled = access_controls_enabled;
        self
    }

    pub fn build(&mut self) -> SnsWasmCanisterInitPayload {
        self.payload.clone()
    }
}
