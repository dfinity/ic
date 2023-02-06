use ic_base_types::PrincipalId;

pub(crate) struct TvlState {
    pub governance_principal: PrincipalId,
    pub xrc_principal: PrincipalId,
    pub update_period: u64,
}
