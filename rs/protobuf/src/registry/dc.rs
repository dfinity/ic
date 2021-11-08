#[rustfmt::skip]
pub mod v1 {
    include!(std::concat!("../../gen/registry/registry.dc.v1.rs"));

    pub const MAX_DC_ID_LENGTH: usize = 255;
    pub const MAX_DC_REGION_LENGTH: usize = 255;
    pub const MAX_DC_OWNER_LENGTH: usize = 255;

    impl DataCenterRecord {
        pub fn validate(&self) -> Result<(), String> {
            if self.id.len() > MAX_DC_ID_LENGTH {
                Err(format!("id must not be longer than {} characters", MAX_DC_ID_LENGTH))
            } else if self.region.len() > MAX_DC_REGION_LENGTH {
                Err(format!("region must not be longer than {} characters", MAX_DC_REGION_LENGTH))
            } else if self.owner.len() > MAX_DC_OWNER_LENGTH {
                Err(format!("owner must not be longer than {} characters", MAX_DC_OWNER_LENGTH))
            } else {
                Ok(())
            }
        }
    }

    impl AddOrRemoveDataCentersProposalPayload {
        pub fn validate(&self) -> Result<(), String> {
            for dc in &self.data_centers_to_add {
                dc.validate()?;
            }

            Ok(())
        }
    }
}
