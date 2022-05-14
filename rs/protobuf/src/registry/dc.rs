#[rustfmt::skip]
#[allow(clippy::all)]
pub mod v1 {
    include!("../../gen/registry/registry.dc.v1.rs");
    use std::fmt;

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

    impl fmt::Display for DataCenterRecord {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let json = serde_json::to_string_pretty(&self)
                .unwrap_or_else(|e| format!("Error when serializing: {}", e));
            writeln!(f, "{}", json)
        }
    }

    impl fmt::Display for AddOrRemoveDataCentersProposalPayload {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let json = serde_json::to_string_pretty(&self)
                .unwrap_or_else(|e| format!("Error when serializing: {}", e));
            writeln!(f, "{}", json)
        }
    }
}
