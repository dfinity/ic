#[rustfmt::skip]
pub mod v1 {
    include!(std::concat!("../../gen/registry/registry.dc.v1.rs"));
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
            writeln!(f, "DataCenterRecord:")?;
            writeln!(f, "\tid: {}", &self.id)?;
            writeln!(f, "\tregion: {}", &self.region)?;
            writeln!(f, "\towner: {}", &self.owner)?;

            let (latitude, longitude) = &self.gps
                .as_ref()
                .map(|gps| (gps.latitude.to_string(), gps.longitude.to_string(),))
                .unwrap_or_else(|| ("Not specified".to_string(), "Not specified".to_string()));

            writeln!(f, "\tgps.latitude: {}", latitude)?;
            writeln!(f, "\tgps.longitude: {}", longitude)
        }
    }

    /// Used to display and validate input to the ic-admin command
    /// to submit a `AddOrRemoveDataCentersProposalPayload`
    ///
    /// Example output:
    /// ```text
    /// AddOrRemoveDataCentersProposalPayload {
    /// Data Centers to add:
    ///     DataCenterRecord:
    ///     id: AN1
    ///     region: us-west
    ///     owner: DC Corp
    ///     gps.latitude: 37.77493
    ///     gps.longitude: -122.41942
    ///
    ///     DataCenterRecord:
    ///     id: BC1
    ///     region: ca-west
    ///     owner: BC Corp
    ///     gps.latitude: 38.77493
    ///     gps.longitude: -125.41942
    ///
    /// Data Centers to remove:
    ///     FM1, IT1,
    /// }
    /// ```
    impl fmt::Display for AddOrRemoveDataCentersProposalPayload {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "AddOrRemoveDataCentersProposalPayload {{")?;
            writeln!(f, "Data Centers to add:")?;
            for dc in &self.data_centers_to_add {
                writeln!(f, "\t{}", dc)?;
            }
            write!(f, "Data Centers to remove:\n\t")?;
            for dc_id in &self.data_centers_to_remove {
                write!(f, "{}, ", dc_id)?;
            }
            writeln!(f, "\n}}")
        }
    }
}
