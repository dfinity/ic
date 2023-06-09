use crate::pb::v1::Canister;
use ic_base_types::PrincipalId;
use pb::v1::GlobalTimeOfDay;

pub mod pb;

impl GlobalTimeOfDay {
    pub fn from_hh_mm(hh: u64, mm: u64) -> Result<Self, String> {
        if hh >= 23 || mm >= 60 {
            return Err(format!("invalid time of day ({}:{})", hh, mm));
        }
        let seconds_after_utc_midnight = Some(hh * 3600 + mm * 60);
        Ok(Self {
            seconds_after_utc_midnight,
        })
    }

    pub fn to_hh_mm(&self) -> Option<(u64, u64)> {
        let hh = self.seconds_after_utc_midnight? / 3600;
        let mm = (self.seconds_after_utc_midnight? % 3600) / 60;
        Some((hh, mm))
    }
}

impl Canister {
    pub fn new(principal_id: PrincipalId) -> Self {
        Self {
            id: Some(principal_id),
        }
    }
}
