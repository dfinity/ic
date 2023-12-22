use crate::pb::v1::Canister;
use ic_base_types::PrincipalId;
use pb::v1::{Duration, GlobalTimeOfDay, Percentage, Tokens};

pub mod pb;

// Normally, we would import this from ic_nervous_system_common, but we'd be
// dragging in lots of stuff along with it. The main problem with that is that
// any random change that requires ic_nervous_system_common to be rebuilt will
// also trigger a rebuild here. This gives us a "fire wall" to prevent fires
// from spreading. Also, depending on ic_nervous_system_common would prevent
// ic_nervous_system_common from depending on us.
//
// TODO:(NNS1-2284) Move E8, and other such things to their own tiny library to avoid
// triggering mass rebuilds.
const E8: u64 = 100_000_000;

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

impl Duration {
    pub fn from_secs(seconds: u64) -> Duration {
        Duration {
            seconds: Some(seconds),
        }
    }
}

impl TryFrom<Duration> for std::time::Duration {
    type Error = String;
    fn try_from(d: Duration) -> Result<std::time::Duration, Self::Error> {
        let seconds = d.seconds.ok_or("seconds should not be blank")?;
        Ok(std::time::Duration::from_secs(seconds))
    }
}

impl From<std::time::Duration> for Duration {
    fn from(d: std::time::Duration) -> Duration {
        Duration {
            seconds: Some(d.as_secs()),
        }
    }
}

impl Tokens {
    pub fn from_tokens(tokens: u64) -> Tokens {
        Tokens {
            e8s: Some(tokens.saturating_mul(E8)),
        }
    }

    pub fn from_e8s(e8s: u64) -> Tokens {
        Tokens { e8s: Some(e8s) }
    }
}

impl Percentage {
    pub fn from_percentage(percentage: f64) -> Percentage {
        assert!(
            !percentage.is_sign_negative(),
            "percentage must be non-negative"
        );
        Percentage {
            basis_points: Some((percentage * 100.0).round() as u64),
        }
    }

    pub const fn from_basis_points(basis_points: u64) -> Percentage {
        Percentage {
            basis_points: Some(basis_points),
        }
    }
}

impl std::fmt::Display for Percentage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.basis_points {
            None => write!(f, "[unspecified]"),
            Some(basis_points) => write!(f, "{}.{:02}%", basis_points / 100, basis_points % 100),
        }
    }
}

impl Tokens {
    pub fn checked_add(&self, rhs: &Tokens) -> Option<Tokens> {
        let e8s = self.e8s?.checked_add(rhs.e8s?)?;
        Some(Tokens { e8s: Some(e8s) })
    }

    pub fn checked_sub(&self, rhs: &Tokens) -> Option<Tokens> {
        let e8s = self.e8s?.checked_sub(rhs.e8s?)?;
        Some(Tokens { e8s: Some(e8s) })
    }
}
