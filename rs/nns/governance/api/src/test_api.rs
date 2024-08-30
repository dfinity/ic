/// Affects the perception of time by users of CanisterEnv (i.e. Governance).
///
/// Specifically, the time that Governance sees is the real time + delta.
#[derive(PartialEq, Eq, Clone, Copy, Debug, candid::CandidType, serde::Deserialize)]
pub struct TimeWarp {
    pub delta_s: i64,
}
