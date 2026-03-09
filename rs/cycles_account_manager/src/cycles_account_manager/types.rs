use ic_types::{CanisterId, Cycles};
use serde::{Deserialize, Serialize};

/// Errors returned by the [`CyclesAccountManager`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CyclesAccountManagerError {
    /// One of the API contracts that the cycles account manager enforces was
    /// violated.
    ContractViolation(String),
}

impl std::error::Error for CyclesAccountManagerError {}

impl std::fmt::Display for CyclesAccountManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CyclesAccountManagerError::ContractViolation(msg) => {
                write!(f, "Contract violation: {msg}")
            }
        }
    }
}

/// Measures how much a resource such as compute or storage is being used.
/// It will be used in resource reservation to scale reservation parameters
/// depending on the resource usage.
///
/// The default implementation corresponds to a no-op (empty) resource
/// saturation with `threshold = capacity = 0`.
///
/// This struct maintains an invariant that `usage <= capacity` and
/// `threshold <= capacity`.  There are no constraints between `usage` and
/// `threshold`.
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ResourceSaturation {
    usage: u64,
    threshold: u64,
    capacity: u64,
}

impl ResourceSaturation {
    /// Creates a new `ResourceSaturation` based on the given resource usages,
    /// threshold, and capacity. All arguments have the same unit that depends
    /// on the concrete resource:
    ///    - The unit of compute is percents.
    ///    - The unit of storage is bytes.
    ///
    /// See the comment of the `scale()` function for explanation of how the
    /// arguments are used.
    pub fn new(usage: u64, threshold: u64, capacity: u64) -> Self {
        let usage = usage.min(capacity);
        let threshold = threshold.min(capacity);
        Self {
            usage,
            threshold,
            capacity,
        }
    }

    /// Returns the part of the usage that is above the threshold.
    pub fn usage_above_threshold(&self) -> u64 {
        self.usage.saturating_sub(self.threshold)
    }

    /// Scales the given value proportionally to the resource saturation.
    /// More specifically, the value is scaled by `(U - T) / (C - T)`,
    /// where
    /// - `U` is the usage.
    /// - `T` is the threshold.
    /// - `C` is the capacity.
    ///
    /// The function returns `0` if `C == T`.
    ///
    /// Note that the invariant of this struct guarantees that `U <= C`,
    /// so the result of this function does not exceed the input value.
    pub fn reservation_factor(&self, value: u64) -> u64 {
        let capacity = self.capacity.saturating_sub(self.threshold);
        let usage = self.usage.saturating_sub(self.threshold);
        if capacity == 0 {
            0
        } else {
            let result = (value as u128 * usage as u128) / capacity as u128;
            // We know that the result fits in 64 bits because `value` fits in
            // 64 bits and `usage / capacity <= 1`.
            result.try_into().unwrap()
        }
    }

    /// Returns a new `ResourceSaturation` with the additional usage.
    pub fn add(&self, usage: u64) -> Self {
        Self {
            usage: (self.usage + usage).min(self.capacity),
            threshold: self.threshold,
            capacity: self.capacity,
        }
    }
}

/// Encapsulates the payer and cost of inducting an ingress messages.
#[derive(Eq, PartialEq, Debug)]
pub enum IngressInductionCost {
    /// Induction is free.
    Free,
    /// Induction cost and the canister to pay for it.
    Fee { payer: CanisterId, cost: Cycles },
}

impl IngressInductionCost {
    /// Returns the cost of inducting an ingress message in [`Cycles`].
    pub fn cost(&self) -> Cycles {
        match self {
            Self::Free => Cycles::zero(),
            Self::Fee { cost, .. } => *cost,
        }
    }
}
