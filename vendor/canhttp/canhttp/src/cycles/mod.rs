//! Middleware to handle cycles accounting.
//!
//! Issuing HTTPs outcalls requires cycles, and this layer takes care of the following:
//! 1. Calculate the number of cycles required.
//! 2. Decide how the canister should charge for those cycles.
//! 3. Do the actual charging.
//!
//! # Examples
//!
//! To let the canister pay for HTTPs outcalls with its own cycle:
//! ```rust
//! use canhttp::{cycles::{ChargeMyself, CyclesAccountingServiceBuilder}, Client};
//! use tower::{Service, ServiceBuilder, ServiceExt, BoxError};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!   .cycles_accounting(ChargeMyself::default())
//!   .service(Client::new_with_box_error());
//!
//! let _ = service.ready().await.unwrap();
//!
//! # Ok(())
//! # }
//! ```
//!
//! To charge the caller of the canister for the whole cost of the HTTPs outcall with an additional fixed fee of 1M cycles:
//! ```rust
//! use canhttp::{cycles::{ChargeCaller, CyclesAccountingServiceBuilder}, Client};
//! use tower::{Service, ServiceBuilder, ServiceExt, BoxError};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!   .cycles_accounting(ChargeCaller::new(|_request, cost| cost + 1_000_000))
//!   .service(Client::new_with_box_error());
//!
//! let _ = service.ready().await.unwrap();
//!
//! # Ok(())
//! # }
//! ```

use crate::{
    convert::{ConvertRequestLayer, Filter},
    ConvertServiceBuilder,
};
use ic_cdk::management_canister::HttpRequestArgs;
use std::convert::Infallible;
use thiserror::Error;
use tower::ServiceBuilder;
use tower_layer::Stack;

/// Charge cycles to pay for a single HTTPs outcall.
pub trait CyclesChargingPolicy {
    /// Type returned in case of a charging error.
    type Error;

    /// Return the number of cycles that would be charged for the given request
    fn cycles_to_charge(&self, request: &HttpRequestArgs, request_cycles_cost: u128) -> u128;

    /// Charge cycles and return the charged amount.
    fn charge_cycles(
        &self,
        request: &HttpRequestArgs,
        request_cycles_cost: u128,
    ) -> Result<u128, Self::Error>;
}

/// The canister using that policy will pay for HTTPs outcalls with its own cycles.
#[derive(Default, Clone)]
pub struct ChargeMyself {}

impl CyclesChargingPolicy for ChargeMyself {
    type Error = Infallible;

    fn cycles_to_charge(&self, _request: &HttpRequestArgs, _request_cycles_cost: u128) -> u128 {
        0
    }

    fn charge_cycles(
        &self,
        _request: &HttpRequestArgs,
        _request_cycles_cost: u128,
    ) -> Result<u128, Self::Error> {
        // no-op,
        Ok(0)
    }
}

/// Cycles will be transferred from the caller of the canister using that library to pay for HTTPs outcalls.
#[derive(Clone)]
pub struct ChargeCaller<F> {
    cycles_to_charge: F,
}

impl<F> ChargeCaller<F>
where
    F: Fn(&HttpRequestArgs, u128) -> u128,
{
    /// Create a new instance of [`ChargeCaller`].
    pub fn new(cycles_to_charge: F) -> Self {
        ChargeCaller { cycles_to_charge }
    }
}

impl<F> CyclesChargingPolicy for ChargeCaller<F>
where
    F: Fn(&HttpRequestArgs, u128) -> u128,
{
    type Error = ChargeCallerError;

    fn cycles_to_charge(&self, request: &HttpRequestArgs, request_cycles_cost: u128) -> u128 {
        (self.cycles_to_charge)(request, request_cycles_cost)
    }

    fn charge_cycles(
        &self,
        request: &HttpRequestArgs,
        request_cycles_cost: u128,
    ) -> Result<u128, Self::Error> {
        let cycles_to_charge = self.cycles_to_charge(request, request_cycles_cost);
        if cycles_to_charge > 0 {
            let cycles_available = ic_cdk::api::msg_cycles_available();
            if cycles_available < cycles_to_charge {
                return Err(ChargeCallerError::InsufficientCyclesError {
                    expected: cycles_to_charge,
                    received: cycles_available,
                });
            }
            let cycles_received = ic_cdk::api::msg_cycles_accept(cycles_to_charge);
            assert_eq!(
                cycles_received, cycles_to_charge,
                "Expected to receive {cycles_to_charge}, but got {cycles_received}"
            );
        }
        Ok(cycles_to_charge)
    }
}

/// Error returned by the [`CyclesAccounting`] middleware.
#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum ChargeCallerError {
    /// Error returned when the caller should be charged but did not attach sufficiently many cycles.
    #[error("insufficient cycles (expected {expected:?}, received {received:?})")]
    InsufficientCyclesError {
        /// Expected amount of cycles. Minimum value that should have been sent.
        expected: u128,
        /// Received amount of cycles
        received: u128,
    },
}

/// A middleware to handle cycles accounting, i.e. verify if sufficiently many cycles are available in a request.
/// The cost of sending the request is calculated by [`ic_cdk::api::cost_http_request`].
#[derive(Clone, Debug)]
pub struct CyclesAccounting<ChargingPolicy> {
    charging_policy: ChargingPolicy,
}

impl<ChargingPolicy> CyclesAccounting<ChargingPolicy> {
    /// Create a new middleware given the charging policy.
    pub fn new(charging_policy: ChargingPolicy) -> Self {
        Self { charging_policy }
    }
}

impl<ChargingPolicy> Filter<HttpRequestArgs> for CyclesAccounting<ChargingPolicy>
where
    ChargingPolicy: CyclesChargingPolicy,
{
    type Error = ChargingPolicy::Error;

    fn filter(&mut self, request: HttpRequestArgs) -> Result<HttpRequestArgs, Self::Error> {
        let cycles_to_attach = ic_cdk::management_canister::cost_http_request(&request);
        self.charging_policy
            .charge_cycles(&request, cycles_to_attach)?;
        Ok(request)
    }
}

/// Extension trait that adds methods to [`tower::ServiceBuilder`] for adding middleware
/// related to cycles accounting
pub trait CyclesAccountingServiceBuilder<L> {
    /// Add cycles accounting.
    ///
    /// See the [module docs](crate::cycles) for examples.
    fn cycles_accounting<C>(
        self,
        charging: C,
    ) -> ServiceBuilder<Stack<ConvertRequestLayer<CyclesAccounting<C>>, L>>;
}

impl<L> CyclesAccountingServiceBuilder<L> for ServiceBuilder<L> {
    fn cycles_accounting<C>(
        self,
        charging: C,
    ) -> ServiceBuilder<Stack<ConvertRequestLayer<CyclesAccounting<C>>, L>> {
        self.convert_request(CyclesAccounting::new(charging))
    }
}
