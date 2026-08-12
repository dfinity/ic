/* tag::catalog[]
Title:: Test correctness of feature according to spec, under pay-as-you-go pricing.

Goal:: Ensure simple HTTP requests can be made from canisters, with outcalls
priced by the pay-as-you-go model: only a base fee is charged up front, the rest
of the payment becomes a per-replica allowance, and what goes unspent is credited
back to the caller.

This runs the same scenarios as `canister_http_correctness_test` — what a caller
observes must not depend on how it was priced — plus the ones that only exist
under this model: the refund of the unspent allowance, and an outcall whose
payment cannot cover delivering a response.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200, and the caller's balance moves by the
   expected amount.

end::catalog[] */

use anyhow::Result;
use ic_management_canister_types_private::PRICING_VERSION_PAY_AS_YOU_GO;

fn main() -> Result<()> {
    let group = canister_http_correctness::shared_scenarios(PRICING_VERSION_PAY_AS_YOU_GO);
    canister_http_correctness::add_pay_as_you_go_pricing_scenarios(group).execute_from_args()?;

    Ok(())
}
