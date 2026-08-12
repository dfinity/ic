/* tag::catalog[]
Title:: Flexible HTTP outcalls where they are paid for.

Goal:: Exercise the `flexible_http_request` management canister endpoint on an
application subnet with a normal cost schedule, where outcalls are actually paid
for under pay-as-you-go.

This runs the same scenarios as `canister_http_flexible_test` — what a caller
observes must not depend on whether it was charged — plus the ones that only
exist because it was charged: refunds of the unspent per-replica allowance, and
outcalls whose payment cannot cover a response.

Runbook::
0. Instantiate a universal VM with a webserver (httpbin).
1. Instantiate an IC with the HTTP feature enabled on both a 4-node application
   subnet (normal cost schedule) and the 1-node system subnet.
2. Install NNS canisters.
3. Install a proxy canister on each of the two subnets.
4. Make flexible HTTP outcalls through the proxy canisters covering everything
   `canister_http_flexible_test` covers, and additionally:
   - the caller is charged what the outcall cost and refunded the rest,
   - an outcall paid too little to cover a response fails as out of cycles.

Success::
1. Each scenario returns the expected `FlexibleHttpRequestResult` (or rejection),
   and the caller's balance moves by the expected amount.

end::catalog[] */

use anyhow::Result;

fn main() -> Result<()> {
    let group =
        canister_http_flexible::shared_scenarios(canister_http::setup_with_paying_cost_schedule);
    // Pricing scenarios before fault tolerance, which leaves a node dead behind it.
    let group = canister_http_flexible::add_pricing_scenarios(group);
    canister_http_flexible::add_fault_tolerance(group).execute_from_args()?;

    Ok(())
}
