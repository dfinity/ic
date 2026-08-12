/* tag::catalog[]
Title:: Flexible HTTP outcalls where they are free.

Goal:: Exhaustively exercise the `flexible_http_request` management canister
endpoint on an application subnet with a free cost schedule, where HTTP outcalls
cost nothing.

The scenarios are shared with `canister_http_flexible_paying_test`, which runs
them against a subnet that charges for its outcalls: what a caller observes must
not depend on whether it was charged.

Runbook::
0. Instantiate a universal VM with a webserver (httpbin).
1. Instantiate an IC with the HTTP feature enabled on both a 4-node application
   subnet (free cost schedule) and the 1-node system subnet (free for outcalls
   despite a normal cost schedule).
2. Install NNS canisters.
3. Install a proxy canister on each of the two subnets.
4. Make flexible HTTP outcalls through the proxy canisters covering:
   - success across replication parameters and HTTP methods,
   - synchronous validation rejections,
   - runtime errors (too many rejects, responses too large),
   - adapter-level per-node failures,
   - an outcall on the system subnet,
   - fault tolerance: an outcall still succeeds with a subnet node killed.

Success::
1. Each scenario returns the expected `FlexibleHttpRequestResult` (or rejection).

end::catalog[] */

use anyhow::Result;

fn main() -> Result<()> {
    let group =
        canister_http_flexible::shared_scenarios(canister_http::setup_with_free_cost_schedule);
    canister_http_flexible::add_fault_tolerance(group).execute_from_args()?;

    Ok(())
}
