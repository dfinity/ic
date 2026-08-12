/* tag::catalog[]
Title:: Test correctness of feature according to spec, under legacy pricing.

Goal:: Ensure simple HTTP requests can be made from canisters, with outcalls
priced by the legacy model that charges for the whole of `max_response_bytes`
up front.

The scenarios are shared with `canister_http_correctness_pay_as_you_go_test`,
which runs them under the pay-as-you-go model: what a caller observes must not
depend on how it was priced.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

use anyhow::Result;
use ic_management_canister_types_private::PRICING_VERSION_LEGACY;

fn main() -> Result<()> {
    let group = canister_http_correctness::shared_scenarios(PRICING_VERSION_LEGACY);
    canister_http_correctness::add_legacy_pricing_scenarios(group).execute_from_args()?;

    Ok(())
}
