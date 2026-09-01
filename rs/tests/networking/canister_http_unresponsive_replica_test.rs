/* tag::catalog[]
Title:: Refunding the allowance of an unresponsive replica.

Goal:: Ensure that a replica which never reports what it spent on an HTTP outcall
has its whole per-replica allowance returned to the caller once the delivered
request context times out.

Runbook::
0. Instantiate a universal VM with a webserver (httpbin).
1. Instantiate an IC with the HTTP feature enabled on a 1-node system subnet and a
   4-node application subnet on a normal cost schedule.
2. Install NNS canisters.
3. Install the proxy canister.
4. Kill one application node, so that it can never report what it spent.
5. Make a pay-as-you-go outcall, which the three surviving nodes deliver.
6. Watch the proxy canister's balance across the delivered context's timeout.

Success::
1. While the delivered context is alive, the killed node's per-replica allowance
   stays withheld from the caller.
2. Once the context times out, the caller is credited exactly that allowance.

This lives in a suite of its own: the timeout is minutes long, and the assertions
watch the proxy canister's balance, which any concurrent outcall of its own would
perturb.

end::catalog[] */

use anyhow::{Result, bail};
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_https_outcalls_pricing::fees::max_usage_fee;
use ic_management_canister_types_private::{
    HttpMethod, PRICING_VERSION_PAY_AS_YOU_GO, TransformContext, TransformFunc,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, HasVm, READY_WAIT_TIMEOUT};
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::{retry_with_msg_async, systest};
use ic_types::{NumberOfNodes, canister_http::Replication};
use proxy_canister::{
    RejectionCode, RemoteHttpRequest, RemoteHttpResponse, UnvalidatedCanisterHttpRequestArgs,
};
use slog::{Logger, info};
use std::time::{Duration, Instant};

/// The cycles attached to the outcall. Far more than it could possibly spend, so
/// that the worst-case usage fee rather than the payment is what sizes the
/// per-replica allowances (asserted below).
const PAYMENT: u64 = 500_000_000_000;

/// What an idle canister pays per second on the 4-node subnet these tests use.
///
/// `CyclesAccountManagerConfig::application_subnet` charges 10_000 per second for
/// simply existing plus 317_500 per GiB of storage, and every fee there is quoted
/// for a 13-node reference subnet and scaled by `subnet_size /
/// reference_subnet_size`. That comes to a little over 3_000 per second for this
/// canister; rounding up to 5_000 covers its storage and leaves room to spare.
const IDLE_CYCLES_PER_SECOND: u128 = 5_000;

/// How often the proxy canister's balance is polled. The delivered context is kept
/// around for a couple of minutes, so the wait for the refund spans many polls.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What the proxy canister replies with for an outcall: the response, or the
/// rejection the management canister answered with.
type OutcallResult = Result<RemoteHttpResponse, (RejectionCode, String)>;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_test(systest!(test_unresponsive_replica_is_refunded_on_timeout))
        .execute_from_args()?;

    Ok(())
}

/// A replica that never reports its spend — here because it is dead — has its
/// whole per-replica allowance refunded once the delivered request context times
/// out, rather than the caller forfeiting it.
///
/// The three surviving nodes of a 4-node subnet are enough to agree on a
/// fully-replicated response, so they report their spend and are refunded the rest
/// of their allowances as soon as the response is delivered. The killed node's
/// allowance stays withheld until the context times out, which is what this test
/// waits for.
fn test_unresponsive_replica_is_refunded_on_timeout(env: TestEnv) {
    let logger = env.logger();
    let webserver_ipv6 = get_universal_vm_address(&env);

    let nodes: Vec<_> = get_paying_app_subnet_node_snapshots(&env).collect();
    let subnet_size = nodes.len();
    assert!(
        subnet_size >= 4,
        "a fully-replicated outcall needs to survive a killed node, which takes at \
         least 4 nodes, but the subnet has {subnet_size}"
    );
    let killed_node = &nodes[0];
    // The proxy canister belongs to the subnet rather than to any one node, so it
    // stays reachable through a node that stays up.
    let healthy_node = &nodes[1];

    // The allowance the killed node would forfeit if it were not refunded on
    // timeout. Every participating replica is granted
    // `min(payment - base_fee, max_usage_fee) / n`, and the payment dwarfs both the
    // base fee (on the order of 10^7 cycles here) and the worst-case usage fee, so
    // the latter is what binds.
    let max_usage_fee = max_usage_fee(
        &Replication::FullyReplicated,
        // Defaults to the largest response the outcall is allowed to return, which
        // makes the allowance large next to what this outcall actually spends.
        None,
        NumberOfNodes::from(subnet_size as u32),
    )
    .get();
    assert!(
        max_usage_fee * 4 < u128::from(PAYMENT),
        "the {PAYMENT}-cycle payment does not comfortably exceed the worst-case \
         usage fee of {max_usage_fee} cycles, so the payment — not the usage fee — \
         would size the allowances"
    );
    // `max_usage_fee` is rounded up to a multiple of the number of replicas, so
    // this division is exact.
    let allowance = max_usage_fee / subnet_size as u128;

    let runtime = get_runtime_from_node(healthy_node);
    let proxy = Canister::new(
        &runtime,
        CanisterId::unchecked_from_principal(get_proxy_canister_id(&env)),
    );

    info!(logger, "Killing one application node.");
    killed_node.vm().kill();
    killed_node
        .await_status_is_unavailable()
        .expect("the killed node did not become unavailable");

    block_on(async {
        let before = settled_balance(&proxy, &logger).await;
        info!(
            logger,
            "Node is down; making a pay-as-you-go outcall with a balance of {before} \
             and an allowance of {allowance} per replica."
        );

        let request = RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/ascii/unresponsive"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some(vec![]),
                // httpbin stamps a `Date` header, which differs between replicas;
                // dropping the headers is what lets the surviving ones agree on a
                // response.
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: proxy.canister_id().get().0,
                        method: "transform".to_string(),
                    }),
                    context: vec![],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: Some(PRICING_VERSION_PAY_AS_YOU_GO),
            },
            cycles: PAYMENT,
        };
        let response = proxy
            .update_(
                "send_request",
                candid_one::<OutcallResult, RemoteHttpRequest>,
                request,
            )
            .await
            .expect("calling the proxy canister failed")
            .expect("the outcall did not succeed with a node down");
        assert_eq!(
            response.status, 200,
            "unexpected response status: {response:?}"
        );

        // The three surviving replicas report their spend as part of delivering the
        // response and are refunded the rest of their allowances right away. The
        // killed one reported nothing, so its allowance is still withheld.
        let after_delivery = settled_balance(&proxy, &logger).await;
        let withheld = before
            .checked_sub(after_delivery)
            .unwrap_or_else(|| panic!("balance grew from {before} to {after_delivery}"));
        assert!(
            withheld >= allowance,
            "expected at least the killed replica's allowance of {allowance} cycles \
             to still be withheld after the response was delivered, but only \
             {withheld} cycles are"
        );

        info!(
            logger,
            "Response delivered with {withheld} cycles withheld; waiting for the \
             delivered context to time out."
        );
        let waiting_since = Instant::now();
        let after_timeout = retry_with_msg_async!(
            "the killed replica's allowance is refunded".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            POLL_INTERVAL,
            || async {
                let balance = cycle_balance(&proxy).await;
                // Strictly greater, not merely different: on a subnet that charges,
                // the canister pays for existing every round, so the balance moves
                // downward on its own. Only a refund adds to it.
                if balance <= after_delivery {
                    bail!("the balance has not risen above {after_delivery} yet");
                }
                Ok(balance)
            }
        )
        .await
        .expect("the killed replica's allowance was never refunded");

        let refunded = after_timeout
            .checked_sub(after_delivery)
            .unwrap_or_else(|| panic!("balance fell from {after_delivery} to {after_timeout}"));
        // Nothing but the refund credits the canister, so the balance cannot have
        // risen by more than the allowance.
        assert!(
            refunded <= allowance,
            "the balance rose by {refunded} cycles, more than the {allowance} allowance the \
             killed replica had to give back"
        );
        // It can have risen by a little less, though: the canister goes on paying to
        // exist for as long as we wait, and that cannot be observed separately from
        // the refund. Bounding it by the time actually waited keeps the check to a
        // fraction of a percent of the allowance.
        let idle = IDLE_CYCLES_PER_SECOND * waiting_since.elapsed().as_secs() as u128;
        assert!(
            refunded + idle >= allowance,
            "the balance rose by {refunded} cycles, short of the {allowance} allowance by more \
             than the {idle} the canister could have spent existing while we waited"
        );
        // What is left charged is the base fee plus what the outcall actually cost,
        // both far below a single allowance — which is what forfeiting the killed
        // replica's allowance would have added on top.
        let charged = before
            .checked_sub(after_timeout)
            .unwrap_or_else(|| panic!("balance grew from {before} to {after_timeout}"));
        assert!(
            charged < allowance,
            "the outcall kept {charged} cycles, as much as the whole per-replica \
             allowance of {allowance} that the killed replica was supposed to refund"
        );
        info!(
            logger,
            "The killed replica refunded its allowance of {allowance}; the outcall \
             cost {charged} cycles in total."
        );
    });
}

/// Reads the proxy canister's own cycle balance.
async fn cycle_balance(proxy: &Canister<'_>) -> u128 {
    proxy
        .query_("cycle_balance", candid_one::<u128, ()>, ())
        .await
        .expect("querying the proxy canister's balance failed")
}

/// Reads the proxy canister's balance once it has stopped moving.
///
/// The replicas that do report their spend are refunded a round or two after the
/// response itself is delivered, so a reading taken right away could still be
/// moving — and this test has to attribute a later change to the timeout alone.
async fn settled_balance(proxy: &Canister<'_>, logger: &Logger) -> u128 {
    retry_with_msg_async!(
        "the proxy canister's balance settles".to_string(),
        logger,
        READY_WAIT_TIMEOUT,
        POLL_INTERVAL,
        || async {
            let first = cycle_balance(proxy).await;
            tokio::time::sleep(POLL_INTERVAL).await;
            let second = cycle_balance(proxy).await;
            // Settled means nothing is owed any more, which is not the same as the
            // balance holding still: it drifts down as the canister pays for
            // existing. Refunds are the only thing that adds to it.
            if second > first {
                bail!("the balance is still being credited: {first} -> {second}");
            }
            Ok(second)
        }
    )
    .await
    .expect("the proxy canister kept being credited")
}
