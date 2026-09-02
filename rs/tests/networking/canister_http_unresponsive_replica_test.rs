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

This lives in a suite of its own: waiting out the timeout takes a minute of wall
clock on its own, and the assertions watch the proxy canister's balance, which any
concurrent outcall of its own would perturb.

end::catalog[] */

use anyhow::{Result, bail};
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_management_canister_types_private::{
    HttpMethod, PRICING_VERSION_PAY_AS_YOU_GO, TransformContext, TransformFunc,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasVm, IcNodeSnapshot, READY_WAIT_TIMEOUT,
};
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::{retry_with_msg_async, systest};
use proxy_canister::{
    RemoteHttpRequest, ResponseWithRefundedCycles, UnvalidatedCanisterHttpRequestArgs,
};
use slog::info;
use std::time::{Duration, Instant};

/// The cycles attached to the outcall. Far more than it could possibly spend, so
/// that the worst-case usage fee rather than the payment is what sizes the
/// per-replica allowances (asserted below).
const PAYMENT: u64 = 500_000_000_000;

/// How often the proxy canister's balance is polled. The delivered context is kept
/// around for a minute, so the wait for the refund spans many polls.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long to wait for the replicas that did report their spend to be refunded.
/// They are refunded a round or two after the response is delivered, so this only
/// has to outlast a hiccup — and it has to stay well inside the delivered
/// context's own 60-second timeout, which is what the test measures afterwards.
const SURVIVOR_REFUND_TIMEOUT: Duration = Duration::from_secs(20);

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

    let runtime = get_runtime_from_node(healthy_node);
    let proxy_id = get_proxy_canister_id(&env);
    let proxy = Canister::new(&runtime, CanisterId::unchecked_from_principal(proxy_id));

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]/ascii/unresponsive"),
        headers: vec![],
        method: HttpMethod::GET,
        body: Some(vec![]),
        // httpbin stamps a `Date` header, which differs between replicas; dropping
        // the headers is what lets the surviving ones agree on a response.
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: proxy_id.into(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: Some(PRICING_VERSION_PAY_AS_YOU_GO),
    };

    // The allowance the killed node would forfeit if it were not refunded on timeout.
    let fees = fees_for(
        CanisterId::unchecked_from_principal(proxy_id),
        request.clone(),
        subnet_size,
    );
    let payment = u128::from(PAYMENT);
    assert!(fees.payment_is_ample(payment),);
    let allowance = fees.allowance(payment);

    info!(logger, "Killing one application node.");
    killed_node.vm().kill();
    killed_node
        .await_status_is_unavailable()
        .expect("the killed node did not become unavailable");

    block_on(async {
        let before_consumed = read_consumed(healthy_node, proxy_id).await;
        let before = balance(healthy_node, proxy_id).await;
        info!(
            logger,
            "Node is down; making a pay-as-you-go outcall with a balance of {before} \
             and an allowance of {allowance} per replica."
        );

        let started = Instant::now();
        let ResponseWithRefundedCycles {
            result,
            refunded_cycles,
        } = proxy
            .update_(
                "send_request_with_refund_callback",
                candid_one::<ResponseWithRefundedCycles, RemoteHttpRequest>,
                RemoteHttpRequest {
                    request,
                    cycles: PAYMENT,
                },
            )
            .await
            .expect("calling the proxy canister failed");
        // Bounds the round trip the surviving replicas were charged for: it happened
        // strictly inside this call.
        let elapsed = started.elapsed();
        let response = result.expect("the outcall did not succeed with a node down");
        assert_eq!(
            response.status, 200,
            "unexpected response status: {response:?}"
        );
        // Everything the payment covered beyond the base fee and the allowances comes
        // straight back on the reply, whether or not a replica later reports what it
        // spent. Exact, since it turns on no measurement.
        if let Err(wrong) = fees.check_reply_refund(payment, u128::from(refunded_cycles)) {
            panic!("an outcall with a replica down {wrong}");
        }

        // The three surviving replicas report their spend on delivery and are
        // refunded the rest of their allowances a round or two later, leaving exactly
        // one — the killed replica's — withheld. That is the state the timeout acts
        // on, so wait for it before reading the balance the refund is measured
        // against.
        let after_delivery = retry_with_msg_async!(
            "the replicas that reported their spend are refunded".to_string(),
            &logger,
            SURVIVOR_REFUND_TIMEOUT,
            POLL_INTERVAL,
            || async {
                let consumed = read_consumed(healthy_node, proxy_id).await;
                let balance = balance(healthy_node, proxy_id).await;
                let withheld = before
                    .checked_sub(balance)
                    .unwrap_or_else(|| panic!("balance grew from {before} to {balance}"));
                // Two allowances sits halfway between the four withheld while those
                // refunds are outstanding and the one left once they have landed,
                // so it tells the two apart with a whole allowance of margin either
                // side of the threshold.
                if withheld >= 2 * allowance {
                    bail!(
                        "{withheld} cycles are still withheld, so the replicas that \
                         reported their spend have not been refunded yet"
                    );
                }
                Ok((consumed, balance))
            }
        )
        .await
        .expect("the replicas that reported their spend were never refunded");
        let (consumed_at_delivery, after_delivery) = after_delivery;
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
        let after_timeout = retry_with_msg_async!(
            "the killed replica's allowance is refunded".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            POLL_INTERVAL,
            || async {
                let balance = balance(healthy_node, proxy_id).await;
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
        // It rises by a little less: the canister keeps paying to exist while this
        // waits, and the balance nets that against the refund. No slack factor is
        // needed — the reads are ordered so the counters' window contains the
        // balance's, so every cycle lost to existing is inside `while_waiting`.
        let at_timeout = read_consumed(healthy_node, proxy_id).await;
        let while_waiting = at_timeout.since(&consumed_at_delivery).total();
        assert!(
            allowance <= refunded + while_waiting,
            "the balance rose by {refunded} cycles, short of the {allowance} allowance by \
             more than the {while_waiting} the canister was charged for existing while we \
             waited"
        );
        // And what stays charged is what the outcall cost.
        let charged = before
            .checked_sub(after_timeout)
            .unwrap_or_else(|| panic!("balance grew from {before} to {after_timeout}"));
        let consumed = at_timeout.since(&before_consumed);
        if let Err(wrong) = fees.check_charge(&consumed, charged, elapsed) {
            panic!("an outcall with a replica down {wrong}");
        }
        info!(
            logger,
            "The killed replica refunded its allowance of {allowance}; the outcall \
             cost {charged} cycles in total."
        );
    });
}

/// Reads the proxy canister's balance, treating a failed query as fatal: this test
/// has no outer retry to absorb one.
async fn balance(node: &IcNodeSnapshot, canister: PrincipalId) -> u128 {
    cycle_balance(node, canister)
        .await
        .unwrap_or_else(|err| panic!("{err}"))
}

/// The same for the per-use-case breakdown.
async fn read_consumed(node: &IcNodeSnapshot, canister: PrincipalId) -> ConsumedCycles {
    consumed_cycles(node, canister)
        .await
        .unwrap_or_else(|err| panic!("{err}"))
}
