use crate::api::handle::Ic;
use crate::tests::{cleanup, locate_canisters, parallel_async};
use candid::{CandidType, Deserialize};
use canister_test::*;
use dfn_candid::candid;
use ic_base_types::SubnetId;
use std::{collections::BTreeMap, fmt::Display};
use std::{str::FromStr, time::Duration};
use xnet_test::{Metrics, NetworkTopology};

/// For how long to run the test after canisters have been installed and
/// `start()` was called. Not a `Duration` as we use it for computing how many
/// messages we expect to have gotten responses.
const DEFAULT_TEST_DURATION_SECONDS: u64 = 60;

const DEFAULT_RATE: u64 = 10;
const DEFAULT_PAYLOAD_SIZE: u64 = 1024;

/// Maximum messages a canister should send every round (in order to prevent it
/// filling up its output queue). This should be estimated as:
///
/// `queue_capacity / 10 /* max_rounds roundtrip */`
const MAX_CANISTER_TO_CANISTER_RATE: usize = 30;

const DEFAULT_TARGETED_LATENCY_SECONDS: u64 = 20;

/// Testcase 4.3 implementation: installs `xnet-test-canister` onto the first
/// `subnets` subnets of `ic`; calls `start()` on each; sleeps for `runtime`;
/// calls `stop()` on each; and finally retrieves and validates the metrics
/// collected by each canister.
///
/// Optionally a collection of `wallet_canisters` can be provided, one per
/// subnet, to serve as an alternative way of creating canisters if
/// `ProvisionalCreateCanisterWithCycles` is not available on the testnet.
#[allow(clippy::too_many_arguments)]
pub async fn test_impl(
    ic: &dyn Ic,
    subnets: Option<u64>,
    runtime: Option<u64>,
    rate: Option<u64>,
    payload_size_bytes: Option<u64>,
    targeted_latency_seconds: Option<u64>,
    wallet_canisters: Option<Vec<String>>,
    cycles_per_subnet: Option<u64>,
    skip_cleanup: bool,
    all_to_one: bool,
) {
    if let Some(subnets) = subnets {
        assert!(
            subnets >= 2 ,
            "At least 2 subnets are required to test XNet messaging. Test was invoked with `--subnets {}`",
            subnets
        );
    }
    if let Some(runtime) = runtime {
        assert!(
            runtime > 10,
            "Test runtime must be more than 10 seconds. Test was invoked with `--runtime {}`",
            runtime
        );
    }
    if let Some(rate) = rate {
        assert!(
            rate > 0,
            "Message rate must be non-zero. Test was invoked with `--rate {}`",
            rate
        );
    }
    if let Some(wallet_canisters) = wallet_canisters.as_ref() {
        let subnets = subnets.unwrap_or_else(|| ic.subnet_ids().len() as u64);
        assert!(
            wallet_canisters.len() >= subnets as usize,
            "One wallet canister is required for each of {} subnets",
            subnets
        );
    }
    if wallet_canisters.is_none() && cycles_per_subnet.is_some() {
        println!("Warning: cycles_per_subnet will be ignored when not specifying wallet_canisters");
    }

    // (Build and) load the xnet-test canister.
    let wasm = load_canister_bin("xnet_test", "xnet-test-canister");

    // Map subnets to wallet canisters (if provided) and retain those subnets with
    // wallet canisters only.
    let wallet_canisters =
        wallet_canisters.map(|canisters| subnets_to_wallet_canisters(canisters, ic));
    let subnet_ids = wallet_canisters
        .as_ref()
        .map(|wallet_canisters| wallet_canisters.keys().copied().collect())
        .unwrap_or_else(|| ic.subnet_ids());
    let wallet_canisters = wallet_canisters.unwrap_or_default();
    assert!(
        subnet_ids.len() >= 2,
        "At least 2 subnets are required to test XNet messaging. Provided topology has {} subnets.",
        subnet_ids.len()
    );
    let subnets = subnets.map(|s| s as usize).unwrap_or(subnet_ids.len());

    // Nodes 0 on each subnet and the corresponding wallet canisters (if any).
    let node_apis: Vec<_> = subnet_ids
        .into_iter()
        .map(|id| {
            (
                ic.subnet(id).node_by_idx(0).api(),
                wallet_canisters.get(&id),
            )
        })
        .take(subnets)
        .collect();
    let subnets = node_apis.len();

    let rate = rate.unwrap_or(DEFAULT_RATE);
    // Subnet-to-subnet request rate: ceil(rate / (subnets -1)).
    let subnet_to_subnet_rate = (rate as usize - 1) / (subnets - 1) + 1;
    // Minimum number of subnet-to-subnet queues needed to stay under
    // `MAX_CANISTER_TO_CANISTER_RATE`.
    let subnet_to_subnet_queues = (subnet_to_subnet_rate - 1) / MAX_CANISTER_TO_CANISTER_RATE + 1;
    // Minimum number of canisters required to send `subnet_to_subnet_rate` requests
    // per round.
    let canisters_per_subnet = (subnet_to_subnet_queues as f64).sqrt().ceil() as usize;
    // A canister's outbound request rate to a given subnet.
    let canister_to_subnet_rate = (subnet_to_subnet_rate - 1) / canisters_per_subnet + 1;

    let cycles_per_canister = cycles_per_subnet
        .map(|cycles| cycles / canisters_per_subnet as u64)
        .unwrap_or(std::u64::MAX);
    let payload_size_bytes = payload_size_bytes.unwrap_or(DEFAULT_PAYLOAD_SIZE);
    let targeted_latency_seconds =
        targeted_latency_seconds.unwrap_or(DEFAULT_TARGETED_LATENCY_SECONDS);

    // Install `canisters_per_subnet` canisters on every subnet.
    println!(
        "👉 Installing {} xnet-test-canister instance(s) onto each of {} subnets",
        canisters_per_subnet, subnets
    );
    let canisters: Vec<_> = parallel_async(
        node_apis
            .iter()
            .cycle()
            .take(canisters_per_subnet * subnets),
        |(api, wallet_canister)| {
            install(
                wasm.clone(),
                api,
                wallet_canister.copied(),
                cycles_per_canister,
                ic.get_principal(),
            )
        },
        |i, res| {
            res.unwrap_or_else(|err| {
                panic!(
                    "Failed to install canister onto subnet {}: {}",
                    i % subnets,
                    err
                )
            })
        },
    )
    .await;

    // Call `start()` on all canisters to get them chatting to one another.
    println!(
        "👉 Starting chatter: {} messages/round * {} bytes = {} bytes/round",
        canister_to_subnet_rate * canisters_per_subnet * (subnets - 1),
        payload_size_bytes,
        canister_to_subnet_rate
            * canisters_per_subnet
            * (subnets - 1)
            * payload_size_bytes as usize
    );
    let mut topology: NetworkTopology = vec![Vec::with_capacity(canisters_per_subnet); subnets];

    if all_to_one {
        topology
            .get_mut(0)
            .unwrap()
            .push(canisters[0].canister_id_vec8());
    } else {
        canisters.iter().enumerate().for_each(|(i, canister)| {
            topology
                .get_mut(i % subnets)
                .unwrap()
                .push(canister.canister_id_vec8())
        });
    }
    let _: Vec<String> = parallel_async(
        &canisters,
        |canister| {
            canister.update_(
                "start",
                candid,
                (
                    topology.clone(),
                    canister_to_subnet_rate as u64,
                    payload_size_bytes,
                ),
            )
        },
        |i, res| {
            res.unwrap_or_else(|e| {
                panic!("Calling start() on subnet {} failed: {}", i % subnets, e)
            })
        },
    )
    .await;

    // Let them run for a while.
    let runtime = runtime.unwrap_or(DEFAULT_TEST_DURATION_SECONDS);
    println!("👉 Sleeping for {} seconds", runtime);
    let delay = Duration::from_secs(runtime);
    std::thread::sleep(delay);

    // Stop the chatter (as a way of ensuring that subnets are still responsive).
    println!("👉 Stopping chatter");
    stop_chatters(&canisters, |error| {
        panic!("Calling stop() on canister failed: {}", error)
    })
    .await;

    // Retrieve collected metrics.
    println!("👉 Collecting metrics");
    let metrics: Vec<Metrics> = parallel_async(
        &canisters,
        |canister| canister.query_("metrics", candid, ()),
        |i, res| {
            res.unwrap_or_else(|e| {
                panic!("Querying metrics() on subnet {} failed: {}", i % subnets, e)
            })
        },
    )
    .await;

    if !skip_cleanup {
        println!("👉 Cleaning up");
        cleanup(locate_canisters(&canisters, &wallet_canisters, ic)).await;
    }

    let mut aggregated_metrics: Vec<Metrics> = Vec::with_capacity(subnets);
    for _ in 0..subnets {
        aggregated_metrics.push(Metrics::default());
    }
    for (i, m) in metrics.iter().enumerate() {
        println!(
            "👉 Metrics for subnet {}, canister {}: {:?}",
            i % subnets,
            i / subnets,
            m
        );
        aggregated_metrics.get_mut(i % subnets).unwrap().merge(m);
    }

    let mut success = true;
    let mut expect =
        |cond: bool, subnet: usize, ok_msg: &str, fail_msg: &str, val: &dyn Display| {
            success &= cond;
            println!(
                "Subnet {}: {} {}: {} {}",
                subnet,
                if cond { "✅" } else { "❌" },
                if cond { ok_msg } else { fail_msg },
                val,
                if cond { "🎉🎉🎉" } else { "😭😭😭" }
            );
        };

    for (i, m) in aggregated_metrics.iter().enumerate() {
        let attempted_calls = m.requests_sent + m.call_errors;
        if attempted_calls != 0 {
            let failed_calls = m.call_errors + m.reject_responses;
            let error_ratio = 100. * failed_calls as f64 / attempted_calls as f64;
            expect(
                error_ratio < 5.,
                i,
                "Error ratio below 5%",
                "Failed calls",
                &format!("{}% ({}/{})", error_ratio, failed_calls, attempted_calls),
            );
        }

        expect(
            m.seq_errors == 0,
            i,
            "Sequence errors",
            "Sequence errors",
            &m.seq_errors,
        );

        let send_rate = attempted_calls as f64
            / (subnets - 1) as f64
            / runtime as f64
            / canisters_per_subnet as f64
            / canister_to_subnet_rate as f64;
        expect(
            send_rate >= 0.3,
            i,
            "Send rate at least 0.3",
            "Send rate below 0.3",
            &send_rate,
        );

        // Successful plus reject responses.
        let responses_received =
            m.latency_distribution.buckets().last().unwrap().1 + m.reject_responses;
        // All messages sent more than `targeted_latency_seconds` before the end of the
        // test should have gotten a response.
        let responses_expected = (m.requests_sent as f64
            * (runtime - targeted_latency_seconds) as f64
            / runtime as f64) as usize;
        // Account for requests enqueued this round (in case canister messages were
        // executed before ingress messages, i.e. the heartbeat was executed before
        // metrics collection) or uncounted responses (if ingress executed first).
        let responses_expected = responses_expected - subnet_to_subnet_rate;
        let actual = format!("{}/{}", responses_received, m.requests_sent);
        let msg = format!(
            "Expected requests sent more than {}s ago ({}/{}) to receive responses",
            targeted_latency_seconds, responses_expected, m.requests_sent
        );
        expect(
            responses_received >= responses_expected,
            i,
            &msg,
            &msg,
            &actual,
        );

        if responses_received != 0 {
            let avg_latency_millis = m.latency_distribution.sum_millis() / responses_received;
            expect(
                avg_latency_millis <= targeted_latency_seconds as usize * 1000,
                i,
                &format!(
                    "Mean response latency less than {}s",
                    targeted_latency_seconds
                ),
                &format!(
                    "Mean response latency was more than {}s",
                    targeted_latency_seconds
                ),
                &(avg_latency_millis as f64 * 1e-3),
            );
        }
    }

    assert!(success, "Test failed.");
}

/// (Builds and) loads the given canister binary from the given package within
/// the given `rust_canisters` subdirectory.
pub fn load_canister_bin(dir: &str, bin: &str) -> Wasm {
    println!("👉 Building {} canister binary", bin);
    let cargo_manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rust_canisters")
        .join(dir);

    Project { cargo_manifest_dir }.cargo_bin(bin, &[])
}

pub async fn stop_chatters(canisters: &[Canister<'_>], on_error: fn(&str) -> ()) {
    let _: Vec<()> = parallel_async(
        canisters,
        |canister| canister.update_("stop", candid, ()),
        |_, res| res.map(|_: String| ()).unwrap_or_else(|e| on_error(&e)),
    )
    .await;
}

/// Creates a map of subnets to wallet canisters, ensuring that every provided
/// canister maps to unique subnet.
fn subnets_to_wallet_canisters(
    wallet_canisters: Vec<String>,
    ic: &dyn Ic,
) -> BTreeMap<SubnetId, CanisterId> {
    let wallet_canister_count = wallet_canisters.len();
    let subnet_wallet_canisters = wallet_canisters
        .into_iter()
        .map(|s| CanisterId::new(PrincipalId::from_str(&s).unwrap()).unwrap())
        .map(|c| (ic.route(c.get()).unwrap(), c))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(wallet_canister_count, subnet_wallet_canisters.len());
    subnet_wallet_canisters
}

/// Creates a canister on the given `Runtime` (via a wallet canister if
/// provided; else using `ProvisionalCreateCanisterWithCycles` as a whitelisted
/// principal) and installs the provided Wasm.
async fn install(
    wasm: Wasm,
    api: &Runtime,
    wallet_canister_id: Option<CanisterId>,
    cycles: u64,
    principal: Option<PrincipalId>,
) -> Result<Canister<'_>, String> {
    if let Some(wallet_canister_id) = wallet_canister_id {
        #[derive(CandidType, Clone, Deserialize)]
        struct CanisterSettings {
            controller: Option<PrincipalId>,
            compute_allocation: Option<candid::Nat>,
            memory_allocation: Option<candid::Nat>,
            freezing_threshold: Option<candid::Nat>,
        }

        #[derive(CandidType, Deserialize)]
        struct CreateCanisterArgs {
            cycles: u64,
            settings: CanisterSettings,
        }
        #[derive(CandidType, Deserialize)]
        struct CreateResult {
            canister_id: PrincipalId,
        }

        // Create canister via wallet canister.
        let wallet_canister = Canister::new(api, wallet_canister_id);
        let res: Result<CreateResult, String> = wallet_canister
            .update_(
                "wallet_create_canister",
                candid,
                (CreateCanisterArgs {
                    cycles,
                    settings: CanisterSettings {
                        controller: principal,
                        compute_allocation: None,
                        memory_allocation: None,
                        freezing_threshold: None,
                    },
                },),
            )
            .await?;

        // Install the Wasm.
        let canister_id = CanisterId::new(res?.canister_id).map_err(|e| e.to_string())?;
        let mut canister = Canister::new(api, canister_id);
        wasm.install_onto_canister(&mut canister, None).await?;

        Ok(canister)
    } else {
        // Create and install canister via whitelisted principal.
        wasm.install_(api, vec![]).await
    }
}
