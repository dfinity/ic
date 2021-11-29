use ic_scenario_tests::api::e2e::testnet::*;
use ic_scenario_tests::runner::{passing_test_async, runner};
use ic_scenario_tests::tests::e2e::*;

#[derive(Default)]
struct Config {
    nns_url: Option<String>,
    nns_public_key: Option<String>,
    subnets: Option<u64>,
    runtime: Option<u64>,
    sleeptime: Option<u64>,
    rate: Option<u64>,
    payload_size: Option<u64>,
    num_canisters: Option<u64>,
    size_level: Option<u64>,
    random_seed: Option<u64>,
    targeted_latency: Option<u64>,
    principal_key_file: Option<String>,
    wallet_canisters: Option<Vec<String>>,
    cycles_per_subnet: Option<u64>,
    canisters_to_cleanup: Option<Vec<String>>,
    skip_cleanup: bool,
    all_to_one: bool,
}

pub fn main() {
    let mut config = Config::default();
    let mut args = std::env::args();
    // Skip binary name.
    let binary = args.next().unwrap_or_default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--nns_url" => config.nns_url = Some(args.next().expect("Missing NNS URL")),
            "--nns_public_key" => {
                config.nns_url = Some(args.next().expect("Missing NNS public key path"))
            }
            "--subnets" => {
                config.subnets = Some(
                    args.next()
                        .expect("Missing subnets value")
                        .parse()
                        .expect("Invalid subnets, expected u64 value"),
                )
            }
            "--runtime" => {
                config.runtime = Some(
                    args.next()
                        .expect("Missing runtime value")
                        .parse()
                        .expect("Invalid runtime, expected u64 value"),
                )
            }
            "--sleeptime" => {
                config.sleeptime = Some(
                    args.next()
                        .expect("Missing sleeptime value")
                        .parse()
                        .expect("Invalid sleeptime, expected u64 value"),
                )
            }
            "--rate" => {
                config.rate = Some(
                    args.next()
                        .expect("Missing rate value")
                        .parse()
                        .expect("Parse error"),
                )
            }
            "--payload_size" => {
                config.payload_size = Some(
                    args.next()
                        .expect("Missing payload_size value")
                        .parse()
                        .expect("Invalid payload_size, expected u64 value"),
                )
            }
            "--num_canisters" => {
                config.num_canisters = Some(
                    args.next()
                        .expect("Missing value for num_canisters")
                        .parse()
                        .expect("Invalid num_canisters, expected u64 value"),
                )
            }
            "--size_level" => {
                config.size_level = Some(
                    args.next()
                        .expect("Missing value for size_level")
                        .parse()
                        .expect("Invalid size_level, expected u64 value"),
                )
            }
            "--random_seed" => {
                config.random_seed = Some(
                    args.next()
                        .expect("Missing value for random_seed")
                        .parse()
                        .expect("Invalid size_level, expected u64 value"),
                )
            }
            "--targeted_latency" => {
                config.targeted_latency = Some(
                    args.next()
                        .expect("Missing value for targeted_latency")
                        .parse()
                        .expect("Invalid targeted_latency, expected u64 value"),
                )
            }
            "--principal_key" => {
                config.principal_key_file =
                    Some(args.next().expect("Missing value for principal_key"))
            }
            "--wallet_canisters" => {
                config.wallet_canisters = Some(
                    args.next()
                        .expect("Missing value for wallet_canisters")
                        .split(',')
                        .map(|s| s.into())
                        .collect(),
                )
            }
            "--cycles_per_subnet" => {
                config.cycles_per_subnet = Some(
                    args.next()
                        .expect("Missing value for cycles_per_subnet")
                        .parse()
                        .expect("Invalid cycles_per_subnet, expected u64 value"),
                )
            }
            "--canisters_to_cleanup" => {
                config.canisters_to_cleanup = Some(
                    args.next()
                        .expect("Missing value for canisters_to_cleanup")
                        .split(',')
                        .map(|s| s.into())
                        .collect(),
                )
            }
            "--skip_cleanup" => {
                config.skip_cleanup = true;
            }
            "--all_to_one" => {
                config.all_to_one = true;
            }
            // Remaining arguments will be passed to `runner()`.
            "--" => break,
            other => panic!("Unexpected command line flag: \"{}\"", other),
        }
    }

    let nns_public_key_path = config.nns_public_key.clone();
    let testnet = config
        .nns_url
        .as_ref()
        .map(|nns_url| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                load_testnet_topology(&registry_client(nns_url, nns_public_key_path))
                    .unwrap_or_else(|e| {
                        panic!("Failed to load testnet topology from {}: {}", nns_url, e)
                    })
            })
        })
        .expect("Missing required argument: nns_url");

    let flag = args.next().expect("Missing E2E test CLI flag");
    match flag.as_str() {
        "4.3" => {
            let testcase = move || {
                testcase_4_3_xnet_slo::e2e_test(
                    testnet,
                    config.subnets,
                    config.runtime,
                    config.rate,
                    config.payload_size,
                    config.targeted_latency,
                    config.principal_key_file,
                    config.wallet_canisters,
                    config.cycles_per_subnet,
                    config.canisters_to_cleanup,
                    config.skip_cleanup,
                    config.all_to_one,
                )
            };
            runner(
                vec![passing_test_async("Xnet Messaging 4.3", testcase)],
                std::iter::once(binary).chain(args).collect(),
            )
        }
        "5.2" => {
            let testcase = move || {
                testcase_5_2_does_not_stop::e2e_test(
                    testnet,
                    config.sleeptime,
                    config.num_canisters,
                    config.size_level,
                    config.random_seed,
                )
            };
            runner(
                vec![passing_test_async("Statesync 5.2", testcase)],
                std::iter::once(binary).chain(args).collect(),
            )
        }
        _ => panic!("Unknown E2E test {}", flag),
    }
}
