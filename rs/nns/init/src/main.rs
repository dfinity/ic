use canister_test::{RemoteTestRuntime, Runtime};
use clap::Parser;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client::{Agent, HttpClientConfig, Sender};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_init::{make_hsm_sender, set_up_env_vars_for_all_canisters};
use ic_nns_test_utils::{
    common::{NnsInitPayloads, NnsInitPayloadsBuilder},
    itest_helpers::NnsCanisters,
};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Parser)]
#[clap(
    name = "ic-nns-init",
    about = "Install and initialize NNS canisters.",
    version
)]
struct CliArgs {
    #[clap(long)]
    url: Option<Url>,

    /// Path to a directory containing the .wasm file for each NNS
    /// canister.
    ///
    /// Optional: defaults to the current directory.
    #[clap(long)]
    wasm_dir: Option<PathBuf>,

    /// Path to a .csv file for initialising the `neurons` canister.
    ///
    /// Optional: defaults to creating canisters with test neurons.
    #[clap(long)]
    initial_neurons: Option<PathBuf>,

    /// Path to the file containing the initial registry required for NNS
    /// Bootstrap.
    ///
    /// The format is whatever ProtoRegistryDataProvider::load_from_file wants.
    /// No clue what it is, it's documented neither in ic-admin nor in
    /// ProtoRegistryDataProvider::load_from_file.
    ///
    /// This option is incompatible with --registry-local-store-dir !
    #[clap(long)]
    initial_registry: Option<PathBuf>,

    /// Path to a directory containing one file for each registry version to be
    /// inserted as initial content into the registry.
    ///
    /// This option is incompatible with --initial-registry !
    #[clap(long)]
    registry_local_store_dir: Option<PathBuf>,

    /// Use an HSM to sign calls.
    #[clap(long)]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        default_value = "0x0",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    hsm_slot: String,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        default_value = "",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    key_id: String,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        default_value = "",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    pin: String,

    /// If `true`, initialize the GTC and Governance canisters with Genesis
    /// neurons.
    #[clap(long)]
    initialize_with_gtc_neurons: bool,

    /// Create the ledger with existing accounts with 1_000_000_000 tokens in on
    /// behalf of these principals.
    #[clap(long, num_args(1..))]
    initialize_ledger_with_test_accounts_for_principals: Vec<PrincipalId>,

    /// Create the ledger with existing accounts with 1_000_000_000 tokens on
    /// the specified ledger accounts.
    #[clap(long, num_args(1..))]
    initialize_ledger_with_test_accounts: Vec<String>,

    /// The number of months over which a GTC Seed Round account will be
    /// released as neurons (one neuron each month).
    #[clap(long)]
    months_to_release_seed_round_gtc_neurons: Option<u8>,

    /// The number of months over which a GTC Early Contributor Tokenholder
    /// (ECT) account will be released as neurons (one neuron each month).
    #[clap(long)]
    months_to_release_ect_gtc_neurons: Option<u8>,

    /// The subnets to which SNS may be deployed
    #[clap(long, num_args(1..))]
    sns_subnet: Vec<PrincipalId>,

    /// Pass specified_id to provisional_create_canister_with_cycles when creating canisters.
    #[clap(long)]
    pass_specified_id: bool,

    /// If set, HTTP/2 is used for connections to the IC. By default, HTTP/1.1 is used.
    #[clap(long)]
    http2_only: bool,
}

const LOG_PREFIX: &str = "[ic-nns-init] ";

/// The ID of the Neuron that GTC account owners will have their funds donated
/// to when they call the GTC's `donate_account` method.
const GTC_DONATE_ACCOUNT_RECIPIENT_NEURON_ID: NeuronId = NeuronId { id: 29 };

/// The ID of the Neuron that the funds of all unclaimed GTC accounts will be
/// forwarded to when the `forward_all_unclaimed_accounts` GTC method is
/// called.
const GTC_FORWARD_ALL_UNCLAIMED_ACCOUNTS_RECIPIENT_NEURON_ID: NeuronId = NeuronId { id: 30 };

#[tokio::main]
async fn main() {
    let args = CliArgs::try_parse_from(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {e}"));

    let init_payloads = create_init_payloads(&args);

    let default_wasm_dir = PathBuf::from(".".to_string());
    set_up_env_vars_for_all_canisters(args.wasm_dir.as_ref().unwrap_or(&default_wasm_dir));

    let url = args.url.expect("Url must be provided to install canister.");

    let http_client_config = HttpClientConfig {
        http2_only: args.http2_only,
        ..HttpClientConfig::default()
    };
    let agent = if args.use_hsm {
        let sender = make_hsm_sender(&args.hsm_slot, &args.key_id, &args.pin);
        Agent::new_with_http_client_config(url.clone(), sender, http_client_config)
    } else {
        // Use the special identity that has superpowers, like calling
        // ic00::Method::ProvisionalCreateCanisterWithCycles.
        Agent::new_with_http_client_config(
            url.clone(),
            Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
            http_client_config,
        )
    };

    // Don't let the "Test" distract you -- the RemoteTestRuntime is simply a
    // client-side view of a subnet.
    let runtime = Runtime::Remote(RemoteTestRuntime {
        agent,
        effective_canister_id: REGISTRY_CANISTER_ID.into(),
    });
    match args.pass_specified_id {
        true => NnsCanisters::set_up_at_ids(&runtime, init_payloads).await,
        false => NnsCanisters::set_up(&runtime, init_payloads).await,
    };
    eprintln!("{LOG_PREFIX}All NNS canisters have been set up on the replica with {url}");
}

/// Constructs the `NnsInitPayloads` from the command line options.
fn create_init_payloads(args: &CliArgs) -> NnsInitPayloads {
    let mut init_payloads_builder = NnsInitPayloadsBuilder::new();

    add_registry_content(
        &mut init_payloads_builder,
        args.initial_registry.as_ref(),
        args.registry_local_store_dir.as_ref(),
    );

    if let Some(path) = &args.initial_neurons {
        eprintln!("{LOG_PREFIX}Initializing neurons from CSV file: {path:?}");
        init_payloads_builder.with_neurons_from_csv_file(path);
    } else {
        eprintln!(
            "{LOG_PREFIX}Initial neuron CSV or PB path not specified, initializing with test neurons"
        );
        init_payloads_builder
            // We need some neurons, because we need to vote on some proposals to create subnets.
            .with_test_neurons();
    }

    let mut test_ledger_accounts = vec![];

    for principal in &args.initialize_ledger_with_test_accounts_for_principals {
        test_ledger_accounts.push(icp_ledger::AccountIdentifier::new(*principal, None));
    }
    for account_hex in &args.initialize_ledger_with_test_accounts {
        test_ledger_accounts.push(
            icp_ledger::AccountIdentifier::from_hex(account_hex)
                .expect("failed to parse ledger account identifier"),
        );
    }

    for account in test_ledger_accounts.into_iter() {
        init_payloads_builder
            .ledger
            .init_args()
            .unwrap()
            .initial_values
            .insert(
                account,
                icp_ledger::Tokens::from_tokens(1_000_000_000).expect("Couldn't create icpts"),
            );
        eprintln!(
            "{}Initializing with test ledger account: {}",
            LOG_PREFIX,
            account.to_hex(),
        );
    }

    if args.initialize_with_gtc_neurons {
        init_payloads_builder.genesis_token.sr_months_to_release =
            args.months_to_release_seed_round_gtc_neurons;
        init_payloads_builder.genesis_token.ect_months_to_release =
            args.months_to_release_ect_gtc_neurons;

        init_payloads_builder.with_gtc_neurons();
    }

    init_payloads_builder
        .genesis_token
        .donate_account_recipient_neuron_id = Some(GTC_DONATE_ACCOUNT_RECIPIENT_NEURON_ID);

    init_payloads_builder
        .genesis_token
        .forward_whitelisted_unclaimed_accounts_recipient_neuron_id =
        Some(GTC_FORWARD_ALL_UNCLAIMED_ACCOUNTS_RECIPIENT_NEURON_ID);

    init_payloads_builder.sns_wasms.with_sns_subnet_ids(
        args.sns_subnet
            .iter()
            .cloned()
            .map(SubnetId::from)
            .collect(),
    );

    println!("{LOG_PREFIX}Initialized governance.");

    init_payloads_builder.build()
}

fn add_registry_content(
    init_payloads_builder: &mut NnsInitPayloadsBuilder,
    ic_prep_path: Option<&PathBuf>,
    registry_local_store_dir: Option<&PathBuf>,
) {
    let mutate_reqs = match (ic_prep_path, registry_local_store_dir) {
        (Some(_), Some(_)) => panic!(
            "{LOG_PREFIX} --initial-registry and --registry-local-store-dir are incompatible, gotta make up your mind!"
        ),
        (None, None) => vec![],
        (Some(p), None) => ic_nns_init::read_initial_mutations_from_ic_prep(p),
        (None, Some(d)) => ic_nns_init::read_initial_mutations_from_local_store_dir(d),
    };
    if mutate_reqs.is_empty() {
        eprintln!(
            "{LOG_PREFIX}The content of the registry will be initialized with an empty content. \
        This is most likely not what you want. \
        Use --initial-registry or --registry-local-store-dir to specify initial content."
        );
    } else {
        eprintln!(
            "{}The registry will be initialized with {} transactions for a total of {} key-value pair mutations.",
            LOG_PREFIX,
            mutate_reqs.len(),
            mutate_reqs
                .iter()
                .map(|mr| mr.mutations.len())
                .sum::<usize>()
        );
    }
    for mutate_req in mutate_reqs {
        init_payloads_builder
            .registry
            .push_init_mutate_request(mutate_req);
    }
}
