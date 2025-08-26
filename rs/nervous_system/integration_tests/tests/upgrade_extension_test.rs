use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_ledger_core::Tokens;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::Sns;
use ic_nervous_system_common::{E8, ONE_MONTH_SECONDS};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasms_to_sns_wasm, cycles_ledger, install_canister_with_controllers, load_registry_mutations, sns::governance::propose_and_wait, nns, sns, NnsInstaller,
    },
};
use ic_sns_cli::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use ic_sns_cli::register_extension;
use ic_sns_cli::register_extension::{RegisterExtensionArgs, RegisterExtensionInfo};
use ic_sns_governance_api::pb::v1::{
    proposal::Action, ExtensionUpgradeArg, PreciseValue, Proposal, UpgradeExtension, Wasm as ApiWasm,
};
use ic_sns_swap::pb::v1::Lifecycle;
use maplit::btreemap;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tempfile::TempDir;
use url::Url;

mod src {
    pub use ic_nns_governance_api::create_service_nervous_system::initial_token_distribution::{
        developer_distribution::NeuronDistribution, DeveloperDistribution, SwapDistribution,
        TreasuryDistribution,
    };
    pub use ic_nns_governance_api::create_service_nervous_system::InitialTokenDistribution;
}

// Copy from existing test
const ICP_FEE: u64 = 10_000;
const SNS_FEE: u64 = 100_000;

async fn deploy_sns(pocket_ic: &PocketIc, with_mainnet_sns_canisters: bool) -> Sns {
    use ic_nervous_system_proto::pb::v1::{self as pb};

    add_wasms_to_sns_wasm(pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
    create_service_nervous_system.initial_token_distribution =
        Some(src::InitialTokenDistribution {
            developer_distribution: Some(src::DeveloperDistribution {
                developer_neurons: vec![src::NeuronDistribution {
                    controller: Some(PrincipalId::new_user_test_id(830947)),
                    dissolve_delay: Some(pb::Duration {
                        seconds: Some(ONE_MONTH_SECONDS * 6),
                    }),
                    memo: Some(763535),
                    stake: Some(pb::Tokens { e8s: Some(756575) }),
                    vesting_period: Some(pb::Duration { seconds: Some(0) }),
                }],
            }),
            treasury_distribution: Some(src::TreasuryDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(400 * E8),
                }),
            }),
            swap_distribution: Some(src::SwapDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(1_840_880_000),
                }),
            }),
        });

    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();

    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    sns::swap::await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();
    sns::swap::smoke_test_participate_and_finalize(
        pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    sns
}

/// Helper function to create deposit allowances for treasury manager extension init
fn make_deposit_allowances(
    treasury_allocation_icp_e8s: u64,
    treasury_allocation_sns_e8s: u64,
) -> Option<PreciseValue> {
    Some(PreciseValue::Map(btreemap! {
        "treasury_allocation_icp_e8s".to_string() => PreciseValue::Nat(treasury_allocation_icp_e8s),
        "treasury_allocation_sns_e8s".to_string() => PreciseValue::Nat(treasury_allocation_sns_e8s),
    }))
}

#[tokio::test]
async fn test_upgrade_extension() {
    println!("🚀 Starting UpgradeExtension integration test...");
    
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();

    println!("🔧 Setting up NNS and SNS...");

    // Step 1: Install NNS
    {
        let registry_proto_path = state_dir.join("registry.proto");
        let initial_mutations = load_registry_mutations(registry_proto_path);

        let mut nns_installer = NnsInstaller::default();
        nns_installer
            .with_current_nns_canister_versions()
            .with_test_governance_canister()
            .with_cycles_minting_canister()
            .with_cycles_ledger()
            .with_custom_registry_mutations(vec![initial_mutations]);
        nns_installer.install(&pocket_ic).await;
    }

    // Step 2: Deploy SNS
    let sns = deploy_sns(&pocket_ic, false).await;
    let _sns_root_canister_id = CanisterId::try_from_principal_id(sns.root.canister_id).unwrap();
    let _sns_governance_canister_id =
        CanisterId::try_from_principal_id(sns.governance.canister_id).unwrap();

    println!("📦 Installing KongSwap v1 extension...");

    // Step 3: Create v1 KongSwap WASM
    let kong_backend_wasm_v1 = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");
        
        let wasm = Wasm::from_file(&wasm_path);
        
        // Print v1 hash for reference
        let v1_hash = Sha256::hash(&wasm.clone().bytes());
        println!("📊 KongSwap v1 WASM hash: [{}]", 
            v1_hash.iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", "));

        
        wasm
    };

    // Step 4: Install v1 extension canister
    let extension_canister_id = {
        let controllers = vec![PrincipalId::new_user_test_id(42)];
        
        // Use a deterministic canister ID for testing
        let canister_id = CanisterId::try_from_principal_id(
            PrincipalId::from_str("2ipq2-uqaaa-aaaar-qailq-cai").unwrap(),
        )
        .unwrap();

        install_canister_with_controllers(
            &pocket_ic,
            "KongSwap Backend Canister v1",
            canister_id,
            vec![],
            kong_backend_wasm_v1,
            controllers,
        )
        .await;

        canister_id
    };

    // Step 5: Get a neuron with voting power for proposals
    let (neuron_id, sender) = sns::governance::find_neuron_with_majority_voting_power(
        &pocket_ic,
        sns.governance.canister_id,
    )
    .await
    .unwrap();

    println!("📋 Registering extension with SNS governance...");

    // Step 6: Register the extension via RegisterExtension proposal
    {
        let agent = PocketIcAgent::new(&pocket_ic, sender);

        let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
            .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");
        let wasm_path = PathBuf::from(wasm_path);

        // Mint ICP and convert to cycles for the sender
        let icp = Tokens::from_tokens(10).unwrap();
        cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

        // Initial treasury allocations for the test
        let initial_treasury_allocation_icp_e8s = 100_000_000; // 1 ICP
        let initial_treasury_allocation_sns_e8s = 50_000_000;  // 0.5 SNS tokens

        let RegisterExtensionInfo {
            proposal_id,
            extension_canister_id: registered_canister_id,
            wasm_module_hash: _,
        } = register_extension::exec(
            RegisterExtensionArgs {
                sns_neuron_id: Some(ParsedSnsNeuron(neuron_id.clone())),
                sns_root_canister_id: CanisterId::try_from_principal_id(sns.root.canister_id).unwrap(),
                subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
                wasm_path,
                proposal_url: Url::try_from("https://example.com").unwrap(),
                summary: "Register KongSwap Treasury Manager Extension".to_string(),
                extension_init: make_deposit_allowances(
                    initial_treasury_allocation_icp_e8s,
                    initial_treasury_allocation_sns_e8s,
                ),
            },
            &agent,
        )
        .await
        .unwrap();

        println!("✅ Extension registered with proposal ID: {:?}", proposal_id);
        println!("📍 Registered canister ID: {:?}", registered_canister_id);

        // Verify the canister IDs match
        assert_eq!(extension_canister_id, registered_canister_id);
    }

    println!("🔄 Creating KongSwap v2 WASM (with modified metadata)...");

    // Step 7: Create v2 KongSwap WASM with modified metadata
    let kong_backend_wasm_v2 = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");
        
        let mut wasm_bytes = std::fs::read(&wasm_path).expect("Failed to read WASM file");
        
        // Modify the WASM slightly to create a different hash
        // Simple approach: append some bytes at the end
        let version_suffix = b"version=2.0.0-test";
        
        // Append the version suffix to the WASM
        wasm_bytes.extend_from_slice(version_suffix);
        
        let wasm = Wasm::from_bytes(wasm_bytes);
        
        // Print v2 hash for reference  
        let v2_hash = Sha256::hash(&wasm.clone().bytes());
        println!("📊 KongSwap v2 WASM hash: [{}]", 
            v2_hash.iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", "));

        
        wasm
    };

    println!("🗳️  Submitting UpgradeExtension proposal...");

    // Step 8: Create UpgradeExtension proposal

    let upgrade_extension_proposal = Proposal {
        title: "Upgrade KongSwap Extension to v2".to_string(),
        url: "https://example.com/upgrade-kongswap".to_string(),
        summary: "Upgrading KongSwap extension to version 2 with enhanced features".to_string(),
        action: Some(Action::UpgradeExtension(UpgradeExtension {
            extension_canister_id: Some(extension_canister_id.get()),
            canister_upgrade_arg: Some(ExtensionUpgradeArg {
                value: None, // Treasury manager currently has no upgrade args
            }),
            wasm: Some(ApiWasm::Bytes(kong_backend_wasm_v2.bytes())),
        })),
    };

    // Submit the proposal and wait for execution
    println!("⏳ Submitting proposal and waiting for execution...");
    
    let proposal_data = propose_and_wait(
        &pocket_ic,
        sns.governance.canister_id,
        sender,
        neuron_id,
        upgrade_extension_proposal,
    )
    .await
    .expect("Failed to propose UpgradeExtension");

    println!("✅ Proposal executed successfully!");
    println!("📋 Final proposal data: {:?}", proposal_data);

    // Step 9: Verify the upgrade worked
    println!("🔍 Verifying extension upgrade...");

    // Wait a bit for the upgrade to complete
    for _ in 0..10 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(1)).await;
    }

    // TODO: Add verification that the canister was actually upgraded
    // This would involve checking canister status, calling a method, etc.
    
    println!("🎉 UpgradeExtension integration test completed!");
    
    // Print the hashes again for easy copying
    println!("\n=== COPY THESE HASHES ===");
    println!("V1 hash: [{}]", 
        Sha256::hash(&std::fs::read(std::env::var("KONG_BACKEND_CANISTER_WASM_PATH").unwrap()).unwrap())
        .iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", "));
        
    let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH").unwrap();
    let mut v2_bytes = std::fs::read(&wasm_path).unwrap();
    let version_suffix = b"version=2.0.0-test";
    v2_bytes.extend_from_slice(version_suffix);
    
    println!("V2 hash: [{}]", 
        Sha256::hash(&v2_bytes).iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", "));
    println!("=========================");
}
