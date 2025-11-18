use crate::{
    pb::v1::RegistryCanisterStableStorage, registry::Registry,
    registry_lifecycle::canister_post_upgrade,
};

use canbench_rs::{BenchResult, bench, bench_fn, bench_scope};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_registry_routing_table::CANISTER_IDS_PER_SUBNET;
use prost::Message;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Currently there are 37 subnets. We will use 100 subnets for the benchmark.
const NUM_SUBNETS: u64 = 100;
const MAX_CANISTER_ID_U64: u64 = CANISTER_IDS_PER_SUBNET * NUM_SUBNETS;

fn setup_subnets(registry: &mut Registry) {
    for id in 0..NUM_SUBNETS {
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(id));
        let mutations = registry.add_subnet_to_routing_table(registry.latest_version(), subnet_id);
        registry.apply_mutations_for_test(mutations);
    }
}

fn migrate_canisters_to_subnets(registry: &mut Registry, num_migrations: u64, rng: &mut impl Rng) {
    assert!(
        num_migrations.is_multiple_of(NUM_SUBNETS),
        "Please choose a number of migrations that is divisible by the number of subnets"
    );
    let num_canisters_per_subnet = num_migrations / NUM_SUBNETS;

    for subnet_id in 0..NUM_SUBNETS {
        let canister_ids = (0..num_canisters_per_subnet)
            .map(|_| CanisterId::from_u64(rng.gen_range(0..MAX_CANISTER_ID_U64)))
            .collect::<Vec<_>>();

        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id));
        let migration_mutation = registry.migrate_canisters_to_subnet(
            registry.latest_version(),
            canister_ids,
            subnet_id,
        );
        registry.apply_mutations_for_test(migration_mutation);
    }
}

fn migrate_canisters(num_existing_migrations: u64, num_calls: u64) -> BenchResult {
    let mut registry = Registry::new();

    setup_subnets(&mut registry);
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    migrate_canisters_to_subnets(&mut registry, num_existing_migrations, &mut rng);

    bench_fn(|| {
        for _ in 0..num_calls {
            let canister_id = CanisterId::from_u64(rng.gen_range(0..MAX_CANISTER_ID_U64));
            let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(0));
            let migration_mutation = registry.migrate_canisters_to_subnet(
                registry.latest_version(),
                vec![canister_id],
                subnet_id,
            );
            registry.maybe_apply_mutation_internal(migration_mutation);
        }
    })
}

#[bench(raw)]
fn migrate_canisters_10_times_100() -> BenchResult {
    migrate_canisters(100, 10)
}

#[bench(raw)]
fn migrate_canisters_10_times_1k() -> BenchResult {
    migrate_canisters(1_000, 10)
}

#[bench(raw)]
fn migrate_canisters_10_times_10k() -> BenchResult {
    migrate_canisters(10_000, 10)
}

fn upgrade_with_routing_table(num_canisters: u64) -> BenchResult {
    let mut registry = Registry::new();

    setup_subnets(&mut registry);
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    migrate_canisters_to_subnets(&mut registry, num_canisters, &mut rng);

    bench_fn(|| {
        let bytes = {
            let _s1 = bench_scope("pre_upgrade");
            let registry_storage = RegistryCanisterStableStorage {
                registry: Some(registry.serializable_form()),
                pre_upgrade_version: Some(registry.latest_version()),
            };
            registry_storage.encode_to_vec()
        };

        {
            let _s2 = bench_scope("post_upgrade");
            let registry_storage = RegistryCanisterStableStorage::decode(bytes.as_slice())
                .expect("Error decoding from stable.");
            let mut new_registry = Registry::new();
            canister_post_upgrade(&mut new_registry, registry_storage);
            new_registry
        }
    })
}

#[bench(raw)]
fn upgrade_with_routing_table_100() -> BenchResult {
    upgrade_with_routing_table(100)
}

#[bench(raw)]
fn upgrade_with_routing_table_1k() -> BenchResult {
    upgrade_with_routing_table(1_000)
}

#[bench(raw)]
fn upgrade_with_routing_table_10k() -> BenchResult {
    upgrade_with_routing_table(10_000)
}

fn get_subnet_for_canister(num_canisters: u64, num_calls: u64) -> BenchResult {
    let mut registry = Registry::new();

    setup_subnets(&mut registry);
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    migrate_canisters_to_subnets(&mut registry, num_canisters, &mut rng);

    bench_fn(|| {
        for _ in 0..num_calls {
            let canister_id = CanisterId::from_u64(rng.gen_range(0..MAX_CANISTER_ID_U64));
            let _subnet_id = registry
                .get_subnet_for_canister(canister_id.get_ref())
                .unwrap();
        }
    })
}

#[bench(raw)]
fn get_subnet_for_canister_100_times_100() -> BenchResult {
    get_subnet_for_canister(100, 100)
}

#[bench(raw)]
fn get_subnet_for_canister_100_times_1k() -> BenchResult {
    get_subnet_for_canister(1_000, 100)
}

#[bench(raw)]
fn get_subnet_for_canister_100_times_10k() -> BenchResult {
    get_subnet_for_canister(10_000, 100)
}
