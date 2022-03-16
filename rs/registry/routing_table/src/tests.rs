use super::*;
use assert_matches::assert_matches;
use ic_test_utilities::types::ids::subnet_test_id;

fn new_canister_id_ranges(ranges: Vec<(u64, u64)>) -> CanisterIdRanges {
    let ranges = ranges
        .into_iter()
        .map(|(start, end)| CanisterIdRange {
            start: CanisterId::from(start),
            end: CanisterId::from(end),
        })
        .collect();
    CanisterIdRanges(ranges)
}

fn new_routing_table(ranges: Vec<((u64, u64), u64)>) -> RoutingTable {
    let mut map = BTreeMap::new();
    for ((start, end), subnet_id) in ranges {
        let range = CanisterIdRange {
            start: CanisterId::from(start),
            end: CanisterId::from(end),
        };
        map.insert(range, subnet_test_id(subnet_id));
    }
    RoutingTable(map)
}

fn new_canister_migrations(migrations: Vec<((u64, u64), Vec<u64>)>) -> CanisterMigrations {
    let mut map = BTreeMap::new();
    for ((start, end), subnet_ids) in migrations {
        let range = CanisterIdRange {
            start: CanisterId::from(start),
            end: CanisterId::from(end),
        };
        map.insert(range, subnet_ids.into_iter().map(subnet_test_id).collect());
    }
    CanisterMigrations(map)
}

#[test]
fn invalid_canister_id_ranges() {
    let ranges = CanisterIdRanges(vec![CanisterIdRange {
        start: CanisterId::from(1),
        end: CanisterId::from(0),
    }]);
    assert_matches!(
        ranges.well_formed(),
        Err(WellFormedError::CanisterIdRangeEmptyRange(_))
    );

    let ranges = CanisterIdRanges(vec![
        CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(0xff),
        },
        CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(0xff),
        },
    ]);
    assert_matches!(
        ranges.well_formed(),
        Err(WellFormedError::CanisterIdRangeNotSortedOrNotDisjoint(_))
    );
}

#[test]
fn invalid_routing_table() {
    // Empty range.
    let rt = new_routing_table([((0x1000, 0x1ff), 0)].to_vec());
    assert_matches!(
        rt.well_formed(),
        Err(WellFormedError::RoutingTableEmptyRange(_))
    );

    // Overlapping ranges.
    let rt = new_routing_table([((0, 0x100ff), 123), ((0x10000, 0x200ff), 7)].to_vec());
    assert_matches!(
        rt.well_formed(),
        Err(WellFormedError::RoutingTableNotDisjoint(_))
    );
}

#[test]
fn valid_routing_table() {
    // Valid example
    let rt = new_routing_table(
        [
            ((0x100, 0x100ff), 1),
            ((0x20000, 0x2ffff), 2),
            ((0x50000, 0x50fff), 1),
            ((0x80000, 0x8ffff), 8),
            ((0x90000, 0xfffff), 9),
            ((0x1000000000000000, 0xffffffffffffffff), 0xf),
        ]
        .to_vec(),
    );

    assert_eq!(rt.well_formed(), Ok(()));

    assert!(rt.route(CanisterId::from(0).get()) == None);
    assert!(rt.route(CanisterId::from(0x99).get()) == None);
    assert!(rt.route(CanisterId::from(0x100).get()) == Some(subnet_test_id(1)));
    assert!(rt.route(CanisterId::from(0x10000).get()) == Some(subnet_test_id(1)));
    assert!(rt.route(CanisterId::from(0x100ff).get()) == Some(subnet_test_id(1)));
    assert!(rt.route(CanisterId::from(0x10100).get()) == None);
    assert!(rt.route(CanisterId::from(0x20500).get()) == Some(subnet_test_id(2)));
    assert!(rt.route(CanisterId::from(0x50050).get()) == Some(subnet_test_id(1)));
    assert!(rt.route(CanisterId::from(0x100000).get()) == None);
    assert!(rt.route(CanisterId::from(0x80500).get()) == Some(subnet_test_id(8)));
    assert!(rt.route(CanisterId::from(0x8ffff).get()) == Some(subnet_test_id(8)));
    assert!(rt.route(CanisterId::from(0x90000).get()) == Some(subnet_test_id(9)));
    assert!(rt.route(CanisterId::from(0xffffffffffffffff).get()) == Some(subnet_test_id(0xf)));

    assert_eq!(rt.ranges(subnet_test_id(1)).well_formed(), Ok(()));
    assert!(
        rt.ranges(subnet_test_id(1)).0
            == new_canister_id_ranges(vec![(0x100, 0x100ff), (0x50000, 0x50fff)]).0
    );
}

#[test]
fn route_when_principal_corresponds_to_subnet() {
    // Valid routing table
    let rt = new_routing_table(
        [
            ((0x100, 0x100ff), 1),
            ((0x20000, 0x2ffff), 2),
            ((0x50000, 0x50fff), 1),
            ((0x80000, 0x8ffff), 8),
            ((0x90000, 0xfffff), 9),
            ((0x1000000000000000, 0xffffffffffffffff), 0xf),
        ]
        .to_vec(),
    );

    assert_eq!(rt.well_formed(), Ok(()));

    // Existing subnets.
    let subnet_id1 = subnet_test_id(1);
    let subnet_id8 = subnet_test_id(8);

    // Non existing subnets
    let subnet_id5 = subnet_test_id(5);
    let subnet_id12 = subnet_test_id(12);

    assert_eq!(rt.route(subnet_id1.get()), Some(subnet_id1));
    assert_eq!(rt.route(subnet_id8.get()), Some(subnet_id8));
    assert_eq!(rt.route(subnet_id5.get()), None);
    assert_eq!(rt.route(subnet_id12.get()), None);
}

#[test]
fn can_insert_valid_route() {
    let mut rt = new_routing_table(vec![((1, 1000), 1)]);
    assert_eq!(rt.well_formed(), Ok(()));
    assert_eq!(
        rt.insert(
            CanisterIdRange {
                start: CanisterId::from(1001u64),
                end: CanisterId::from(2000u64)
            },
            subnet_test_id(2)
        ),
        Ok(())
    );
    assert_eq!(rt.well_formed(), Ok(()));
    assert_eq!(
        rt.route(CanisterId::from(1001u64).get()),
        Some(subnet_test_id(2))
    );
}

#[test]
fn cannot_insert_invalid_route() {
    let mut rt = new_routing_table(vec![((1, 1000), 1)]);
    assert_eq!(rt.well_formed(), Ok(()));
    assert_matches!(
        rt.insert(
            CanisterIdRange {
                start: CanisterId::from(100u64),
                end: CanisterId::from(2000u64)
            },
            subnet_test_id(2)
        ),
        Err(WellFormedError::RoutingTableNotDisjoint(_))
    );
    assert_eq!(
        rt.route(CanisterId::from(101u64).get()),
        Some(subnet_test_id(1))
    );
    assert_eq!(rt.well_formed(), Ok(()));
}

#[test]
fn can_remove_subnet() {
    let mut rt = new_routing_table(vec![((1, 1000), 1), ((2000, 3000), 2)]);
    assert_eq!(rt.well_formed(), Ok(()));
    assert_eq!(
        rt.route(CanisterId::from(100u64).get()),
        Some(subnet_test_id(1))
    );
    rt.remove_subnet(subnet_test_id(1));
    assert_eq!(rt.well_formed(), Ok(()));
    assert_eq!(rt.route(CanisterId::from(100u64).get()), None);
}

#[test]
fn can_reassign_range() {
    let rt = new_routing_table(vec![
        ((0, 5), 1),
        ((6, 10), 2),
        ((21, 25), 3),
        ((30, 30), 4),
    ]);
    let dst = subnet_test_id(10);
    for start in 0..=30u64 {
        for end in start..=30u64 {
            let mut rt_copy = rt.clone();

            rt_copy.assign_range(
                CanisterIdRange {
                    start: CanisterId::from(start),
                    end: CanisterId::from(end),
                },
                dst,
            );

            for i in 0u64..start {
                assert_eq!(
                    rt.route(CanisterId::from(i).into()),
                    rt_copy.route(CanisterId::from(i).into())
                );
            }
            for i in start..=end {
                assert_eq!(rt_copy.route(CanisterId::from(i).into()), Some(dst));
            }
            for i in (end + 1)..=30u64 {
                assert_eq!(
                    rt.route(CanisterId::from(i).into()),
                    rt_copy.route(CanisterId::from(i).into())
                );
            }
        }
    }
}

#[test]
fn can_optimize_routing_table() {
    let rt = new_routing_table(vec![
        ((0, 5), 1),
        ((6, 10), 1),
        ((11, 20), 2),
        ((21, 25), 1),
        ((26, 27), 1),
        ((30, 30), 1),
    ]);
    let rt_optimized = {
        let mut rt = rt.clone();
        rt.optimize();
        rt
    };
    assert_eq!(rt.ranges(subnet_test_id(1)).0.len(), 5);
    assert_eq!(rt_optimized.ranges(subnet_test_id(1)).0.len(), 3);
    for i in 0..=30 {
        assert_eq!(
            rt_optimized.route(CanisterId::from(i).into()),
            rt.route(CanisterId::from(i).into())
        );
    }
}

#[test]
fn canister_migrations_empty_range() {
    let cm = new_canister_migrations(vec![((0x1000, 0x1ff), vec![0, 1])]);
    assert_matches!(
        cm.well_formed(),
        Err(WellFormedError::CanisterMigrationsEmptyRange(_))
    );
}

#[test]
fn canister_migrations_overlapping_ranges() {
    let cm = new_canister_migrations(vec![
        ((0, 0x100ff), vec![0, 1]),
        ((0x10000, 0x200ff), vec![0, 1]),
    ]);
    assert_matches!(
        cm.well_formed(),
        Err(WellFormedError::CanisterMigrationsNotDisjoint(_))
    );
}

#[test]
fn canister_migrations_single_subnet_trace() {
    let cm = new_canister_migrations(vec![((0, 0x1000), vec![0])]);
    assert_matches!(
        cm.well_formed(),
        Err(WellFormedError::CanisterMigrationsInvalidTrace(_))
    );
}

#[test]
fn canister_migrations_repeated_subnet_in_trace() {
    let cm = new_canister_migrations(vec![((0, 0x1000), vec![0, 1, 1])]);
    assert_matches!(
        cm.well_formed(),
        Err(WellFormedError::CanisterMigrationsInvalidTrace(_))
    );
}

#[test]
fn canister_migrations_try_from_success() {
    let mut map = BTreeMap::new();
    map.insert(
        CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(1),
        },
        vec![subnet_test_id(13), subnet_test_id(14)],
    );
    assert_matches!(CanisterMigrations::try_from(map), Ok(_));
}

#[test]
fn canister_migrations_try_from_invalid() {
    let mut map = BTreeMap::new();
    map.insert(
        CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(1),
        },
        vec![],
    );
    assert_matches!(
        CanisterMigrations::try_from(map),
        Err(WellFormedError::CanisterMigrationsInvalidTrace(_))
    );
}

#[test]
fn valid_canister_migrations() {
    fn trace(trace: &[u64]) -> Option<Vec<SubnetId>> {
        Some(trace.iter().map(|&subnet| subnet_test_id(subnet)).collect())
    }

    let t1 = vec![1, 2];
    let t2 = vec![2, 3];
    let t3 = vec![1, 3];
    let t4 = vec![8, 9, 8]; // Same subnet twice.
    let t5 = vec![9, 8];

    let rt = new_canister_migrations(vec![
        ((0x100, 0x100ff), t1.clone()),
        ((0x20000, 0x2ffff), t2.clone()),
        ((0x50000, 0x50fff), t3.clone()),
        ((0x80000, 0x8ffff), t4.clone()),
        ((0x90000, 0xfffff), t5.clone()),
    ]);

    assert_eq!(rt.well_formed(), Ok(()));

    assert_eq!(None, rt.lookup(CanisterId::from(0)));
    assert_eq!(None, rt.lookup(CanisterId::from(0x99)));
    assert_eq!(trace(&t1), rt.lookup(CanisterId::from(0x100)));
    assert_eq!(None, rt.lookup(CanisterId::from(0x10100)));
    assert_eq!(trace(&t2), rt.lookup(CanisterId::from(0x20500)));
    assert_eq!(trace(&t3), rt.lookup(CanisterId::from(0x50050)));
    assert_eq!(None, rt.lookup(CanisterId::from(0x100000)));
    assert_eq!(trace(&t4), rt.lookup(CanisterId::from(0x8ffff)));
    assert_eq!(trace(&t5), rt.lookup(CanisterId::from(0x90000)));
    assert_eq!(None, rt.lookup(CanisterId::from(0xffffffffffffffff)));
}
