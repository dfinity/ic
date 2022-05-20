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
fn try_convert_string_into_canister_id_range() {
    use std::str::FromStr;
    let str_1 = "rrkah-fqaaa-aaaaa-aaaaq-cai:qaa6y-5yaaa-aaaaa-aaafa-cai";
    let str_2 = "qaa6y-5yaaa-aaaaa-aaafa-cai:rrkah-fqaaa-aaaaa-aaaaq-cai";
    let str_3 = "qaa6y-5yaaa-aaaaa-aaafa:rrkah-fqaaa-aaaaa-aaaaq";
    let str_4 = "rrkah-fqaaa-aaaaa-aaaaq-cai";

    assert_eq!(
        CanisterIdRange::from_str(str_1),
        Ok(CanisterIdRange {
            start: CanisterId::from(1),
            end: CanisterId::from(10)
        })
    );

    assert_matches!(
        CanisterIdRange::from_str(str_2),
        Err(CanisterIdRangeError::CanisterIdRangeEmpty(_))
    );

    assert_matches!(
        CanisterIdRange::from_str(str_3),
        Err(CanisterIdRangeError::CanisterIdParseError(_))
    );

    assert_matches!(
        CanisterIdRange::from_str(str_4),
        Err(CanisterIdRangeError::CanisterIdsNotPair(_))
    );
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
fn canister_id_ranges_is_subset_of() {
    let ranges_a = new_canister_id_ranges(vec![(3, 15), (18, 20)]);
    let ranges_b = new_canister_id_ranges(vec![(0, 30)]);
    let ranges_c = new_canister_id_ranges(vec![(0, 20), (30, 30)]);
    assert!(is_subset_of(ranges_a.iter(), ranges_b.iter()));
    assert!(is_subset_of(ranges_a.iter(), ranges_c.iter()));
}

#[test]
fn canister_id_ranges_is_not_subset_of() {
    let ranges_a = new_canister_id_ranges(vec![(3, 15), (18, 20)]);
    let ranges_b = new_canister_id_ranges(vec![(0, 19)]);
    let ranges_c = new_canister_id_ranges(vec![(0, 15), (19, 19), (20, 30)]);
    // `is_subset_of()` will return false it any range is not contained by exactly one range.
    let ranges_d = new_canister_id_ranges(vec![
        (0, 5),
        (6, 10),
        (11, 16),
        (18, 19),
        (20, 21),
        (30, 30),
    ]);
    assert!(!is_subset_of(ranges_a.iter(), ranges_b.iter()));
    assert!(!is_subset_of(ranges_a.iter(), ranges_c.iter()));
    assert!(!is_subset_of(ranges_a.iter(), ranges_d.iter()));
}

#[test]
fn canister_id_ranges_are_disjoint() {
    let range_a = new_canister_id_ranges(vec![(3, 15), (18, 20)]);
    let ranges_b = new_canister_id_ranges(vec![(100, 0x200ff)]);
    let ranges_c = new_canister_id_ranges(vec![(0, 2), (16, 17), (21, 30)]);

    assert!(are_disjoint(range_a.iter(), ranges_b.iter()));
    assert!(are_disjoint(range_a.iter(), ranges_c.iter()));

    let canister_migrations =
        new_canister_migrations(vec![((3, 15), vec![0, 1]), ((18, 20), vec![0, 1])]);
    assert!(are_disjoint(canister_migrations.ranges(), ranges_b.iter()));
    assert!(are_disjoint(canister_migrations.ranges(), ranges_c.iter()));
}

#[test]
fn canister_id_ranges_are_not_disjoint() {
    let range_a = new_canister_id_ranges(vec![(3, 15), (18, 20)]);
    let ranges_b = new_canister_id_ranges(vec![(10, 10)]);
    let ranges_c = new_canister_id_ranges(vec![(15, 18)]);

    assert!(!are_disjoint(range_a.iter(), ranges_b.iter()));
    assert!(!are_disjoint(range_a.iter(), ranges_c.iter()));

    let canister_migrations =
        new_canister_migrations(vec![((3, 15), vec![0, 1]), ((18, 20), vec![0, 1])]);
    assert!(!are_disjoint(canister_migrations.ranges(), ranges_b.iter()));
    assert!(!are_disjoint(canister_migrations.ranges(), ranges_c.iter()));
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
fn can_reassign_ranges() {
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

            let res = rt_copy.assign_ranges(
                CanisterIdRanges(vec![CanisterIdRange {
                    start: CanisterId::from(start),
                    end: CanisterId::from(end),
                }]),
                dst,
            );
            assert_eq!(res, Ok(()));

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
    assert!(!rt.is_optimized());

    let rt_optimized = {
        let mut rt = rt.clone();
        rt.optimize();
        rt
    };
    assert!(rt_optimized.is_optimized());

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
    let canister_migrations = new_canister_migrations(vec![((0x1000, 0x1ff), vec![0, 1])]);
    assert_matches!(
        canister_migrations.well_formed(),
        Err(WellFormedError::CanisterMigrationsEmptyRange(_))
    );
}

#[test]
fn canister_migrations_overlapping_ranges() {
    let canister_migrations = new_canister_migrations(vec![
        ((0, 0x100ff), vec![0, 1]),
        ((0x10000, 0x200ff), vec![0, 1]),
    ]);
    assert_matches!(
        canister_migrations.well_formed(),
        Err(WellFormedError::CanisterMigrationsNotDisjoint(_))
    );
}

#[test]
fn canister_migrations_single_subnet_trace() {
    let canister_migrations = new_canister_migrations(vec![((0, 0x1000), vec![0])]);
    assert_matches!(
        canister_migrations.well_formed(),
        Err(WellFormedError::CanisterMigrationsInvalidTrace(_))
    );
}

#[test]
fn canister_migrations_repeated_subnet_in_trace() {
    let canister_migrations = new_canister_migrations(vec![((0, 0x1000), vec![0, 1, 1])]);
    assert_matches!(
        canister_migrations.well_formed(),
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

    let canister_migrations = new_canister_migrations(vec![
        ((0x100, 0x100ff), t1.clone()),
        ((0x20000, 0x2ffff), t2.clone()),
        ((0x50000, 0x50fff), t3.clone()),
        ((0x80000, 0x8ffff), t4.clone()),
        ((0x90000, 0xfffff), t5.clone()),
    ]);

    assert_eq!(canister_migrations.well_formed(), Ok(()));

    assert_eq!(None, canister_migrations.lookup(CanisterId::from(0)));
    assert_eq!(None, canister_migrations.lookup(CanisterId::from(0x99)));
    assert_eq!(
        trace(&t1),
        canister_migrations.lookup(CanisterId::from(0x100))
    );
    assert_eq!(None, canister_migrations.lookup(CanisterId::from(0x10100)));
    assert_eq!(
        trace(&t2),
        canister_migrations.lookup(CanisterId::from(0x20500))
    );
    assert_eq!(
        trace(&t3),
        canister_migrations.lookup(CanisterId::from(0x50050))
    );
    assert_eq!(None, canister_migrations.lookup(CanisterId::from(0x100000)));
    assert_eq!(
        trace(&t4),
        canister_migrations.lookup(CanisterId::from(0x8ffff))
    );
    assert_eq!(
        trace(&t5),
        canister_migrations.lookup(CanisterId::from(0x90000))
    );
    assert_eq!(
        None,
        canister_migrations.lookup(CanisterId::from(0xffffffffffffffff))
    );
}

#[test]
fn canister_migrations_can_insert_ranges() {
    let mut canister_migrations =
        new_canister_migrations(vec![((3, 15), vec![0, 1]), ((18, 20), vec![0, 1])]);
    let ranges = new_canister_id_ranges(vec![(0, 2), (16, 17), (21, 30)]);
    let res = canister_migrations.insert_ranges(ranges, subnet_test_id(0), subnet_test_id(2));
    assert_eq!(res, Ok(()));
    let expected_canister_migrations = new_canister_migrations(vec![
        ((3, 15), vec![0, 1]),
        ((18, 20), vec![0, 1]),
        ((0, 2), vec![0, 2]),
        ((16, 17), vec![0, 2]),
        ((21, 30), vec![0, 2]),
    ]);
    assert_eq!(canister_migrations, expected_canister_migrations);
}

#[test]
fn canister_migrations_insert_invalid_ranges_panic() {
    let mut canister_migrations =
        new_canister_migrations(vec![((3, 15), vec![0, 1]), ((18, 20), vec![0, 1])]);
    let ranges = new_canister_id_ranges(vec![(10, 10)]);
    let res = canister_migrations.insert_ranges(ranges, subnet_test_id(0), subnet_test_id(2));
    assert_eq!(
        res,
        Err(WellFormedError::CanisterMigrationsNotDisjoint(
            "Canister migrations cannot insert overlapping entries".to_string(),
        ))
    );
}

#[test]
fn canister_migrations_can_remove_ranges() {
    let canister_migrations = new_canister_migrations(vec![
        ((0, 5), vec![0, 1]),
        ((6, 10), vec![0, 1]),
        ((21, 25), vec![2, 3]),
        ((30, 30), vec![2, 3]),
    ]);

    let mut canister_migrations_copy = canister_migrations.clone();

    // does nothing if any of the ranges does not match the trace.
    let res = canister_migrations_copy.remove_ranges(
        new_canister_id_ranges(vec![(0, 5), (6, 10), (40, 50)]),
        vec![subnet_test_id(0), subnet_test_id(1)],
    );
    assert!(res.is_err());
    assert_eq!(canister_migrations_copy, canister_migrations);

    // does nothing as the range does not exist in the map
    // although it is contained by a range in the map.
    let res = canister_migrations_copy.remove_ranges(
        new_canister_id_ranges(vec![(0, 2)]),
        vec![subnet_test_id(0), subnet_test_id(1)],
    );
    assert!(res.is_err());
    assert_eq!(canister_migrations_copy, canister_migrations);

    // does nothing as the given trace does not match the value in the map.
    let res = canister_migrations_copy.remove_ranges(
        new_canister_id_ranges(vec![(0, 5)]),
        vec![subnet_test_id(2), subnet_test_id(3)],
    );
    assert!(res.is_err());
    assert_eq!(canister_migrations_copy, canister_migrations);

    // `remove_ranges()` can remove one matching range.
    let res = canister_migrations_copy.remove_ranges(
        new_canister_id_ranges(vec![(0, 5)]),
        vec![subnet_test_id(0), subnet_test_id(1)],
    );
    assert!(res.is_ok());
    assert_eq!(
        canister_migrations_copy,
        new_canister_migrations(vec![
            ((6, 10), vec![0, 1]),
            ((21, 25), vec![2, 3]),
            ((30, 30), vec![2, 3])
        ])
    );

    // `remove_ranges()` can remove multiple matching ranges.
    let res = canister_migrations_copy.remove_ranges(
        new_canister_id_ranges(vec![(21, 25), (30, 30)]),
        vec![subnet_test_id(2), subnet_test_id(3)],
    );
    assert!(res.is_ok());
    assert_eq!(
        canister_migrations_copy,
        new_canister_migrations(vec![((6, 10), vec![0, 1])])
    );
}
