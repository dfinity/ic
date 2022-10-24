use super::greedy;
use ic_btc_types::{OutPoint, Utxo};
use proptest::collection::vec;
use proptest::proptest;
use proptest::{prop_assert, prop_assert_eq};
use std::collections::BTreeSet;

fn dummy_utxo_from_value(v: u64) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: v.to_be_bytes().to_vec(),
            vout: 0,
        },
        value: v,
        height: 0,
    }
}

#[test]
fn greedy_smoke_test() {
    let mut utxos: BTreeSet<Utxo> = (1..10u64).map(dummy_utxo_from_value).collect();
    assert_eq!(utxos.len(), 9_usize);

    let res = greedy(15, &mut utxos);

    assert_eq!(res[0].value, 9_u64);
    assert_eq!(res[1].value, 6_u64);
}

proptest! {
    #[test]
    fn greedy_solution_properties(
        values in vec(1u64..1_000_000_000, 1..10),
        target in 1u64..1_000_000_000,
    ) {
        let mut utxos: BTreeSet<Utxo> = values
            .into_iter()
            .map(dummy_utxo_from_value)
            .collect();

        let total = utxos.iter().map(|u| u.value).sum::<u64>();

        if total < target {
            utxos.insert(dummy_utxo_from_value(target - total));
        }

        let original_utxos = utxos.clone();

        let solution = greedy(target, &mut utxos);

        prop_assert!(
            !solution.is_empty(),
            "greedy() must always find a solution given enough available UTXOs"
        );

        prop_assert!(
            solution.iter().map(|u| u.value).sum::<u64>() >= target,
            "greedy() must reach the specified target amount"
        );

        prop_assert!(
            solution.iter().all(|u| original_utxos.contains(u)),
            "greedy() must select utxos from the available set"
        );

        prop_assert!(
            solution.iter().all(|u| !utxos.contains(u)),
            "greedy() must remove found UTXOs from the available set"
        );
    }

    #[test]
    fn greedy_does_not_modify_input_when_fails(
        values in vec(1u64..1_000_000_000, 1..10),
    ) {
        let mut utxos: BTreeSet<Utxo> = values
            .into_iter()
            .map(dummy_utxo_from_value)
            .collect();

        let total = utxos.iter().map(|u| u.value).sum::<u64>();

        let original_utxos = utxos.clone();
        let solution = greedy(total + 1, &mut utxos);

        prop_assert!(solution.is_empty());
        prop_assert_eq!(utxos, original_utxos);
    }
}
