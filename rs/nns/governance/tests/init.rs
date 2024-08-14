use ic_nns_governance_api::pb::v1::Topic;
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use std::path::PathBuf;

#[test]
fn neurons_from_csv() {
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let init_payload = GovernanceCanisterInitPayloadBuilder::new()
        .add_all_neurons_from_csv_file(&p)
        .build();
    assert_eq!(3, init_payload.neurons.len());
    let n0 = &init_payload.neurons.get(&25).unwrap();
    let n1 = &init_payload.neurons.get(&42).unwrap();
    let n2 = &init_payload.neurons.get(&100).unwrap();
    // neuron_id
    assert_eq!(25, n0.id.as_ref().unwrap().id);
    assert_eq!(42, n1.id.as_ref().unwrap().id);
    assert_eq!(100, n2.id.as_ref().unwrap().id);
    // stake
    assert_eq!(1_000_000_000 * 100_000_000, n0.cached_neuron_stake_e8s);
    // follows
    let followees = &n2
        .followees
        .get(&(Topic::Unspecified as i32))
        .unwrap()
        .followees;
    assert_eq!(2, followees.len());
    assert_eq!(25, followees.first().unwrap().id);
    assert_eq!(42, followees.get(1).unwrap().id);
}
