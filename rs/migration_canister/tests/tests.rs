#[tokio::test]
async fn test() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let registry_proto_path = state_dir.join("registry.proto");
    let initial_mutations = load_registry_mutations(registry_proto_path);
    let treasury_principal_id = *TREASURY_PRINCIPAL_ID;

    // Installing NNS canisters
    bootstrap_nns(
        &pocket_ic,
        vec![initial_mutations],
        vec![(
            treasury_principal_id.into(),
            Tokens::from_tokens(10_000_000).unwrap(),
        )],
        dev_participant_id,
        dev_neuron_id,
    )
    .await;
    assert!(validate_network(&pocket_ic).await.is_empty());
}
