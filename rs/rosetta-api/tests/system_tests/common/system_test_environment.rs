pub struct RosettaTestingEnviornment {
    pub pocket_ic: PocketIc,
    pub rosetta_context: RosettaContext,
}

pub struct RosettaTestingEnviornmentBuilder {
    pub persistent_storage: bool,
}

impl RosettaTestingEnviornmentBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn with_persistent_storage(mut self) -> Self {
        self.persistent_storage = true;
        self
    }

    pub fn build(self) -> RosettaTestingEnviornment {
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let canister_id = pocket_ic
            .create_canister_with_id(None, None, ledger_canister_id)
            .await
            .expect("Unable to create the canister in which the Ledger would be installed");
        pocket_ic
            .install_canister(
                canister_id,
                icp_ledger_wasm_bytes(),
                icp_ledger_init(sender_canister_id),
                None,
            )
            .await;
        assert_eq!(
            ledger_canister_id, canister_id,
            "Canister IDs do not match: expected {}, got {}",
            ledger_canister_id, canister_id
        );

        pocket_ic
            .add_cycles(ledger_canister_id, STARTING_CYCLES_PER_CANISTER)
            .await;

        println!(
            "Installed the Ledger canister ({canister_id}) onto {}",
            pocket_ic.get_subnet(ledger_canister_id).await.unwrap()
        );

        let replica_url = pocket_ic.make_live(None).await;

        let rosetta_state_directory =
            TempDir::new().expect("failed to create a temporary directory");

        RosettaTestingEnviornment {
            pocket_ic,
            rosetta_context: RosettaContext::new(self.persistent_storage),
        }
    }
}
