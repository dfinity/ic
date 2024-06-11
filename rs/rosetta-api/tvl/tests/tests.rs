use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat};
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::state_test_helpers::setup_nns_canisters;
use ic_state_machine_tests::{CanisterId, StateMachine};
use ic_tvl_canister::types::{TvlArgs as TVLInitArgs, TvlResult, TvlResultError};
use ic_tvl_canister::{
    multiply_e8s, FiatCurrency, TvlRequest, DEFAULT_UPDATE_PERIOD, ONE_DAY, OTHER_CURRENCIES,
};
use rand::{thread_rng, Rng};
use xrc_mock::{ExchangeRate, Response, SetExchangeRate, XrcMockInitPayload};

const DEFAULT_ICP_RATE: u64 = 1_000_000_000;
const E8S: u64 = 100_000_000;

fn tvl_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("TVL_WASM").unwrap()).unwrap()
}

fn xrc_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(std::env::var("XRC_WASM_PATH").unwrap(), "xrc", &[])
}

struct TvlSetup {
    env: StateMachine,
    governance_id: CanisterId,
    xrc_id: CanisterId,
    tvl_id: CanisterId,
}

impl TvlSetup {
    pub fn new() -> Self {
        let env = StateMachine::new();
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();

        setup_nns_canisters(&env, nns_init_payload);

        pub const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);

        let xrc_args = XrcMockInitPayload {
            response: Response::ExchangeRate(ExchangeRate {
                base_asset: None,
                quote_asset: None,
                metadata: None,
                rate: DEFAULT_ICP_RATE, // This corresponds to an ICP price of 10$
            }),
        };

        let xrc_args = Encode!(&xrc_args).unwrap();
        let xrc_id = env.install_canister(xrc_wasm(), xrc_args, None).unwrap();
        let args = TVLInitArgs {
            update_period: Some(DEFAULT_UPDATE_PERIOD),
            governance_id: Some(GOVERNANCE_CANISTER_ID.get()),
            xrc_id: Some(xrc_id.get()),
        };
        let args = Encode!(&args).unwrap();
        let tvl_id = env.install_canister(tvl_wasm(), args, None).unwrap();
        Self {
            env,
            governance_id: GOVERNANCE_CANISTER_ID,
            xrc_id,
            tvl_id,
        }
    }

    pub fn get_tvl(&self, req: Option<TvlRequest>) -> Result<TvlResult, TvlResultError> {
        Decode!(
            &self.env.query(self.tvl_id, "get_tvl", Encode!(&req).unwrap())
                .expect("failed to query balance")
                .bytes(),
                Result<TvlResult, TvlResultError>
        )
        .expect("failed to decode get_tvl response")
    }

    pub fn set_exchange_rate(&self, arg: SetExchangeRate) {
        let _ = &self
            .env
            .execute_ingress(self.xrc_id, "set_exchange_rate", Encode!(&arg).unwrap())
            .expect("failed to set_exchange_rate")
            .bytes();
    }
}

#[test]
fn test_tvl() {
    let tvl = TvlSetup::new();

    tvl.env.run_until_completion(10_000);
    tvl.env
        .advance_time(std::time::Duration::from_secs(DEFAULT_UPDATE_PERIOD));
    tvl.env.tick();

    let get_tvl_result: TvlResult = tvl.get_tvl(None).unwrap();
    // 3 neurons with respectively 10 ICP, 1 ICP and 0.1 ICP locked.
    // ICP price is 10$, hence tvl should be 111$.
    assert_eq!(get_tvl_result.tvl, Nat::from(111_u8));

    let upgrade_args = TVLInitArgs {
        update_period: Some(30),
        governance_id: Some(tvl.governance_id.get()),
        xrc_id: Some(tvl.xrc_id.get()),
    };
    tvl.env
        .upgrade_canister(tvl.tvl_id, tvl_wasm(), Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the tvl canister");

    let get_tvl_result_after_upgrade: TvlResult = tvl.get_tvl(None).unwrap();
    assert_eq!(get_tvl_result, get_tvl_result_after_upgrade);
}

#[test]
fn test_multiple_currencies() {
    let tvl = TvlSetup::new();
    tvl.env.run_until_completion(100);
    tvl.env
        .advance_time(std::time::Duration::from_secs(24 * 60 * 60));
    tvl.env.tick();

    let mut rng = thread_rng();

    // Check that we cannot get tvl in a currency until it is set.

    for currency in OTHER_CURRENCIES {
        let arg = TvlRequest {
            currency: currency.clone(),
        };
        let get_tvl_result = tvl.get_tvl(Some(arg));
        assert_matches!(
            get_tvl_result,
            Err(TvlResultError { .. }),
            "{}",
            currency.to_string()
        );
        println!("Setting exchange rate for currency: {}", currency);

        let rate: u64 = rng.gen_range(50_000_000_u64..200_000_000_u64);
        tvl.set_exchange_rate(SetExchangeRate {
            base_asset: "USD".to_string(),
            quote_asset: currency.to_string(),
            rate,
        });

        tvl.env.advance_time(std::time::Duration::from_secs(1));
        tvl.env.tick();

        let locked_amount_e8s = 1_110_000_000;
        let expected_tvl =
            multiply_e8s(multiply_e8s(locked_amount_e8s, DEFAULT_ICP_RATE), rate) / E8S;

        let arg = TvlRequest {
            currency: currency.clone(),
        };
        let get_tvl_result = tvl.get_tvl(Some(arg)).unwrap();
        assert_eq!(get_tvl_result.tvl, Nat::from(expected_tvl));
    }

    let upgrade_args = TVLInitArgs {
        update_period: Some(30),
        governance_id: Some(tvl.governance_id.get()),
        xrc_id: Some(tvl.xrc_id.get()),
    };
    tvl.env
        .upgrade_canister(tvl.tvl_id, tvl_wasm(), Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the tvl canister");
    let rate: u64 = rng.gen_range(50_000_000_u64..200_000_000_u64);

    for currency in OTHER_CURRENCIES {
        if currency == FiatCurrency::USD {
            continue;
        }
        let arg = TvlRequest {
            currency: currency.clone(),
        };
        let get_tvl_result = tvl.get_tvl(Some(arg));

        // After an upgrade we should still have the old rates.

        assert_matches!(
            get_tvl_result,
            Ok(TvlResult { .. }),
            "{}",
            currency.to_string()
        );

        tvl.set_exchange_rate(SetExchangeRate {
            base_asset: "USD".to_string(),
            quote_asset: currency.to_string(),
            rate,
        });
    }
    tvl.env.advance_time(ONE_DAY);
    tvl.env.tick();

    for currency in OTHER_CURRENCIES {
        let locked_amount_e8s = 1_110_000_000;
        let expected_tvl =
            multiply_e8s(multiply_e8s(locked_amount_e8s, DEFAULT_ICP_RATE), rate) / E8S;

        let arg = TvlRequest {
            currency: currency.clone(),
        };
        let get_tvl_result = tvl.get_tvl(Some(arg)).unwrap();
        assert_eq!(get_tvl_result.tvl, Nat::from(expected_tvl));
    }
}

#[test]
fn test_fiat_updates() {
    let tvl = TvlSetup::new();
    tvl.env.run_until_completion(100);
    tvl.env
        .advance_time(std::time::Duration::from_secs(24 * 60 * 60));
    tvl.env.tick();

    let mut rng = thread_rng();
    let rate: u64 = rng.gen_range(50_000_000_u64..200_000_000_u64);
    for currency in OTHER_CURRENCIES {
        tvl.set_exchange_rate(SetExchangeRate {
            base_asset: "USD".to_string(),
            quote_asset: currency.to_string(),
            rate,
        });
    }

    tvl.env.advance_time(std::time::Duration::from_secs(1));

    tvl.env.tick();

    let locked_amount_e8s = 1_110_000_000;
    let expected_tvl = multiply_e8s(multiply_e8s(locked_amount_e8s, DEFAULT_ICP_RATE), rate) / E8S;

    let currency = FiatCurrency::EUR;

    let arg = TvlRequest {
        currency: currency.clone(),
    };
    let get_tvl_result = tvl.get_tvl(Some(arg.clone())).unwrap();
    assert_eq!(get_tvl_result.tvl, Nat::from(expected_tvl));

    let rate: u64 = rng.gen_range(200_000_000_u64..400_000_000_u64);
    tvl.set_exchange_rate(SetExchangeRate {
        base_asset: "USD".to_string(),
        quote_asset: currency.to_string(),
        rate,
    });

    tvl.env.advance_time(std::time::Duration::from_secs(1));
    tvl.env.tick();

    let get_tvl_result = tvl.get_tvl(Some(arg.clone())).unwrap();
    assert_eq!(get_tvl_result.tvl, Nat::from(expected_tvl));

    tvl.env.advance_time(ONE_DAY);
    tvl.env.tick();

    let expected_tvl = multiply_e8s(multiply_e8s(locked_amount_e8s, DEFAULT_ICP_RATE), rate) / E8S;
    let get_tvl_result = tvl.get_tvl(Some(arg)).unwrap();
    assert_eq!(get_tvl_result.tvl, Nat::from(expected_tvl));
}
