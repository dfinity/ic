use crate::rosetta_tests::setup::subnet_sys;
use candid::{Decode, Encode, Principal};
use dfn_protobuf::ProtoBuf;
use ic_agent::Agent;
use ic_ledger_core::block::BlockIndex;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, IcNodeContainer};
use ic_system_test_driver::util::{assert_create_agent, block_on};
use icp_ledger::protobuf::TipOfChainRequest;
use icp_ledger::{AccountBalanceArgs, AccountIdentifier, Certification, TipOfChainRes, Tokens};
use on_wire::{FromWire, IntoWire};
use slog::{debug, Logger};

pub struct LedgerClient {
    agent: Agent,
    ledger_canister_id: Principal,
    logger: Logger,
}

///  Create an agent to interact with the ledger.
fn create_agent(env: &TestEnv) -> Agent {
    block_on(async {
        let subnet_sys = subnet_sys(env);
        let node = subnet_sys.nodes().next().expect("No node in sys subnet.");
        assert_create_agent(node.get_public_url().as_str()).await
    })
}

impl LedgerClient {
    pub fn new(env: &TestEnv, ledger_canister_id: Principal) -> LedgerClient {
        let logger = env.logger();
        let agent = create_agent(env);
        LedgerClient {
            agent,
            ledger_canister_id,
            logger,
        }
    }

    /// Get the balance of an account.
    pub async fn get_account_balance(&self, account: AccountIdentifier) -> Tokens {
        debug!(&self.logger, "[ledger_client] Getting account balance");
        let arg = AccountBalanceArgs { account };
        let arg = Encode!(&arg).expect("Error while encoding arg.");
        let res = self
            .agent
            .update(&self.ledger_canister_id, "account_balance_dfx")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("Error while calling endpoint.");
        Decode!(res.as_slice(), Tokens).expect("Error while decoding response.")
    }

    /// Retrieve the tip of chain via protobuf (cf. canister_access).
    pub async fn get_tip(&self) -> (Certification, BlockIndex) {
        debug!(&self.logger, "[ledger_client] Getting blockchain tip");
        let payload = TipOfChainRequest {};
        let arg = ProtoBuf(payload)
            .into_bytes()
            .expect("Error while converting arg");
        let bytes = self
            .agent
            .query(&self.ledger_canister_id, "tip_of_chain_pb")
            .with_arg(arg)
            .call()
            .await
            .expect("Error while retrieving tip");
        let res: TipOfChainRes = ProtoBuf::from_bytes(bytes)
            .map(|c| c.0)
            .expect("Error while decoding result");
        debug!(
            &self.logger,
            "[ledger_client] blockchain tip: {:?}", res.tip_index
        );
        (res.certification, res.tip_index)
    }
}
