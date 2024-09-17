/* tag::catalog[]
Title:: Transaction ledger is recorded correctly and can be queried

Goal:: Demonstrate E2E that third parties can obtain the correct ledger

Runbook::
. generate IC principals (account holders)
. start NNS with ledger canister instantiated with k accounts and their balance
. send transfer requests modifying balance
. fetch transactions from ledger canister
. Compare stored transactions with requests

Success:: check certificate for result and that all transfers and nothing else shows up in the transaction ledger

Notes:: Implement as property test, talk to DMD and Bogdan before starting

Framework:: create IC principals and sign on their behalf, ledger canister part of NNS initialization, send queries and update requests and process their responses, verify certifications

Not Covered:: Ledger archives, Timestamps, Mint & Burn, Subaccounts

end::catalog[] */

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use ic_system_test_driver::util::{block_on, runtime_from_url};
use rand_chacha::ChaCha8Rng;
use slog::info;

use async_recursion::async_recursion;
use canister_test::{Canister, Runtime};
use dfn_candid::{candid, candid_one};
use dfn_protobuf::protobuf;
use ic_agent::Agent;
use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair, Sender};
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_types::{CanisterId, PrincipalId};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Block, BlockArg, BlockIndex, BlockRes, Memo,
    Operation, Tokens, Transaction, TransferArgs, TransferError, DEFAULT_TRANSFER_FEE,
};
use quickcheck::{Arbitrary, Gen};
use rand::Rng;

// Seed for a random generator
const RND_SEED: u64 = 42;

/* Runbook::
. Setup NNS with a ledger canister tracking test neurons' account
. upgrade the minting canister to become a funds holder (Motoko canister)
. Create a few more canisters in application subnet, these will have accounts
. Run a generated sequence of transactions (executed by holders)
. Check the blockchain in `ledger` at the end.
 */

/// A test runs within a given IC configuration. Later on, we really want to
/// combine tests that are being run in similar environments. Please, keep this
/// in mind when writing your tests!
pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    info!(logger, "Installing NNS canisters ...");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(logger, "NNS canisters installed successfully");
    let app_node = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    let app_agent = app_node.with_default_agent(|agent| async move { agent });
    let app_runtime = runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id());
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    let plan = create_plan(&mut rng);
    info!(logger, "plan is {:?}", plan);
    block_on(async move {
        // upgrade the minting canister
        holder::upgrade(&nns_runtime, &LIFELINE_CANISTER_ID).await;
        let plan = populate_plan(
            &app_runtime,
            &app_agent,
            app_node.effective_canister_id(),
            &plan,
            &mut rng,
        )
        .await;
        info!(logger, "populated plan is {:?}", plan);

        // convert the test plan to actions
        let mut actions: Vec<Action> = Vec::new();
        actions_from_plan(&mut actions, &plan);

        // run the actions
        info!(logger, "running these actions now: {:?}", actions);
        run_actions(&nns_runtime, &app_runtime, &actions).await;
    });
}

mod holder {
    use canister_test::{Canister, Runtime, Wasm};
    use ic_base_types::PrincipalId;
    use ic_types::CanisterId;
    use ic_utils::interfaces::ManagementCanister;
    use std::convert::TryFrom;

    const HOLDER_CANISTER_WASM: &[u8] = include_bytes!("./transaction_ledger_correctness.wasm");

    #[allow(clippy::needless_lifetimes)]
    pub async fn new<'a>(
        rt: &'a Runtime,
        agent: &ic_agent::Agent,
        effective_canister_id: PrincipalId,
    ) -> Canister<'a> {
        // Create a canister.
        let mgr = ManagementCanister::create(agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(effective_canister_id)
            .call_and_wait()
            .await
            .unwrap()
            .0;

        // Install the holding canister.
        mgr.install_code(&canister_id, HOLDER_CANISTER_WASM)
            .call_and_wait()
            .await
            .expect("Couldn't install?");

        Canister::new(rt, CanisterId::try_from(canister_id.as_slice()).unwrap())
    }

    pub async fn upgrade(rt: &Runtime, nns_canister_id: &CanisterId) {
        ic_nns_test_utils::governance::upgrade_nns_canister_by_proposal(
            &Canister::new(rt, *nns_canister_id),
            &Canister::new(rt, ic_nns_constants::GOVERNANCE_CANISTER_ID),
            &Canister::new(rt, ic_nns_constants::ROOT_CANISTER_ID),
            true,
            Wasm::from_bytes(HOLDER_CANISTER_WASM.to_vec()),
            None,
        )
        .await;
    }
}

type RawKeypair = ([u8; 32], [u8; 32]);
type Receiver = Result<Result<PrincipalId, RawKeypair>, u32>;

/// The `Plan` allows the derivation of all invariants that must
/// hold. Details will get filled in when the principals get created.
/// Please refer to https://hceris.com/either-types-for-rust/
#[derive(Clone, Debug)]
enum Plan {
    Empty,
    IdentityAccount(Result<RawKeypair, u32>, Box<Plan>),
    CanisterAccount(Result<PrincipalId, u32>, Box<Plan>),
    Transfer((Receiver, u64, Result<PrincipalId, u32>), Box<Plan>),
}

impl Plan {
    pub(crate) fn count_principals(&self) -> u32 {
        match self {
            Plan::Empty => 1, // the minting canister is Ok(0)
            Plan::IdentityAccount(_, tail) | Plan::CanisterAccount(_, tail) => {
                1 + tail.count_principals()
            }
            Plan::Transfer(_, tail) => tail.count_principals(),
        }
    }

    fn length(&self) -> u64 {
        use Plan::*;
        match self {
            Empty => 0,
            Transfer(_, plan) | CanisterAccount(_, plan) | IdentityAccount(_, plan) => {
                1 + plan.length()
            }
        }
    }

    /// count how many canisters are created in the plan
    fn count_canisters(&self) -> u64 {
        use Plan::*;
        match self {
            Empty => 0,
            CanisterAccount(_, plan) => 1 + plan.count_canisters(),
            Transfer(_, plan) | IdentityAccount(_, plan) => plan.count_canisters(),
        }
    }
}

impl Arbitrary for Plan {
    fn arbitrary(g: &mut Gen) -> Self {
        match g.choose(&(0..5).collect::<Vec<_>>()) {
            Some(0) => Plan::Empty,
            Some(1) => {
                let tail: Plan = Self::arbitrary(g);
                let principals = tail.count_principals();
                Self::IdentityAccount(Err(principals), Box::new(tail))
            }
            Some(2) => {
                let tail: Plan = Self::arbitrary(g);
                let principals = tail.count_principals();
                if tail.count_canisters() < 6 {
                    Self::CanisterAccount(Err(principals), Box::new(tail))
                } else {
                    // We exceeded the number of canisters in the `send_whitelist`
                    // of `ledger` (see `nns.rs`). Create an identity instead.
                    Self::IdentityAccount(Err(principals), Box::new(tail))
                }
            }
            Some(3) | Some(4) => {
                let tail: Plan = Self::arbitrary(g);
                let principals = tail.count_principals();
                let candidates = (0..principals).collect::<Vec<_>>();
                let from = g.choose(&candidates).unwrap();
                let to = g.choose(&candidates).unwrap();
                let amount: &u64 = g.choose(&[0, 1, 13, 42, 2000, 60000]).unwrap();
                Plan::Transfer((Err(*from), *amount, Err(*to)), Box::new(tail))
            }
            _ => panic!("wut?"),
        }
    }
}

fn create_plan<R: Rng>(rng: &mut R) -> Plan {
    let mut gen = Gen::new(rng.next_u64() as usize);
    loop {
        let plan: Plan = Arbitrary::arbitrary(&mut gen);
        if plan.length() > 25 {
            break plan;
        }
    }
}

fn ed25519_public_to_principal(public: &[u8; 32]) -> PrincipalId {
    PrincipalId::new_self_authenticating(&ed25519_public_key_to_der(public.to_vec()))
}

/// `principal` turns an identity into a PrincipalId
fn principal(ptr: &Result<RawKeypair, u32>) -> Result<PrincipalId, u32> {
    ptr.map(|(_, public)| ed25519_public_to_principal(&public))
}

/// `link0` resolves a numerical canister identifier to a principal or identity
/// given the raw plan vs. the populated plan.
fn link0(
    ptr: &Result<PrincipalId, u32>,
    iplan: &Plan,
    oplan: &Plan,
) -> Result<PrincipalId, RawKeypair> {
    if *ptr == Err(0) {
        return Ok(LIFELINE_CANISTER_ID.get());
    }
    match (iplan, oplan) {
        (Plan::CanisterAccount(i, _), Plan::CanisterAccount(Ok(o), _)) if i == ptr => Ok(*o),
        (Plan::IdentityAccount(i, _), Plan::IdentityAccount(Ok(o), _)) if principal(i) == *ptr => {
            Err(*o)
        }
        (Plan::CanisterAccount(_, itail), Plan::CanisterAccount(_, otail))
        | (Plan::IdentityAccount(_, itail), Plan::IdentityAccount(_, otail))
        | (Plan::Transfer(_, itail), Plan::Transfer(_, otail)) => link0(ptr, itail, otail),
        _ => panic!("cannot happen! {:?}", (ptr, iplan, oplan)),
    }
}

/// `link` resolves a numerical canister identifier to a principal
/// given the raw plan vs. the populated plan.
fn link(ptr: &Result<PrincipalId, u32>, iplan: &Plan, oplan: &Plan) -> Result<PrincipalId, u32> {
    if *ptr == Err(0) {
        return Ok(LIFELINE_CANISTER_ID.get());
    }
    match (iplan, oplan) {
        (Plan::CanisterAccount(i, _), Plan::CanisterAccount(o, _)) if i == ptr => *o,
        (Plan::IdentityAccount(i, _), Plan::IdentityAccount(o, _)) if principal(i) == *ptr => {
            principal(o)
        }
        (Plan::CanisterAccount(_, itail), Plan::CanisterAccount(_, otail))
        | (Plan::IdentityAccount(_, itail), Plan::IdentityAccount(_, otail))
        | (Plan::Transfer(_, itail), Plan::Transfer(_, otail)) => link(ptr, itail, otail),
        _ => panic!("cannot happen! {:?}", (ptr, iplan, oplan)),
    }
}

/// `funds` figures out given a plan, by tracking ICPT movements and
/// anticipates transfers that will fail to materialise as transactions.
fn funds(ptr: &Result<PrincipalId, u32>, plan: &Plan) -> Tokens {
    match plan {
        Plan::Empty => {
            if *ptr == Err(0) || *ptr == link(&Err(0), plan, plan) {
                Tokens::from_e8s(1000000000000) // LIFELINE start balance
            } else {
                Tokens::ZERO
            }
        }
        Plan::IdentityAccount(_, tail) | Plan::CanisterAccount(_, tail) => funds(ptr, tail),
        Plan::Transfer((from0, amount, to), tail) => {
            let mut balance = funds(ptr, tail);

            let from = from0.map(|owner| match owner {
                Ok(princ) => princ,
                Err((_, public)) => ed25519_public_to_principal(&public),
            });

            let minimal_balance = Tokens::from_e8s(*amount)
                .checked_add(&DEFAULT_TRANSFER_FEE)
                .unwrap();
            if from != *to {
                // checking for account exhaustion
                let source = funds(&from, tail);
                if source < minimal_balance {
                    // transfer not covered (traps)
                    return balance;
                }
            } else if balance < minimal_balance {
                // transfer not covered (traps)
                // even for a self-transfer
                return balance;
            }

            // at this point we know that addition won't overflow,
            // as the total sum invariant holds
            if ptr == to {
                balance = balance.checked_add(&Tokens::from_e8s(*amount)).unwrap()
            }
            if *ptr == from {
                balance = balance
                    .checked_sub(&Tokens::from_e8s(*amount))
                    .unwrap()
                    .checked_sub(&DEFAULT_TRANSFER_FEE)
                    .unwrap()
            }
            balance
        }
    }
}

/// `populate_plan` performs canister installations in order to turn
/// numerical canister identifications into principal ids, also resolving
/// them in transfers. A populated plan won't contain numerical ids (i.e
/// `Err`) any more.
#[async_recursion(?Send)]
async fn populate_plan(
    app_rt: &Runtime,
    agent: &Agent,
    effective_canister_id: PrincipalId,
    plan: &Plan,
    rng: &mut rand_chacha::ChaCha8Rng,
) -> Plan {
    match plan {
        Plan::Empty => Plan::Empty,
        Plan::IdentityAccount(Err(_), tail) => {
            let tail = populate_plan(app_rt, agent, effective_canister_id, tail, rng).await;
            let keypair = Ed25519KeyPair::generate(rng);
            Plan::IdentityAccount(Ok((keypair.secret_key, keypair.public_key)), Box::new(tail))
        }
        Plan::CanisterAccount(Err(_), tail) => {
            let (tail, can) = tokio::join!(
                populate_plan(app_rt, agent, effective_canister_id, tail, rng),
                holder::new(app_rt, agent, effective_canister_id)
            );
            Plan::CanisterAccount(Ok(can.canister_id().get()), Box::new(tail))
        }
        Plan::Transfer((Err(from), amount, to), itail) => {
            let otail = populate_plan(app_rt, agent, effective_canister_id, itail, rng).await;
            let from0 = link0(&Err(*from), itail, &otail);
            let to = link(to, itail, &otail);
            Plan::Transfer((Ok(from0), *amount, to), Box::new(otail))
        }
        _ => panic!("wuut?"),
    }
}

#[derive(Debug)]
enum Message {
    Send((Tokens, Tokens), PrincipalId, Tokens),
    InitialAccountQuery(Tokens),
}

/// An `Action` is a pair consisting of addressee and message
/// arguments for sending information (and processing results)
/// in the IC. The `Message` part also encodes the method name
/// and whether the send is a query or an update.
type Action = (Result<PrincipalId, Ed25519KeyPair>, Message);

/// `actions_from_plan` turns a populated `Plan` into a sequence
/// of actions.
fn actions_from_plan(acc: &mut Vec<Action>, plan: &Plan) {
    match plan {
        Plan::Empty => {
            acc.push((
                Ok(LIFELINE_CANISTER_ID.get()),
                Message::InitialAccountQuery(funds(&Err(0), plan)),
            ));
            let neurons_stake = Tokens::ZERO; // TEST_NEURON_TOTAL_STAKE_E8S would be the sum of subaccounts
            acc.push((
                Ok(GOVERNANCE_CANISTER_ID.get()),
                Message::InitialAccountQuery(neurons_stake),
            ));
            acc.push((
                Ok(ROOT_CANISTER_ID.get()),
                Message::InitialAccountQuery(Tokens::ZERO), // minting canister has unlimited funds
            ))
        }
        Plan::IdentityAccount(Ok(_), tail) | Plan::CanisterAccount(Ok(_), tail) => {
            actions_from_plan(acc, tail)
        }
        Plan::Transfer((Ok(from0), amount, Ok(to)), tail) => {
            let from = match from0 {
                Err((_, public)) => ed25519_public_to_principal(public),
                Ok(princ) => *princ,
            };
            let from_funds = funds(&Ok(from), tail);
            let to_funds = if from == *to {
                from_funds
            } else {
                funds(&Ok(*to), tail)
            };
            actions_from_plan(acc, tail);

            fn from_addr(
                from0: &Result<PrincipalId, RawKeypair>,
            ) -> Result<PrincipalId, Ed25519KeyPair> {
                from0.map_err(|(secret_key, public_key)| Ed25519KeyPair {
                    secret_key,
                    public_key,
                })
            }

            // check the accounts
            if from0.is_err() {
                acc.push((from_addr(from0), Message::InitialAccountQuery(from_funds)));
                acc.push((Ok(*to), Message::InitialAccountQuery(to_funds)))
            }
            // perform the transfer
            acc.push((
                from_addr(from0),
                Message::Send((from_funds, to_funds), *to, Tokens::from_e8s(*amount)),
            ))
        }
        _ => panic!("wwut?"),
    }
}

/// `run_actions` performs all the IC communication corresponding to the
/// sequence of actions. Checks results.
async fn run_actions(nns_rt: &Runtime, app_rt: &Runtime, actions: &[Action]) {
    for (owner, mess) in actions {
        let ledger = Canister::new(nns_rt, LEDGER_CANISTER_ID);
        match mess {
            Message::InitialAccountQuery(want_to_see) => {
                let princ: PrincipalId = match owner {
                    Ok(princ) => *princ,
                    Err(keypair) => ed25519_public_to_principal(&keypair.public_key),
                };
                let balance: Tokens = ledger
                    .query_(
                        "account_balance",
                        candid_one,
                        BinaryAccountBalanceArgs {
                            account: AccountIdentifier::new(princ, None).to_address(),
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(*want_to_see, balance);
            }
            Message::Send((from_funds, to_funds), to, amount) => {
                let to_account = AccountIdentifier::new(*to, None);
                let debit = amount.checked_add(&DEFAULT_TRANSFER_FEE).unwrap();
                let block: Option<(BlockIndex, AccountIdentifier, Memo)> = match owner {
                    Ok(princ) => {
                        let rt = if *princ == LIFELINE_CANISTER_ID.get() {
                            nns_rt
                        } else {
                            app_rt
                        };
                        let from_account = AccountIdentifier::new(*princ, None);
                        Canister::new(rt, CanisterId::unchecked_from_principal(*princ))
                            .update_(
                                "check_and_send",
                                candid::<Option<u64>, _>,
                                (
                                    from_account.to_address(),
                                    from_funds,
                                    to_account.to_address(),
                                    to_funds,
                                    *amount,
                                ),
                            )
                            .await
                            .unwrap()
                            .map(|tip| (tip, from_account, Memo(42)))
                    }
                    Err(keypair) => {
                        let args = TransferArgs {
                            memo: Memo::default(),
                            from_subaccount: None,
                            amount: *amount,
                            fee: DEFAULT_TRANSFER_FEE,
                            to: to_account.to_address(),
                            created_at_time: None,
                        };
                        let result: Result<Result<BlockIndex, TransferError>, String> = ledger
                            .update_from_sender(
                                "transfer",
                                candid_one,
                                args,
                                &Sender::from_keypair(keypair),
                            )
                            .await;
                        if debit <= *from_funds {
                            let from_princ = ed25519_public_to_principal(&keypair.public_key);
                            Some((
                                result.unwrap().unwrap(),
                                AccountIdentifier::new(from_princ, None),
                                Memo::default(),
                            ))
                        } else {
                            assert!(
                                matches!(result, Ok(Err(TransferError::InsufficientFunds { .. }))),
                                "unexpected result: {:?}",
                                result
                            );
                            Option::None
                        }
                    }
                };

                if let Some((tip, from_account, memo)) = block {
                    let trans = obtain_block(&ledger, tip).await;
                    assert_eq!(trans.memo, memo);
                    if let Operation::Transfer {
                        from,
                        to,
                        amount: amnt,
                        fee,
                        ..
                    } = trans.operation
                    {
                        assert_eq!(from, from_account);
                        assert_eq!(to, to_account);
                        assert_eq!(amnt, *amount);
                        assert_eq!(fee, DEFAULT_TRANSFER_FEE);
                    } else {
                        panic!("Encountered {:?}", trans.operation)
                    }
                }
            }
        }
    }
}

/// Given a block height, obtain the corresponding block from
/// the ledger and compare its contents with expectations.
async fn obtain_block(ledger: &Canister<'_>, block: BlockIndex) -> Transaction {
    let BlockRes(result) = ledger
        .query_("block_pb", protobuf, BlockArg(block))
        .await
        .unwrap();

    let block = Block::decode(result.unwrap().unwrap()).expect("unable to decode block");

    block.transaction
}
