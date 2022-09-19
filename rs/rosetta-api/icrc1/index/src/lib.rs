use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap};

use candid::{CandidType, Deserialize, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::endpoints::{ArchivedTransactionRange, TransactionRange};
use ic_icrc1::{
    endpoints::{GetTransactionsRequest, GetTransactionsResponse, Transaction, Transfer},
    Account, Subaccount,
};
use num_traits::cast::ToPrimitive;

// Maximum number of transactions that can be returned
// by [get_account_transactions]
const MAX_TRANSACTIONS_PER_RESPONSE: usize = 1000;

const LOG_PREFIX: &str = "[ic-icrc1-index] ";

type TxId = Nat;
struct Index {
    // The id of the Ledger canister to index
    pub ledger_id: CanisterId,

    // The next txid to query from the Ledger
    pub next_txid: TxId,

    // Whether there is a [heartbeat] running right now
    pub is_heartbeat_running: bool,

    // The index of transactions per account
    pub account_index: BTreeMap<PrincipalId, BTreeMap<Subaccount, Vec<TxId>>>,
}

impl Index {
    fn from(init_args: InitArgs) -> Self {
        Self {
            ledger_id: init_args.ledger_id,
            next_txid: Nat::from(0),
            is_heartbeat_running: false,
            account_index: BTreeMap::new(),
        }
    }
}

thread_local! {
    static INDEX: RefCell<Option<Index>>  = RefCell::new(None);
}

fn with_index<R>(f: impl FnOnce(&Index) -> R) -> R {
    INDEX.with(|idx| f(idx.borrow().as_ref().expect("Index state is not set!")))
}

fn with_index_mut<R>(f: impl FnOnce(&mut Index) -> R) -> R {
    INDEX.with(|idx| f(idx.borrow_mut().as_mut().expect("Index state is not set!")))
}

#[derive(CandidType, Debug, Deserialize)]
pub struct InitArgs {
    // The Ledger canister id of the Ledger to index
    pub ledger_id: CanisterId,
}

pub fn init(init_args: InitArgs) {
    INDEX.with(|idx| *idx.borrow_mut() = Some(Index::from(init_args)));
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetAccountTransactionsArgs {
    pub account: Account,
    // The txid of the last transaction seen by the client.
    // If None then the results will start from the most recent
    // txid.
    pub start: Option<TxId>,
    // Maximum number of transactions to fetch.
    pub max_results: Nat,
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct TransactionWithId {
    pub id: TxId,
    pub transaction: Transaction,
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetTransactions {
    pub transactions: Vec<TransactionWithId>,
    // The txid of the oldest transaction the account has
    pub oldest_tx_id: Option<TxId>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetTransactionsErr {
    pub message: String,
}

pub type GetTransactionsResult = Result<GetTransactions, GetTransactionsErr>;

pub async fn heartbeat() {
    if with_index(|idx| idx.is_heartbeat_running) {
        return;
    }
    with_index_mut(|idx| idx.is_heartbeat_running = true);

    if let Err(err) = build_index().await {
        ic_cdk::eprintln!("{}Failed to fetch blocks: {}", LOG_PREFIX, err);
    }

    with_index_mut(|idx| idx.is_heartbeat_running = false);
}

async fn get_transactions_from_ledger(
    start: Nat,
    length: usize,
) -> Result<GetTransactionsResponse, String> {
    let ledger_id = with_index(|idx| idx.ledger_id);
    let req = GetTransactionsRequest {
        start,
        length: Nat::from(length),
    };
    let (res,): (GetTransactionsResponse,) =
        ic_cdk::call(ledger_id.get().0, "get_transactions", (req,))
            .await
            .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn get_transactions_from_archive(
    archived: &ArchivedTransactionRange,
) -> Result<TransactionRange, String> {
    let req = GetTransactionsRequest {
        start: archived.start.clone(),
        length: archived.length.clone(),
    };
    let (res,): (TransactionRange,) = ic_cdk::call(
        archived.callback.canister_id.get().0,
        &archived.callback.method,
        (req,),
    )
    .await
    .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn build_index() -> Result<(), String> {
    let next_txid = with_index(|idx| idx.next_txid.clone());
    let res = get_transactions_from_ledger(next_txid, MAX_TRANSACTIONS_PER_RESPONSE).await?;
    let mut idx = res.first_index;
    for archived in res.archived_transactions {
        let res = get_transactions_from_archive(&archived).await?;
        for transaction in res.transactions {
            index_transaction(idx.clone(), transaction)?;
            idx += 1u32;
        }
    }
    for transaction in res.transactions {
        index_transaction(idx.clone(), transaction)?;
        idx += 1u32;
    }
    Ok(())
}

fn index_transaction(txid: Nat, transaction: Transaction) -> Result<(), String> {
    match transaction.kind.as_str() {
        "mint" => {
            add_tx(txid, transaction.mint.unwrap().to);
            Ok(())
        }
        "burn" => {
            add_tx(txid, transaction.burn.unwrap().from);
            Ok(())
        }
        "transfer" => {
            let Transfer { from, to, .. } = transaction.transfer.unwrap();
            add_tx(txid.clone(), from);
            add_tx(txid, to);
            Ok(())
        }
        kind => Err(format!("Found transaction of unknown kind {}", kind)),
    }
}

fn add_tx(txid: Nat, account: Account) {
    with_index_mut(|idx| {
        let account_index = match idx.account_index.entry(account.owner) {
            btree_map::Entry::Vacant(v) => v.insert(BTreeMap::new()),
            btree_map::Entry::Occupied(o) => o.into_mut(),
        };
        match account_index.entry(*account.effective_subaccount()) {
            btree_map::Entry::Vacant(v) => {
                let _ = v.insert(vec![txid.clone()]);
            }
            btree_map::Entry::Occupied(o) => o.into_mut().push(txid.clone()),
        };
        idx.next_txid = txid + 1;
    });
}

/// Returns args.max_results transactions ids of the account args.account
/// since args.start.
/// The transactions will be sorted from the most recent to the least recent.
///
/// If arg.start is not set then it represents the max txid. A query with
/// start=None will always return the most recent transaction as first transaction
///
/// Examples [1, 3, 5, 6, 9]:
/// start=None  max_results=3 => [9, 6, 5]  // last 3
/// start=9     max_results=3 => [9, 6, 5]  // last 3 before 10
/// start=5     max_results=2 => [5, 3]     // last 2 after 5
/// start=3     max_results=3 => [3, 1]     // last 3 before 3 but there are only 2 txs
/// start=0     max_results=2 => []         // start is before oldest txid
fn get_account_transactions_ids(args: GetAccountTransactionsArgs) -> Vec<TxId> {
    // The SNS Ledger txid (or block index) is a u64
    if args.start.is_some() && (&args.start).as_ref().unwrap() > &Nat::from(u64::MAX) {
        return vec![];
    }
    let max_results = (&args.max_results)
        .min(&Nat::from(MAX_TRANSACTIONS_PER_RESPONSE))
        .0
        .to_usize()
        .unwrap();
    with_index(|idx| {
        let account_index = match idx.account_index.get(&args.account.owner) {
            Some(account_index) => account_index,
            None => return vec![],
        };
        let txids = match account_index.get(args.account.effective_subaccount()) {
            Some(txids) => txids,
            None => return vec![],
        };
        let start_pos = match &args.start {
            None => txids.len() - 1,
            // binary_search doc:
            // If the value is found then Result::Ok is returned, containing the index
            // of the matching element. ... If the value is not found then Result::Err
            // is returned, containing the index where a matching element could be
            // inserted while maintaining sorted order.
            Some(start) => match txids.binary_search(start) {
                Ok(i) => i,
                Err(i) if i > 0 => i - 1,
                _ => return vec![],
            },
        };
        let end_pos = (start_pos as i64 - max_results as i64 + 1).max(0) as usize;
        (end_pos..=start_pos)
            .rev()
            .map(|pos| txids.get(pos).unwrap().clone())
            .collect()
    })
}

pub async fn get_account_transactions(args: GetAccountTransactionsArgs) -> GetTransactionsResult {
    let txids = get_account_transactions_ids(args);
    let mut txs = vec![];
    for txid in &txids {
        match get_transactions_from_ledger(txid.clone(), 1).await {
            Ok(mut res) => {
                if let Some(tx) = res.transactions.pop() {
                    txs.push(TransactionWithId {
                        id: txid.clone(),
                        transaction: tx,
                    })
                } else if let Some(archive) = res.archived_transactions.get(0) {
                    match get_transactions_from_archive(archive).await {
                        Ok(res) if !res.transactions.is_empty() => txs.push(TransactionWithId {
                            id: txid.clone(),
                            transaction: res.transactions.get(0).unwrap().clone(),
                        }),
                        Ok(_) => {
                            let message = format!("Error fetching transaction {} from archive {}: archive didn't   return the transaction!", txid, archive.callback.canister_id);
                            ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                            return Err(GetTransactionsErr { message });
                        }
                        Err(e) => {
                            let message = format!(
                                "Error fetching transaction {}from archive {}: {}",
                                txid, archive.callback.canister_id, e
                            );
                            ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                            return Err(GetTransactionsErr { message });
                        }
                    }
                }
            }
            Err(e) => {
                let message = format!("Error fetching transaction {}: {}", txid, e);
                ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                return Err(GetTransactionsErr { message });
            }
        }
    }
    Ok(GetTransactions {
        transactions: txs,
        oldest_tx_id: txids.get(0).cloned(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{btree_map, BTreeMap};

    use candid::Nat;
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1::Account;

    use proptest::{option, proptest};

    use crate::{get_account_transactions_ids, GetAccountTransactionsArgs, Index, TxId, INDEX};

    fn n(i: u64) -> Nat {
        Nat::from(i)
    }

    fn account1() -> Account {
        Account {
            owner: PrincipalId::new_anonymous(),
            subaccount: None,
        }
    }

    fn init_state(txids: Vec<(Account, Vec<TxId>)>) {
        INDEX.with(|idx| {
            let mut account_index = BTreeMap::new();
            for (account, new_txids) in txids {
                let account_index = match account_index.entry(account.owner) {
                    btree_map::Entry::Vacant(v) => v.insert(BTreeMap::new()),
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };
                let txids = match account_index.entry(*account.effective_subaccount()) {
                    btree_map::Entry::Vacant(v) => v.insert(vec![]),
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };
                txids.extend(new_txids);
            }
            *idx.borrow_mut() = Some(Index {
                ledger_id: CanisterId::from_u64(42),
                next_txid: Nat::from(0u16),
                is_heartbeat_running: false,
                account_index,
            });
        });
    }

    fn check_get_account_transactions_ids(
        start: Option<u64>,
        max_results: u64,
        expected: Vec<u64>,
    ) {
        let actual = get_account_transactions_ids(GetAccountTransactionsArgs {
            account: account1(),
            start: start.map(|x| n(x)),
            max_results: n(max_results),
        });
        let expected: Vec<Nat> = expected.iter().map(|x| n(*x)).collect();
        assert_eq!(
            actual, expected,
            "start: {:?} max_results: {}",
            start, max_results
        );
    }

    proptest! {
        #[test]
        fn get_account_transactions_ids_no_account_fuzzy(start in option::of(u64::MIN..u64::MAX), max_results in u64::MIN..u64::MAX) {
            init_state(vec![]);
            check_get_account_transactions_ids(start, max_results, vec![]);
        }
    }

    #[test]
    fn get_account_transactions_start_none() {
        init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

        // first element
        check_get_account_transactions_ids(None, 1, vec![9]);

        // first 2 elements
        check_get_account_transactions_ids(None, 2, vec![9, 6]);

        // all elements
        check_get_account_transactions_ids(None, 5, vec![9, 6, 5, 3, 1]);
    }

    proptest! {
        #[test]
        fn get_account_transactions_from_end_fuzzy(max_results in 6u64..) {
            init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

            // max_results > num transactions
            check_get_account_transactions_ids(None, max_results, vec![9, 6, 5, 3, 1]);
        }
    }

    #[test]
    fn get_account_transactions_start_some() {
        init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

        // start matches an existing txid, return that tx
        check_get_account_transactions_ids(Some(3), 1, vec![3]);

        // start matches an existing txid, return that tx with the previous one
        check_get_account_transactions_ids(Some(5), 2, vec![5, 3]);

        // start matches the last txid, return the last tx and the previous one
        check_get_account_transactions_ids(Some(9), 2, vec![9, 6]);

        // start matches the first txid, return that tx
        check_get_account_transactions_ids(Some(1), 2, vec![1]);

        // start doesn't match an existing txid and there is 1 tx that has txid < start, return that
        check_get_account_transactions_ids(Some(2), 1, vec![1]);

        // start doesn't match an existing txid and there are no txs with txid < start
        check_get_account_transactions_ids(Some(0), 1, vec![]);

        // start is bigger than any other txid, return the last tx
        check_get_account_transactions_ids(Some(10), 1, vec![9]);
    }

    proptest! {
        #[test]
        fn get_account_transactions_start_some_fuzzy(max_results in 5u64..) {
            init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

            // all results from each existing txid
            check_get_account_transactions_ids(Some(0), max_results, vec![]);
            check_get_account_transactions_ids(Some(1), max_results, vec![1]);
            check_get_account_transactions_ids(Some(3), max_results, vec![3, 1]);
            check_get_account_transactions_ids(Some(5), max_results, vec![5, 3, 1]);
            check_get_account_transactions_ids(Some(6), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(9), max_results, vec![9, 6, 5, 3, 1]);

            // all results from non-existing txid
            check_get_account_transactions_ids(Some(2), max_results, vec![1]);
            check_get_account_transactions_ids(Some(4), max_results, vec![3, 1]);
            check_get_account_transactions_ids(Some(7), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(8), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(10), max_results, vec![9, 6, 5, 3, 1]);
        }

        #[test]
        fn get_account_transactions_start_some_fuzzy_out_of_range(max_results in 0u64..) {
            init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

            // start = 0 so the results must always be empty
            check_get_account_transactions_ids(Some(0), max_results, vec![]);
        }
    }

    proptest! {
        #[test]
        fn get_account_transactions_check_panics(start in option::of(0u64..), max_results in u64::MIN..u64::MAX) {
            init_state(vec![(account1(), vec![n(1), n(3), n(5), n(6), n(9)])]);

            get_account_transactions_ids(GetAccountTransactionsArgs {
                account: account1(),
                start: start.map(|x| n(x)),
                max_results: n(max_results)
            });
        }
    }
}
