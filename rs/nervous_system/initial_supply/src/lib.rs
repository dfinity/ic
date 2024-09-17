use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_runtime::Runtime;
use icrc_ledger_types::icrc3::{
    archive::{ArchivedRange, QueryArchiveFn},
    transactions::{
        GetTransactionsRequest, GetTransactionsResponse, Transaction, TransactionRange,
    },
};
use num_bigint::BigUint;
use std::ops::AddAssign;

pub async fn initial_supply_e8s<MyRuntime: Runtime>(
    ledger_canister_id: CanisterId,
    options: InitialSupplyOptions,
) -> Result<u64, String> {
    let InitialSupplyOptions {
        batch_size,
        max_transactions,
    } = options;
    let ledger = ThickLedgerClient::new(ledger_canister_id);

    let mut result = Nat(BigUint::from(0_u64));
    let mut transaction_count: u64 = 0;
    let mut first_timestamp = None;
    'outer: loop {
        let transactions = ledger
            .get_transactions::<MyRuntime>(transaction_count, batch_size)
            .await?;

        if transactions.is_empty() {
            // No more transactions -> Done!
            break;
        }

        for transaction in transactions {
            // Look at timestamp. If != first_timestamp, we are done.
            match first_timestamp {
                None => {
                    first_timestamp = Some(transaction.timestamp);
                }
                Some(first_timestamp) => {
                    if transaction.timestamp != first_timestamp {
                        // Found a non-initial transaction -> Done!
                        break 'outer;
                    }
                }
            }
            debug_assert_eq!(Some(transaction.timestamp), first_timestamp);

            // Bail if this scan seems to go on forever.
            if transaction_count >= max_transactions {
                return Err(format!(
                    "Unable to find the last initial transaction after scanning {} transactions.",
                    transaction_count,
                ));
            }

            // Unpack transaction; it should be a mint.
            let mint = match transaction.mint {
                Some(ok) => ok,
                None => {
                    return Err(format!(
                        "Transaction {} was not a mint, even though it was among the initial transactions: {:#?}",
                        transaction_count, transaction,
                    ));
                }
            };

            // Update running totals.
            result.add_assign(mint.amount);
            transaction_count = transaction_count
                .checked_add(1)
                .ok_or_else(|| "Transaction count overflowed u64.".to_string())?;
        }
    }

    // Convert to return type.
    let result = u64::try_from(result.0).map_err(|err| {
        format!(
            "Failed to convert initial supply in e8s does to u64. Reason: {:?}",
            err,
        )
    })?;

    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub struct InitialSupplyOptions {
    /// Give up if more than this many transactions need to be scanned to come up with a result.
    pub max_transactions: u64,

    /// How many transactions to fetch at a time.
    pub batch_size: u64,
}

impl InitialSupplyOptions {
    /// Sensible values.
    pub fn new() -> Self {
        Self {
            max_transactions: 100_000,
            batch_size: 250,
        }
    }
}

impl Default for InitialSupplyOptions {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Might probably make sense to spin this in its own library.
/// A ledger canister does not hold very old transactions. Instead, it passes
/// old transactions to archive canister(s). Therefore, it is not enough to
/// simply call a ledger canister's get_transactions method. The response can
/// indicate that older records must be fetched from an archive canister.
/// Following those redirects is our main job here.
#[derive(Debug)]
struct ThickLedgerClient {
    ledger_canister_id: CanisterId,
}

impl ThickLedgerClient {
    pub fn new(ledger_canister_id: CanisterId) -> Self {
        Self { ledger_canister_id }
    }

    pub async fn get_transactions<MyRuntime: Runtime>(
        &self,
        start: u64,
        length: u64,
    ) -> Result<Vec<Transaction>, String> {
        let start = Nat::from(start);
        let length = Nat::from(length);
        let request = GetTransactionsRequest {
            start: start.clone(),
            length: length.clone(),
        };

        let (mut response,): (GetTransactionsResponse,) =
            MyRuntime::call_with_cleanup(self.ledger_canister_id, "get_transactions", (request,))
                .await
                .map_err(|err| format!("Failed to call ledger: {:?}", err))?;

        normalize_get_transactions_response(start, &mut response)?;

        let mut result = vec![];
        // Fetch transactions from archive.
        for archived_range in response.archived_transactions {
            let mut transactions = self
                .follow_get_transactions_redirect::<MyRuntime>(archived_range)
                .await
                .map_err(|err| {
                    format!(
                        "Ledger {} (partially) forwarded us (presumably to archive), \
                         but that failed: {}",
                        self.ledger_canister_id, err,
                    )
                })?;
            result.append(&mut transactions);
        }

        result.append(&mut response.transactions);

        Ok(result)
    }

    async fn follow_get_transactions_redirect<MyRuntime: Runtime>(
        &self,
        archived_range: ArchivedRange<QueryArchiveFn<GetTransactionsRequest, TransactionRange>>,
    ) -> Result<Vec<Transaction>, String> {
        type Request = GetTransactionsRequest;
        type Response = TransactionRange;
        type F = QueryArchiveFn<Request, Response>;

        let ArchivedRange::<F> {
            start,
            length,
            callback,
        } = archived_range;

        let F {
            canister_id,
            method,
            _marker: _,
        } = callback;

        let request = Request { start, length };
        let (response,): (Response,) = MyRuntime::call_with_cleanup(
            CanisterId::unchecked_from_principal(PrincipalId::from(canister_id)),
            &method,
            (request,),
        )
        .await
        .map_err(|err| {
            format!(
                "Redirected to the {} method of {}, but calling that method failed: {:?}",
                method, canister_id, err,
            )
        })?;

        Ok(response.transactions)
    }
}

/// Returns Err if the response seems to have gaps.
///
/// Here, normalizing just means that response.archived_transactions is sorted.
fn normalize_get_transactions_response(
    mut start: Nat,
    response: &mut GetTransactionsResponse,
) -> Result<(), String> {
    if start >= response.log_length {
        // These should already be empty, but since we are normalizing right
        // now, let's clear just to be super sure.
        response.transactions.clear();
        response.archived_transactions.clear();

        return Ok(());
    }

    // This is in case archived_transactions is not already sorted. That might
    // be guaranteed already, but I have not seen any such promises in writing.
    // This is really all the normalization going on here. The rest of this
    // function just makes sure that the response is not missing any requested
    // transactions.
    response
        .archived_transactions
        .sort_by_key(|archived_range| archived_range.start.clone());

    for archived_range in &response.archived_transactions {
        if archived_range.start != start {
            return Err(format!(
                "GetTransactionsResponse seems to be missing requested transactions \
                 from {} to ({} - 1). (This is might not be a retry-able failure.)",
                start, archived_range.start,
            ));
        }

        start.add_assign(archived_range.length.clone());
    }

    if response.first_index != start {
        return Err(format!(
            "GetTransactionsResponse seems to be missing requested transactions \
             from {} to ({} - 1). (This is probably not retry-able failure.)",
            start, response.first_index,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
