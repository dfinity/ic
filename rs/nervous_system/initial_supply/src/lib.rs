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
use std::ops::{AddAssign, SubAssign};

pub async fn initial_supply_e8s<MyRuntime: Runtime>(
    ledger_canister_id: CanisterId,
    options: InitialSupplyOptions,
) -> Result<u64, String> {
    let InitialSupplyOptions {
        batch_size,
        max_transactions,
    } = options;
    let ledger = ThickLedgerClient::new(ledger_canister_id);

    const STANDARD_MAX_TRANSACTIONS_PER_LEDGER_RESPONSE: u64 = 2_000;
    let batch_size = batch_size.clamp(
        // batch_size == 0 would lead to an infinite loop, so we don't allow that.
        1,
        // batch_size > the max transactions per ledger_response is something
        // that we cannot handle (yet. This leads to a panic.).
        STANDARD_MAX_TRANSACTIONS_PER_LEDGER_RESPONSE,
    );

    let mut result = Nat(BigUint::from(0_u64));
    let mut transaction_count: u64 = 0;
    let mut first_timestamp = None;
    'outer: loop {
        let transactions = ledger
            .get_transactions::<MyRuntime>(transaction_count, batch_size)
            .await?;

        // This will be used later to determine whether we can break early.
        let len = transactions.len();
        let len = u64::try_from(len).map_err(|err| {
            format!(
                "Unable to convert transactions length ({}) to a u64: {:?}",
                len, err,
            )
        })?;

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

        if len < batch_size {
            // The previous condition tells us that we have scanned ALL
            // transactions.
            //
            // (This is necessary, and not "just" an optimization to avoid the
            // next iteration of the 'outer loop. In particular, if len == 0,
            // then without this, we would never make it past the 'outer loop.)
            //
            // What this means is that the only transactions that currently
            // exist are just the initial minting transactions. This is strange,
            // but not wrong. Normally, we break out of the outer loop when
            // transaction.timestamp != first_timestamp.
            break;
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

    /// How many transactions to fetch at a time. Currently, this needs to be <=
    /// the cap on transactions / response from ledger & archive. The standard
    /// cap is 2_000; whereas, the default batch_size is 250 (see the new
    /// method). Therefore, there is no need to worry about this in the context
    /// of SNS, ICP, and ck*. Otherwise, more care needs to be taken when
    /// setting this.
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

        let (mut response,): (GetTransactionsResponse,) = MyRuntime::call_with_cleanup(
            self.ledger_canister_id,
            "get_transactions",
            (request.clone(),),
        )
        .await
        .map_err(|err| format!("Failed to call ledger: {:?}", err))?;

        normalize_get_transactions_response(&request, &mut response)?;

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

        let request = Request {
            start,
            length: length.clone(),
        };
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

        if response.transactions.len() != length {
            // This could occur if batch_size is too large.
            return Err(format!(
                "{} did not return all the requested transactions: \
                 requested = {} vs. actual = {}",
                canister_id,
                length,
                response.transactions.len(),
            ));
        }

        Ok(response.transactions)
    }
}

/// Returns Err if the response seems to have gaps.
///
/// Here, normalizing just means that response.archived_transactions is sorted.
fn normalize_get_transactions_response(
    request: &GetTransactionsRequest,
    response: &mut GetTransactionsResponse,
) -> Result<(), String> {
    let GetTransactionsRequest {
        mut start,
        mut length,
    } = request.clone();

    if start >= response.log_length {
        // We went past the end of the log. In that case, these fields should
        // already be empty, but since we are normalizing right now, let's clear
        // just to be super sure. Alternatively, we could return Err.
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

    // Scan archived_ranges to make sure they are not missing any transactions
    // that we asked for. In other words, that they are "complete". (This check
    // requires that archived_transactions be sorted, which is ensured by the
    // previous statement.)
    for archived_range in &response.archived_transactions {
        if archived_range.start != start {
            return Err(format!(
                "GetTransactionsResponse seems to be missing requested transactions \
                 from {} to ({} - 1). (This is might not be a retry-able failure.)",
                start, archived_range.start,
            ));
        }

        start.add_assign(archived_range.length.clone());

        // Decrement length by the same amount.
        if length < archived_range.length {
            return Err(format!(
                "An excess of transactions was returned in archived_range: {:?} vs. {:?}",
                request, archived_range,
            ));
        }
        length.sub_assign(archived_range.length.clone());
    }

    // Make sure there is no gap between response.archived_ranges vs. response.transactions.
    if response.first_index != start {
        return Err(format!(
            "GetTransactionsResponse seems to be missing requested transactions \
             from {} to ({} - 1). (This is probably not retry-able failure.)",
            start, response.first_index,
        ));
    }

    // Make sure that the response is not missing transactions at the end of our
    // requested range. More concretely, the length of response.transactions
    // must be maximal: either we got the amount we aked for (i.e. length), or
    // we got all the transactions that exist (at the end of the log). We can
    // remove this if ThickLedgerClient.get_transactions knew how to handle
    // incomplete transactions, which is only a problem with batch_size is too
    // big.
    let available_transactions_count = checked_sub(&response.log_length, &response.first_index)
        .map_err(|_err| {
            format!(
                "Received a GetTransactionsResponse from ledger that is inconsistent: \
         first_index = {}, log_length = {}",
                response.first_index, response.log_length,
            )
        })?;
    let is_last_complete = response.transactions.len() == length.min(available_transactions_count);
    if !is_last_complete {
        return Err(format!(
            "GetTransactionsResponse seems to be missing some requested \
             transactions at the end of our requested range. This might \
             be because batch-size is too large (specifically, greater \
             than the transactions / response cap from ledger): {:?} vs. \
             response.first_index = {}, response.log_length = {}, \
             response.transactions.len() = {}",
            request,
            response.first_index,
            response.log_length,
            response.transactions.len(),
        ));
    }

    Ok(())
}

/// Returns Err when change > base.
///
/// Otherwise, returns Ok(base - change).
///
/// AFAICT, if you try to do 7 - 99 (or similar) with Nats, you will get a
/// panic. This returns Err instead.
///
/// Since Nat does not implement Copy, this takes references to avoid taking the
/// caller's data.
fn checked_sub(base: &Nat, change: &Nat) -> Result<Nat, ()> {
    if change > base {
        return Err(());
    }

    Ok(base.clone() - change.clone())
}

#[cfg(test)]
mod tests;
