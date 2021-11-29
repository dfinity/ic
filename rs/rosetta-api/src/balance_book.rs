use crate::errors::ApiError;
use ledger_canister::{AccountIdentifier, BalancesStore, BlockHeight, Tokens};
use std::collections::HashMap;

pub type BalanceBook = ledger_canister::Balances<ClientBalancesStore>;

const EMPTY_HISTORY: [(BlockHeight, Tokens); 0] = [];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceHistory {
    // TODO consider switching to VecDeque, to have more efficient pruning
    // Unfortunately binary_search on VecDeque is only available on nightly,
    // so we would need to add our implementation

    // Note: If num_pruned > 0, the first entry in inner has a slightly
    // different meaning -- it corresponds to the oldest information
    // about this account, but the block at that height does not
    // necessary involve a transaction on this account
    inner: Vec<(BlockHeight, Tokens)>,
    pub num_pruned_transactions: usize,
}

impl Default for BalanceHistory {
    fn default() -> Self {
        Self {
            inner: Vec::default(),
            num_pruned_transactions: 0,
        }
    }
}

impl BalanceHistory {
    // Add new entry or overwrite a present one.
    // Panics if new height < last_entry().height
    pub fn insert(&mut self, height: BlockHeight, amount: Tokens) {
        #[allow(clippy::comparison_chain)]
        if let Some((h, a)) = self.inner.last_mut() {
            if *h > height {
                panic!(
                    "Attempt to insert balance at height {}, when previous recorded height is already {}",
                    height, *h
                );
            } else if *h == height {
                *a = amount;
                return;
            }
        }
        self.inner.push((height, amount));
    }

    pub fn get_at(&self, height: BlockHeight) -> Result<Tokens, ApiError> {
        // after prunning we always have at least one entry
        if self.num_pruned_transactions > 0 && self.inner.first().unwrap().0 > height {
            // TODO Add a new error type (ApiError::BlockPruned or something like that)
            return Err(ApiError::InvalidBlockId(
                false,
                format!(
                    "Block not available for query: {}. Oldest block: {}",
                    height,
                    self.inner.first().unwrap().0
                )
                .into(),
            ));
        }
        let idx = match self.inner.binary_search_by_key(&height, |&(h, _)| h) {
            Ok(i) => i,
            Err(i) => {
                if i == 0 {
                    return Ok(Tokens::ZERO);
                }
                i - 1
            }
        };
        let (_h, a) = self.inner.get(idx).expect("Binary search went wrong");
        // sanity check
        if let Some((nh, _)) = self.inner.get(idx + 1) {
            assert!(
                height < *nh,
                "Wrong height in balance history {} {}",
                height,
                *nh
            );
        }
        assert!(
            height >= *_h,
            "Wrong height in balance history {} {}",
            height,
            *_h
        );
        Ok(*a)
    }

    pub fn get_last(&self) -> Tokens {
        self.inner
            .last()
            .cloned()
            .map(|(_h, a)| a)
            .unwrap_or_else(|| Tokens::ZERO)
    }

    pub fn get_last_ref(&self) -> Option<&Tokens> {
        self.inner.last().map(|(_h, a)| a)
    }

    pub fn prune_at(&mut self, height: BlockHeight) {
        let idx = match self.inner.binary_search_by_key(&height, |&(h, _)| h) {
            Ok(i) => i,
            Err(i) => {
                if i == 0 {
                    return;
                }
                i - 1
            }
        };
        assert!(idx <= self.inner.len()); // sanity check. can never happen
        let mut trimmed = self.inner.split_off(idx);
        if self.num_pruned_transactions == 0 {
            // this is a special case of the first pruning on this account
            // the first entry becomes a pruned entry even if it survives
            // the split_off
            self.num_pruned_transactions = 1;
        }

        self.num_pruned_transactions += self.inner.len();
        let (bh, _amount) = trimmed.first_mut().unwrap();
        *bh = height;
        self.inner = trimmed;
    }

    pub fn get_history(&self, max_block: Option<BlockHeight>) -> &[(BlockHeight, Tokens)] {
        let end = if let Some(height) = max_block {
            match self.inner.binary_search_by_key(&height, |&(h, _)| h) {
                Ok(i) => i + 1,
                Err(i) => i,
            }
        } else {
            self.inner.len()
        };

        let start = if self.num_pruned_transactions == 0 {
            0
        } else {
            1
        };
        let end = std::cmp::max(end, start);

        &self.inner[start..end]
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ClientBalancesStore {
    pub acc_to_hist: HashMap<AccountIdentifier, BalanceHistory>,
    pub transaction_context: Option<BlockHeight>,
}

impl ClientBalancesStore {
    pub fn insert(&mut self, acc: AccountIdentifier, height: BlockHeight, amount: Tokens) {
        self.acc_to_hist
            .entry(acc)
            .or_default()
            .insert(height, amount);
    }

    pub fn get_at(&self, acc: AccountIdentifier, height: BlockHeight) -> Result<Tokens, ApiError> {
        self.acc_to_hist
            .get(&acc)
            .map(|hist| hist.get_at(height))
            .unwrap_or_else(|| Ok(Tokens::ZERO))
    }

    pub fn prune_at(&mut self, height: BlockHeight) {
        for hist in self.acc_to_hist.values_mut() {
            hist.prune_at(height);
        }
    }

    pub fn get_history(
        &self,
        acc: &AccountIdentifier,
        max_block: Option<BlockHeight>,
    ) -> &[(BlockHeight, Tokens)] {
        self.acc_to_hist
            .get(acc)
            .map(|hist| hist.get_history(max_block))
            .unwrap_or_else(|| &EMPTY_HISTORY)
    }
}

impl BalancesStore for ClientBalancesStore {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&Tokens> {
        self.acc_to_hist.get(k).and_then(|hist| hist.get_last_ref())
    }

    // In here, ledger removes zero amount accounts from it's map,
    // but we can't do that or we may risk giving incorrect
    // historical balance information
    fn update<F, E>(&mut self, k: AccountIdentifier, mut f: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>,
    {
        let index = self
            .transaction_context
            .expect("Transaction context missing");
        let acc_hist = self.acc_to_hist.entry(k).or_default();
        let last_balance = acc_hist.get_last_ref();
        let new_balance = f(last_balance)?;
        acc_hist.insert(index, new_balance);
        Ok(new_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_history() {
        let mut hist = BalanceHistory::default();
        assert_eq!(hist.get_last(), Tokens::ZERO);
        assert_eq!(hist.get_at(4), Ok(Tokens::ZERO));

        hist.insert(1, Tokens::from_e8s(1));
        hist.insert(2, Tokens::from_e8s(2));
        hist.insert(4, Tokens::from_e8s(4));
        hist.insert(10, Tokens::from_e8s(10));

        assert_eq!(hist.get_last(), Tokens::from_e8s(10));
        assert_eq!(hist.get_at(0), Ok(Tokens::from_e8s(0)));
        assert_eq!(hist.get_at(1), Ok(Tokens::from_e8s(1)));
        assert_eq!(hist.get_at(2), Ok(Tokens::from_e8s(2)));
        assert_eq!(hist.get_at(3), Ok(Tokens::from_e8s(2)));
        assert_eq!(hist.get_at(4), Ok(Tokens::from_e8s(4)));
        assert_eq!(hist.get_at(5), Ok(Tokens::from_e8s(4)));
        assert_eq!(hist.get_at(7), Ok(Tokens::from_e8s(4)));
        assert_eq!(hist.get_at(9), Ok(Tokens::from_e8s(4)));
        assert_eq!(hist.get_at(10), Ok(Tokens::from_e8s(10)));
        assert_eq!(hist.get_at(100), Ok(Tokens::from_e8s(10)));
        assert_eq!(hist.get_history(Some(100)).len(), 4);
        assert_eq!(hist.get_history(None).len(), 4);
        assert_eq!(hist.get_history(Some(10)).len(), 4);
        assert_eq!(hist.get_history(Some(9)).len(), 3);

        hist.prune_at(2);
        assert!(hist.get_at(0).is_err());
        assert!(hist.get_at(1).is_err());
        assert_eq!(hist.get_at(2), Ok(Tokens::from_e8s(2)));
        assert_eq!(hist.get_at(100), Ok(Tokens::from_e8s(10)));
        assert_eq!(hist.num_pruned_transactions, 2);
        hist.prune_at(2);
        assert_eq!(hist.num_pruned_transactions, 2);
        assert_eq!(hist.get_history(Some(10)).len(), 2);
        assert_eq!(hist.get_history(Some(0)).len(), 0);

        hist.prune_at(3);
        assert!(hist.get_at(2).is_err());
        assert_eq!(hist.get_at(3), Ok(Tokens::from_e8s(2)));
        assert_eq!(hist.num_pruned_transactions, 2);

        let mut hist = BalanceHistory::default();
        hist.insert(0, Tokens::from_e8s(100));
        hist.insert(4, Tokens::from_e8s(104));
        assert_eq!(hist.get_at(1), Ok(Tokens::from_e8s(100)));
        assert_eq!(hist.get_history(Some(0)).len(), 1);

        hist.prune_at(0);
        assert_eq!(hist.get_at(0), Ok(Tokens::from_e8s(100)));
        assert_eq!(hist.get_at(1), Ok(Tokens::from_e8s(100)));
        assert_eq!(hist.num_pruned_transactions, 1);
        assert_eq!(hist.get_history(Some(0)).len(), 0);

        hist.prune_at(1);
        assert!(hist.get_at(0).is_err());
        assert_eq!(hist.get_at(1), Ok(Tokens::from_e8s(100)));
        assert_eq!(hist.num_pruned_transactions, 1);

        hist.prune_at(100);
        assert_eq!(hist.num_pruned_transactions, 2);
        assert!(hist.get_at(99).is_err());
        assert_eq!(hist.get_at(100), Ok(Tokens::from_e8s(104)));
    }
}
