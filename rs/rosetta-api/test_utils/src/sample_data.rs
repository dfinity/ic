use ic_ledger_core::block::BlockType;
use ledger_canister::{
    AccountIdentifier, Block, BlockHeight, Memo, Operation, Tokens, Transaction,
    DEFAULT_TRANSFER_FEE,
};

use ic_rosetta_api::store::HashedBlock;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rand_distr::Distribution;
use std::collections::{BTreeMap, VecDeque};
use std::time::SystemTime;

use crate::acc_id;

enum Trans {
    Buy(AccountIdentifier, Tokens),
    Sell(AccountIdentifier, Tokens),
    Transfer(AccountIdentifier, AccountIdentifier, Tokens),
}

pub struct Scribe {
    pub accounts: VecDeque<AccountIdentifier>,
    pub balance_book: BTreeMap<AccountIdentifier, Tokens>,
    pub blockchain: VecDeque<HashedBlock>,
    transactions: VecDeque<Trans>,
    pub balance_history: VecDeque<BTreeMap<AccountIdentifier, Tokens>>,
    rng: StdRng,
}

impl Scribe {
    pub fn new() -> Self {
        Self {
            accounts: VecDeque::new(),
            balance_book: BTreeMap::new(),
            blockchain: VecDeque::new(),
            transactions: VecDeque::new(),
            balance_history: VecDeque::new(),
            rng: StdRng::seed_from_u64(1234),
        }
    }

    pub fn new_with_sample_data(num_accounts: u64, num_transactions: u64) -> Self {
        let mut scribe = Scribe::new();

        scribe.gen_accounts(num_accounts, 1_000_000);
        for _i in 0..num_transactions {
            scribe.gen_transaction();
        }
        scribe
    }

    fn rand_val(&mut self, val: u64, dev: f64) -> u64 {
        let gen = rand_distr::Normal::new(val as f64, val as f64 * dev).unwrap();
        let ret = gen.sample(&mut self.rng).max(0.0);
        ret as u64
    }

    fn dice_num(&mut self, n: u64) -> u64 {
        self.rng.next_u64() % n
    }

    pub fn num_accounts(&self) -> u64 {
        self.accounts.len() as u64
    }

    fn time(&self) -> SystemTime {
        //2010.01.01 1:0:0 + int
        std::time::UNIX_EPOCH
            + std::time::Duration::from_millis(1262307600000 + self.blockchain.len() as u64)
        //std::time::SystemTime::now()
    }

    fn next_message(&self) -> Memo {
        Memo(self.next_index() as u64)
    }

    fn next_index(&self) -> BlockHeight {
        self.blockchain.len() as u64
    }

    pub fn gen_accounts(&mut self, num: u64, balance: u64) {
        let num_accounts = self.num_accounts();
        for i in num_accounts..num_accounts + num {
            let amount = self.rand_val(balance, 0.1);
            let acc = acc_id(i);
            self.accounts.push_back(acc);
            self.balance_book.insert(acc, Tokens::ZERO);
            self.buy(acc, amount);
        }
    }

    pub fn add_account(&mut self, address: &str, balance: u64) {
        let address =
            AccountIdentifier::from_hex(address).expect("Hex was not valid account identifier");
        self.accounts.push_back(address);
        self.balance_book.insert(address, Tokens::ZERO);
        self.buy(address, balance);
    }

    pub fn add_block(&mut self, transaction: Transaction) {
        let parent_hash = self.blockchain.back().map(|hb| hb.hash);
        let index = self.next_index();

        let block = Block::new_from_transaction(parent_hash, transaction, self.time().into());

        self.blockchain
            .push_back(HashedBlock::hash_block(block.encode(), parent_hash, index));
    }

    pub fn buy(&mut self, uid: AccountIdentifier, amount: u64) {
        let amount = Tokens::from_e8s(amount);
        self.transactions.push_back(Trans::Buy(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() += amount;
        let transaction = Transaction {
            operation: Operation::Mint { to: uid, amount },
            memo: self.next_message(),
            created_at_time: self.time().into(),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(transaction);
    }

    pub fn sell(&mut self, uid: AccountIdentifier, amount: u64) {
        let amount = Tokens::from_e8s(amount);
        self.transactions.push_back(Trans::Sell(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() -= amount;
        let transaction = Transaction {
            operation: Operation::Burn { from: uid, amount },
            memo: self.next_message(),
            created_at_time: self.time().into(),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(transaction);
    }

    pub fn transfer(&mut self, src: AccountIdentifier, dst: AccountIdentifier, amount: u64) {
        let amount = Tokens::from_e8s(amount);
        self.transactions
            .push_back(Trans::Transfer(src, dst, amount));
        *self.balance_book.get_mut(&src).unwrap() -= (amount + DEFAULT_TRANSFER_FEE).unwrap();
        *self.balance_book.get_mut(&dst).unwrap() += amount;

        let transaction = Transaction {
            operation: Operation::Transfer {
                from: src,
                to: dst,
                amount,
                fee: DEFAULT_TRANSFER_FEE,
            },
            memo: self.next_message(),
            created_at_time: self.time().into(),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(transaction);
    }

    pub fn get_rand_account(&mut self, min_amount: Tokens) -> AccountIdentifier {
        let mut acc_idx = self.dice_num(self.num_accounts()) as usize;
        let mut acc = self.accounts[acc_idx];
        while *self.balance_book.get(&acc).unwrap() < min_amount {
            acc_idx = self.dice_num(self.num_accounts()) as usize;
            acc = self.accounts[acc_idx];
        }
        acc
    }

    pub fn gen_transfer(&mut self) {
        let x = (1 + self.dice_num(3)) * 100;
        let amount = self.rand_val(x, 0.1);
        let icpt_amount = Tokens::from_e8s(amount);

        let acc1 = self.get_rand_account((icpt_amount + DEFAULT_TRANSFER_FEE).unwrap());
        let mut acc2 = self.get_rand_account(Tokens::ZERO);

        let mut safety_belt = 1000;
        while acc1 == acc2 {
            if safety_belt == 0 {
                panic!("Not enough accounts to chose from");
            }
            acc2 = self.get_rand_account(Tokens::ZERO);
            safety_belt -= 1;
        }
        self.transfer(acc1, acc2, amount);
    }

    pub fn gen_buy(&mut self) {
        let acc = self.get_rand_account(Tokens::ZERO);
        let x = (1 + self.dice_num(3)) * 100;
        let amount = self.rand_val(x, 0.1);
        self.buy(acc, amount)
    }

    pub fn gen_sell(&mut self) {
        let x = (1 + self.dice_num(3)) * 100;
        let amount = self.rand_val(x, 0.1);
        let acc = self.get_rand_account(Tokens::from_e8s(amount));
        self.sell(acc, amount);
    }

    pub fn gen_transaction(&mut self) {
        match self.dice_num(4) {
            0 => self.gen_buy(),
            1 => self.gen_sell(),
            _ => self.gen_transfer(),
        };
    }
}

impl Default for Scribe {
    fn default() -> Self {
        Self::new()
    }
}
