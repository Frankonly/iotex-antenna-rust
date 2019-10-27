use super::*;
use crate::address::{v1::AddrV1, Address};
use std::collections::HashMap;

pub struct accounts {
    accounts: HashMap<String, account>,
}

impl accounts {
    // new_accounts return Accounts instance
    pub fn new_accounts() -> accounts {
        let accounts = HashMap::new();
        accounts { accounts: accounts }
    }
    // create new account
    pub fn create(&mut self) -> Result<account, AccountError> {
        match account::new_account() {
            Ok(acc) => {
                self.accounts.insert(acc.address().string(), acc);
                Ok(acc)
            }
            Err(e) => Err(e),
        }
    }
    // get_account by address
    pub fn get_account(&self, addr: AddrV1) -> Option<account> {
        match self.accounts.get(&addr.string()) {
            Some(acc) => Some(*acc),
            None => None,
        }
    }
    // add_account add an account
    pub fn add_account(&mut self, acc: account) -> Option<AccountError> {
        match self.get_account(acc.address()) {
            Some(_) => return Some(AccountError::AccountExist(acc)),
            None => {
                self.accounts.insert(acc.address().string(), acc);
                None
            }
        }
    }
    // remove_account removes an account
    pub fn remove_account(&mut self, addr: AddrV1) {
        self.accounts.remove(&addr.string());
    }
}
