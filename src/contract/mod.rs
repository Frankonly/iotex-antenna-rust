use super::{
    account, address,
    crypto::{self, key},
};
use ethabi;

#[derive(Copy, Clone, Debug)]
pub struct Data {
    method: string,
    abi: ethabi::Contract,
    Raw: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub struct Contract {
    address: address::v1::AddrV1,
    abi: ethabi::Contract,
    // api:
    account: account::account,
}
