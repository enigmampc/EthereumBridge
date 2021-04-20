use bincode2;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{
    CanonicalAddr, HumanAddr, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::storage::{AppendStore, AppendStoreMut};
use serde::de::DeserializeOwned;
use std::any::type_name;

pub static CONFIG_KEY: &[u8] = b"config";
pub static TOKEN_NAMESPACE: &[u8] = b"TokenContractParams";
pub static WHITELIST_KEY: &[u8] = b"Whitelist";
pub static SWAP_KEY: &[u8] = b"swap";
pub static MINT_KEY: &[u8] = b"mint";

fn set_bin_data<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], data: &T) -> StdResult<()> {
    let bin_data =
        bincode2::serialize(&data).map_err(|e| StdError::serialize_err(type_name::<T>(), e))?;

    storage.set(key, &bin_data);
    Ok(())
}

fn get_bin_data<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    let bin_data = storage.get(key);

    match bin_data {
        None => Err(StdError::not_found("Key not found in storage")),
        Some(bin_data) => Ok(bincode2::deserialize::<T>(&bin_data)
            .map_err(|e| StdError::serialize_err(type_name::<T>(), e))?),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct Mint {
    pub identifier: String,
    pub amount: Uint128,
    pub address: CanonicalAddr,
}

impl Mint {
    /// store
    ///
    /// appends a mint message to contract storage. Will return an Ok() if mint is unique and stored successfully
    /// Err() if the store failed, or if the mint already exists
    pub fn store<S: Storage>(&self, store: &mut S) -> StdResult<()> {
        let exists = Self::exists(store, &self.identifier);
        if exists {
            return Err(StdError::generic_err("Mint already exists"));
        }

        let mut store = PrefixedStorage::new(MINT_KEY, store);

        //let mut store = AppendStoreMut::attach_or_create(&mut store)?;
        //store.set(&self.identifier.into_bytes(), set_bin_data);
        set_bin_data(&mut store, self.identifier.as_bytes(), self);
        // if exists.is_ok() && exists.unwrap() {
        //     return Err(StdError::generic_err("Mint already exists"));
        // }
        //
        // store.push(self)?;
        Ok(())
    }

    pub fn exists<S: ReadonlyStorage>(storage: &S, key: &String) -> bool {
        let store = ReadonlyPrefixedStorage::new(MINT_KEY, storage);

        // Try to access the storage of txs for the account.
        // If it doesn't exist yet, return an empty list of transfers.
        store.get(key.as_bytes()).is_some()

        // let store = if let Some(result) = AppendStore::<Self, _>::attach(&store) {
        //     result?
        // } else {
        //     return Ok(false);
        // };
        //
        // for s in store.iter() {
        //     if &s?.identifier == key {
        //         return Ok(true);
        //     }
        // }
        //
        // return Ok(false);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct Swap {
    pub destination: String,
    pub source: String,
    pub amount: Uint128,
    pub token: HumanAddr,
    pub nonce: u32,
}

impl Swap {
    pub fn store<S: Storage>(&mut self, store: &mut S) -> StdResult<u32> {
        let mut store_name = SWAP_KEY.to_vec();
        store_name.extend_from_slice(self.token.0.as_bytes());

        let mut store = PrefixedStorage::new(&store_name, store);
        let mut store = AppendStoreMut::attach_or_create(&mut store)?;

        let nonce = store.len();
        self.nonce = nonce;
        store.push(self)?;
        Ok(nonce)
    }

    pub fn get<S: ReadonlyStorage>(storage: &S, token: &HumanAddr, key: u32) -> StdResult<Self> {
        let mut store_name = SWAP_KEY.to_vec();
        store_name.extend_from_slice(token.0.as_bytes());

        let store = ReadonlyPrefixedStorage::new(&store_name, storage);

        // Try to access the storage of txs for the account.
        // If it doesn't exist yet, return an empty list of transfers.
        let store = AppendStore::<Self, _>::attach(&store)
            .unwrap_or_else(|| Err(StdError::generic_err("")))?;

        store.get_at(key)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct Contract {
    pub address: CanonicalAddr,
    pub minimum_amount: Uint128,
}

impl PartialEq for Contract {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }

    fn ne(&self, other: &Self) -> bool {
        self.address != other.address
    }
}

//
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, JsonSchema)]
pub struct TokenWhiteList {
    pub tokens: Vec<Contract>,
}

impl TokenWhiteList {
    pub fn new<S: Storage>(store: &mut S) -> StdResult<()> {
        let mut store = PrefixedStorage::new(TOKEN_NAMESPACE, store);

        let whitelist = Self::default();

        let bin_data =
            bincode2::serialize(&whitelist).map_err(|e| StdError::serialize_err("", e))?;

        store.set(WHITELIST_KEY, &bin_data);
        Ok(())
    }

    pub fn add<S: Storage>(store: &mut S, token: &Contract) -> StdResult<()> {
        let mut store = PrefixedStorage::new(TOKEN_NAMESPACE, store);

        if let Some(bytes) = &store.get(WHITELIST_KEY) {
            let mut whitelist: TokenWhiteList =
                bincode2::deserialize(bytes).map_err(|e| StdError::serialize_err("", e))?;

            if whitelist.tokens.contains(token) {
                return Ok(());
            }

            whitelist.tokens.push(token.clone());

            let bin_data =
                bincode2::serialize(&whitelist).map_err(|e| StdError::serialize_err("", e))?;

            store.set(WHITELIST_KEY, &bin_data);
        }
        Ok(())
    }

    pub fn remove<S: Storage>(store: &mut S, address: &CanonicalAddr) -> StdResult<()> {
        let mut store = PrefixedStorage::new(TOKEN_NAMESPACE, store);

        if let Some(bytes) = &store.get(WHITELIST_KEY) {
            let mut whitelist: TokenWhiteList =
                bincode2::deserialize(bytes).map_err(|e| StdError::serialize_err("", e))?;

            if let Some(pos) = whitelist
                .tokens
                .iter()
                .position(|x| &(*x).address == address)
            {
                whitelist.tokens.remove(pos);
            }

            let bin_data =
                bincode2::serialize(&whitelist).map_err(|e| StdError::serialize_err("", e))?;

            store.set(WHITELIST_KEY, &bin_data);
        }

        Ok(())
    }

    pub fn get<S: ReadonlyStorage>(storage: &S, address: &CanonicalAddr) -> StdResult<Contract> {
        let store = ReadonlyPrefixedStorage::new(TOKEN_NAMESPACE, storage);

        // Try to access the storage of txs for the account.
        // If it doesn't exist yet, return an empty list of transfers.
        if let Some(bytes) = &store.get(WHITELIST_KEY) {
            let whitelist: TokenWhiteList =
                bincode2::deserialize(bytes).map_err(|e| StdError::serialize_err("", e))?;

            if let Some(pos) = whitelist
                .tokens
                .iter()
                .position(|x| &(*x).address == address)
            {
                return Ok(whitelist.tokens.get(pos).unwrap().clone());
            }
        }

        Err(StdError::not_found("Token address not in whitelist"))
    }

    pub fn all<S: ReadonlyStorage>(storage: &S) -> StdResult<Vec<Contract>> {
        let store = ReadonlyPrefixedStorage::new(TOKEN_NAMESPACE, storage);

        // Try to access the storage of txs for the account.
        // If it doesn't exist yet, return an empty list of transfers.

        if let Some(bytes) = &store.get(WHITELIST_KEY) {
            let whitelist: TokenWhiteList =
                bincode2::deserialize(bytes).map_err(|e| StdError::serialize_err("", e))?;
            return Ok(whitelist.tokens);
        }
        Ok(vec![])
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub owner: HumanAddr,
    pub paused: bool,
}

pub fn config<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}
