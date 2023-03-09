use cosmwasm_std::{Addr, StdResult, Storage};
use secret_toolkit::storage::Item;
use secret_toolkit::{serialization::Json, storage::Keymap};

use crate::msg::{Config, ContractStatusLevel, StakingInfo};
use crate::staking_interface::Unbonding;

pub const KEY_CONFIG: &[u8] = b"config";
pub const KEY_STAKING_INFO: &[u8] = b"staking_info";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const PREFIX_REVOKED_PERMITS: &str = "revoked_permits";
pub const PREFIX_UNBONDINGS_IDS: &[u8] = b"unbondings_ids";
pub const PREFIX_UNBONDINGS: &[u8] = b"unbondings";
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);
pub static STAKING_CONFIG: Item<StakingInfo> = Item::new(KEY_STAKING_INFO);
pub static CONFIG: Item<Config> = Item::new(KEY_CONFIG);
pub static UNBONDINGS_IDS: Item<Vec<u128>> = Item::new(PREFIX_UNBONDINGS_IDS);
pub static UNBONDING: Keymap<(Addr, u128), Unbonding> = Keymap::new(PREFIX_UNBONDINGS);

pub struct UnbondingIdsStore {}
impl UnbondingIdsStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> Vec<u128> {
        let unbondings_ids = UNBONDINGS_IDS.add_suffix(account.as_str().as_bytes());
        unbondings_ids.load(store).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, ids: Vec<u128>) -> StdResult<()> {
        let unbondings_ids = UNBONDINGS_IDS.add_suffix(account.as_str().as_bytes());
        unbondings_ids.save(store, &ids)
    }
}

pub struct UnbondingStore {}
impl UnbondingStore {
    pub fn may_load(store: &dyn Storage, addr: &Addr, id: u128) -> Option<Unbonding> {
        UNBONDING.get(store, &(addr.clone(), id.clone()))
    }

    pub fn save(
        store: &mut dyn Storage,
        addr: &Addr,
        id: u128,
        unbond: &Unbonding,
    ) -> StdResult<()> {
        UNBONDING.insert(store, &(addr.clone(), id), unbond)
    }

    pub fn remove(store: &mut dyn Storage, addr: &Addr, id: u128) -> StdResult<()> {
        UNBONDING.remove(store, &(addr.clone(), id.clone()))
    }
}
