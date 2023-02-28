use secret_toolkit::serialization::Json;
use secret_toolkit::storage::Item;

use crate::msg::{Config, ContractStatusLevel, StakingInfo};

pub const KEY_CONFIG: &[u8] = b"config";
pub const KEY_STAKING_INFO: &[u8] = b"staking_info";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const PREFIX_REVOKED_PERMITS: &str = "revoked_permits";
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);
pub static STAKING_CONFIG: Item<StakingInfo> = Item::new(KEY_STAKING_INFO);
pub static CONFIG: Item<Config> = Item::new(KEY_CONFIG);
