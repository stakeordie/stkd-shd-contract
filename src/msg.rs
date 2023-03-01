#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Binary, StdError, StdResult, Uint128, Uint256};
use secret_toolkit::permit::Permit;

#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Config {
    pub name: String,
    pub admin: Addr,
    pub symbol: String,
    pub contract_address: Addr,
}

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
pub struct FeeInfo {
    pub collector: Addr,
    pub fee_rate: u32,
}

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct ContractInfo {
    pub address: Addr,
    #[serde(default)]
    pub code_hash: String,
    // Optional entropy use to any transaction required to execute in this contract
    pub entropy: Option<String>,
}

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct StakingInfo {
    // Staking contract (SHADE-CUSTOM) information
    pub staking_contract_info: ContractInfo,
    pub staking_contract_vk: String,
    // Staking authentication contract (SHADE-CUSTOM) information
    pub authentication_contract_info: ContractInfo,
    // SHD (SNIP-20) information
    pub shade_contract_info: ContractInfo,
    pub shade_contract_vk: String,
    // Derivative SNIP-20
    pub derivative_contract_info: ContractInfo,
    // Amount of SHD unbonded waiting to be claim by users
    pub unbonded: u128,
    // Fee collector and rate information
    pub fee_info: FeeInfo,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub admin: Option<String>,
    pub symbol: String,
    pub prng_seed: Binary,
    pub staking_contract_info: ContractInfo,
    pub authentication_contract_info: ContractInfo,
    pub derivative_contract_info: ContractInfo,
    pub shade_contract_info: ContractInfo,
    pub fee_info: FeeInfo,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    //Receiver interface
    Receive {
        sender: Addr,
        from: Addr,
        amount: Uint256,
        #[serde(default)]
        msg: Option<Binary>,
    },
    ChangeAdmin {
        address: String,
        padding: Option<String>,
    },
    SetContractStatus {
        level: ContractStatusLevel,
        padding: Option<String>,
    },
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },
    RevokePermit {
        permit_name: String,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    Stake {
        /// amount of SHD staked
        shd_staked: Uint128,
        /// amount of derivative token minted
        tokens_returned: Uint128,
    },
    CreateViewingKey {
        key: String,
    },
    SetViewingKey {
        status: ResponseStatus,
    },
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
    // Permit
    RevokePermit {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    ContractStatus {},
    WithPermit {
        permit: Permit,
        query: QueryWithPermit,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryWithPermit {}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    ContractStatus { status: ContractStatusLevel },
    ViewingKeyError { msg: String },
}

#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatusLevel {
    NormalRun,
    StopAll,
}

pub fn status_level_to_u8(status_level: ContractStatusLevel) -> u8 {
    match status_level {
        ContractStatusLevel::NormalRun => 0,
        ContractStatusLevel::StopAll => 1,
    }
}

pub fn u8_to_status_level(status_level: u8) -> StdResult<ContractStatusLevel> {
    match status_level {
        0 => Ok(ContractStatusLevel::NormalRun),
        1 => Ok(ContractStatusLevel::StopAll),
        _ => Err(StdError::generic_err("Invalid state level")),
    }
}
