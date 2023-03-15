#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Api, Binary, StdError, StdResult, Uint128, Uint256};
use secret_toolkit::permit::Permit;
use shade_protocol::Contract;

use crate::staking_interface::Unbonding;

#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Config {
    pub name: String,
    pub symbol: String,
    pub contract_address: Addr,
    pub admin_contract_info: Contract,
}

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
pub struct Fee {
    pub collector: Addr,
    pub rate: u32,
    pub decimal_places: u8,
}

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
pub struct FeeInfo {
    pub staking_fee: Fee,
    pub unbonding_fee: Fee,
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
    // Amount of available SHD to be claim by users
    pub unbonded: u128,
    // Fee collector and rate information
    pub fee_info: FeeInfo,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub symbol: String,
    pub prng_seed: Binary,
    pub staking_contract_info: ContractInfo,
    pub authentication_contract_info: ContractInfo,
    pub derivative_contract_info: ContractInfo,
    pub shade_contract_info: ContractInfo,
    pub admin_contract_info: Contract,
    pub fee_info: FeeInfo,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    UpdateFees {
        staking_fee: Option<Fee>,
        unbonding_fee: Option<Fee>,
    },
    PanicUnbond {
        amount: Uint128,
    },
    PanicWithdraw {
        ids: Option<Vec<Uint128>>,
    },
    //Receiver interface
    Receive {
        sender: Addr,
        from: Addr,
        amount: Uint256,
        #[serde(default)]
        msg: Option<Binary>,
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
    /// redeem derivative tokens to unbond SCRT
    Unbond {
        /// amount of derivative tokens redeemed
        tokens_redeemed: Uint128,
        /// amount of shd to be unbonded
        shd_to_be_received: Uint128,
        /// estimated time of maturity
        estimated_time_of_maturity: Uint128,
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
    UpdateFees {
        status: ResponseStatus,
        fee: FeeInfo,
    },
    // Permit
    RevokePermit {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverMsg {
    Stake {},
    Unbond {},
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    StakingInfo {},
    FeeInfo {},
    ContractStatus {},
    Unbondings {
        address: Addr,
        viewing_key: String,
    },
    WithPermit {
        permit: Permit,
        query: QueryWithPermit,
    },
}

impl QueryMsg {
    pub fn get_validation_params(&self, api: &dyn Api) -> StdResult<(Vec<Addr>, String)> {
        match self {
            Self::Unbondings {
                address,
                viewing_key,
            } => {
                let address = api.addr_validate(address.as_str())?;
                Ok((vec![address], viewing_key.clone()))
            }
            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryWithPermit {
    Unbondings {},
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    Unbondings {
        unbonds: Vec<Unbonding>,
    },
    StakingInfo {
        /// unbonding time
        unbonding_time: Uint128,
        /// amount of bonded SHD
        bonded_shd: Uint128,
        /// amount of available SHD not reserved for mature unbondings
        available_shd: Uint128,
        /// unclaimed staking rewards
        rewards: Uint128,
        /// total supply of derivative token
        total_derivative_token_supply: Uint128,
        /// price of derivative token in SHD to 6 decimals
        price: Uint128,
    },
    FeeInfo {
        staking_fee: Fee,
        unbonding_fee: Fee,
    },
    ContractStatus {
        status: ContractStatusLevel,
    },
    ViewingKeyError {
        msg: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InProcessUnbonding {
    pub id: Uint128,
    pub owner: Addr,
    pub amount: Uint128,
    pub complete: Uint128,
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
