use crate::contract::RESPONSE_BLOCK_SIZE;
use cosmwasm_std::{to_binary, CosmosMsg, StdResult, Uint128, WasmMsg};
use secret_toolkit::utils::space_pad;
use serde::Serialize;

// HANDLES
#[derive(Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // Messages allowed when sending SHD to Staking contract
    // Deposit rewards to be distributed
    Stake {},
}

// Staking contract handles
#[derive(Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StakingMsg {
    // Claims rewards generated
    Claim {},
    // Unbond X amount
    Unbond { amount: Uint128 },
    // Claims mature unbondings
    Withdraw {},
    // Claims available rewards and re-stake them
    Compound {},
}

impl StakingMsg {
    /// Returns a StdResult<CosmosMsg> used to execute a contract function
    ///
    /// # Arguments
    ///
    /// * `callback_code_hash` - String holding the code hash of the contract being called
    /// * `contract_addr` - address of the contract being called
    /// * `send_amount` - Optional Uint128 amount of native coin to send with the callback message
    ///                 NOTE: Only a Deposit message should have an amount sent with it
    pub fn to_cosmos_msg(&self, code_hash: String, contract_addr: String) -> StdResult<CosmosMsg> {
        let mut msg = to_binary(self)?;
        space_pad(&mut msg.0, RESPONSE_BLOCK_SIZE);
        let funds = Vec::new();
        let execute = WasmMsg::Execute {
            contract_addr,
            code_hash,
            msg,
            funds,
        };
        Ok(execute.into())
    }
}

/// Returns a StdResult<CosmosMsg> used to execute Claim
/// Claims all rewards generated on the Staking Contract
/// # Arguments
/// * `callback_code_hash` - String holding the code hash of the contract being called
/// * `contract_addr` - address of the contract being called
pub fn claim_rewards_msg(
    callback_code_hash: String,
    contract_addr: String,
) -> StdResult<CosmosMsg> {
    StakingMsg::Claim {}.to_cosmos_msg(callback_code_hash, contract_addr)
}

/// Returns a StdResult<CosmosMsg> used to execute Unbond
/// Unbonds X amount; This can later be claim with a "withdraw" message
/// # Arguments
/// * `amount` - amount of SHD to unbond
/// * `callback_code_hash` - String holding the code hash of the contract being called
/// * `contract_addr` - address of the contract being called
pub fn unbond_msg(
    amount: Uint128,
    callback_code_hash: String,
    contract_addr: String,
) -> StdResult<CosmosMsg> {
    StakingMsg::Unbond { amount }.to_cosmos_msg(callback_code_hash, contract_addr)
}

/// Returns a StdResult<CosmosMsg> used to execute Withdraw
/// Claims any mature unbondings
/// # Arguments
/// * `callback_code_hash` - String holding the code hash of the contract being called
/// * `contract_addr` - address of the contract being called
pub fn withdraw_msg(callback_code_hash: String, contract_addr: String) -> StdResult<CosmosMsg> {
    StakingMsg::Withdraw {}.to_cosmos_msg(callback_code_hash, contract_addr)
}

/// Returns a StdResult<CosmosMsg> used to execute Compound
/// Claims available rewards and re-stake them
/// # Arguments
/// * `callback_code_hash` - String holding the code hash of the contract being called
/// * `contract_addr` - address of the contract being called
pub fn compound_msg(callback_code_hash: String, contract_addr: String) -> StdResult<CosmosMsg> {
    StakingMsg::Compound {}.to_cosmos_msg(callback_code_hash, contract_addr)
}
