use crate::msg::{Config, InProcessUnbonding, ReceiverMsg, StakingInfo};
use crate::msg::{
    ContractStatusLevel, ExecuteAnswer, ExecuteMsg, InstantiateMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};

#[allow(unused_imports)]
use crate::staking_interface::{
    balance_query as staking_balance_query, claim_rewards_msg, config_query, rewards_query, Action,
    RawContract, StakingConfig,
};
use crate::staking_interface::{unbond_msg, withdraw_msg, UnbondResponse, Unbonding};
use crate::state::{
    UnbondingIdsStore, UnbondingStore, CONFIG, CONTRACT_STATUS, PENDING_UNBONDING,
    PREFIX_REVOKED_PERMITS, RESPONSE_BLOCK_SIZE, STAKING_CONFIG, UNBOND_REPLY_ID,
};
/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    entry_point, from_binary, to_binary, Addr, Binary, CosmosMsg, CustomQuery, Deps, DepsMut, Env,
    MessageInfo, QuerierWrapper, Reply, Response, StdError, StdResult, Storage, SubMsg,
    SubMsgResult, Uint128, Uint256,
};
use secret_toolkit::permit::RevokedPermits;
use secret_toolkit::snip20::burn_msg;
#[allow(unused_imports)]
use secret_toolkit::snip20::{
    balance_query, mint_msg, register_receive_msg, send_msg, set_viewing_key_msg, token_info_query,
    TokenInfo,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};
use secret_toolkit_crypto::{sha_256, Prng};
#[allow(unused_imports)]
use shade_protocol::admin::helpers::{validate_admin, AdminPermissions};
#[allow(unused_imports)]
use shade_protocol::Contract;

use crate::msg::{Fee, FeeInfo};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,20}",
        ));
    }

    CONFIG.save(
        deps.storage,
        &Config {
            name: msg.name,
            symbol: msg.symbol,
            contract_address: env.contract.address.clone(),
            admin_contract_info: msg.admin_contract_info,
        },
    )?;
    CONTRACT_STATUS.save(deps.storage, &ContractStatusLevel::NormalRun)?;
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);
    ViewingKey::set_seed(deps.storage, &sha_256(&prng_seed_hashed));
    // Generate viewing key for staking contract
    let entropy: String = msg
        .staking_contract_info
        .entropy
        .clone()
        .unwrap_or_else(|| msg.prng_seed.to_string());
    let (staking_contract_vk, new_seed) =
        new_viewing_key(&info.sender, &env, &msg.prng_seed.0, entropy.as_ref());

    // Generate viewing key for SHD contract
    let entropy: String = msg
        .shade_contract_info
        .entropy
        .clone()
        .unwrap_or_else(|| msg.prng_seed.to_string());
    let (shade_contract_vk, _new_seed) =
        new_viewing_key(&info.sender, &env, &new_seed, entropy.as_ref());

    STAKING_CONFIG.save(
        deps.storage,
        &StakingInfo {
            staking_contract_vk: staking_contract_vk.clone(),
            shade_contract_vk: shade_contract_vk.clone(),
            authentication_contract_info: msg.authentication_contract_info.clone(),
            shade_contract_info: msg.shade_contract_info.clone(),
            derivative_contract_info: msg.derivative_contract_info.clone(),
            staking_contract_info: msg.staking_contract_info,
            fee_info: msg.fee_info,
            unbonded: 0,
        },
    )?;

    let msgs: Vec<CosmosMsg> = vec![
        // Register receive Derivative contract needed for Unbond functionality
        register_receive_msg(
            env.contract.code_hash.clone(),
            msg.derivative_contract_info.entropy.clone(),
            RESPONSE_BLOCK_SIZE,
            msg.derivative_contract_info.code_hash.clone(),
            msg.derivative_contract_info.address.to_string(),
        )?,
        // Register receive SHD contract
        register_receive_msg(
            env.contract.code_hash,
            msg.shade_contract_info.entropy.clone(),
            RESPONSE_BLOCK_SIZE,
            msg.shade_contract_info.code_hash.clone(),
            msg.shade_contract_info.address.to_string(),
        )?,
        // Set viewing key for SHD
        set_viewing_key_msg(
            shade_contract_vk,
            msg.shade_contract_info.entropy,
            RESPONSE_BLOCK_SIZE,
            msg.shade_contract_info.code_hash,
            msg.shade_contract_info.address.to_string(),
        )?,
        // Set viewing key for staking contract
        set_viewing_key_msg(
            staking_contract_vk,
            msg.authentication_contract_info.entropy,
            RESPONSE_BLOCK_SIZE,
            msg.authentication_contract_info.code_hash,
            msg.authentication_contract_info.address.to_string(),
        )?,
    ];

    Ok(Response::default().add_messages(msgs))
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let contract_status = CONTRACT_STATUS.load(deps.storage)?;

    match contract_status {
        ContractStatusLevel::StopAll => {
            let response = match msg {
                ExecuteMsg::SetContractStatus { level, .. } => {
                    set_contract_status(deps, info, level)
                }
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_handle_result(response, RESPONSE_BLOCK_SIZE);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }

    let response = match msg {
        ExecuteMsg::PanicUnbond { amount } => try_panic_unbond(deps, info, amount),
        ExecuteMsg::PanicWithdraw { ids } => try_panic_withdraw(deps, info, ids),
        ExecuteMsg::UpdateFees {
            staking_fee,
            unbonding_fee,
        } => update_fees(deps, info, staking_fee, unbonding_fee),
        //Receiver interface
        ExecuteMsg::Receive {
            sender: _,
            from,
            amount,
            msg,
        } => receive(deps, env, info, from, amount, msg),
        ExecuteMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, info, entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, info, key),
        ExecuteMsg::SetContractStatus { level, .. } => set_contract_status(deps, info, level),
        ExecuteMsg::RevokePermit { permit_name, .. } => revoke_permit(deps, info, permit_name),
    };

    pad_handle_result(response, RESPONSE_BLOCK_SIZE)
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    pad_query_result(
        match msg {
            QueryMsg::StakingInfo {} => query_staking_info(&deps, &env),
            QueryMsg::FeeInfo {} => query_fee_info(&deps),
            QueryMsg::ContractStatus {} => query_contract_status(deps.storage),
            QueryMsg::WithPermit {
                permit: _,
                query: _,
            } => Err(StdError::generic_err("Not implemented")),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

#[entry_point]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> StdResult<Response> {
    match (msg.id, msg.result) {
        (UNBOND_REPLY_ID, SubMsgResult::Ok(s)) => match s.data {
            Some(x) => {
                let result: UnbondResponse = from_binary(&x)?;
                // Read unbonding info
                let pending_unbonding = PENDING_UNBONDING.may_load(deps.storage)?;

                if let Some(unbonding_processing) = pending_unbonding {
                    // Store unbonding
                    let unbond = Unbonding {
                        id: result.unbond.id,
                        amount: unbonding_processing.amount,
                        complete: unbonding_processing.complete,
                    };
                    UnbondingStore::save(deps.storage, result.unbond.id.clone().u128(), &unbond)?;

                    // Add unbonding id to user's unbondings IDs
                    let mut users_unbondings_ids =
                        UnbondingIdsStore::load(deps.storage, &unbonding_processing.owner);
                    users_unbondings_ids.push(result.unbond.id.u128());
                    UnbondingIdsStore::save(
                        deps.storage,
                        &unbonding_processing.owner,
                        users_unbondings_ids,
                    )?;

                    Ok(Response::default())
                } else {
                    Err(StdError::generic_err(
                        "Unexpected error: pending unbond storage is empty.",
                    ))
                }
            }
            None => Err(StdError::generic_err("Unknown reply id")),
        },
        _ => Err(StdError::generic_err("Unknown reply id")),
    }
}
/************ HANDLES ************/
fn try_panic_unbond(deps: DepsMut, info: MessageInfo, amount: Uint128) -> StdResult<Response> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;
    let constants = CONFIG.load(deps.storage)?;
    check_if_admin(
        &deps.querier,
        AdminPermissions::DerivativeAdmin,
        info.sender.to_string(),
        &constants.admin_contract_info,
    )?;
    let msgs = vec![unbond_msg(
        amount,
        staking_config.staking_contract_info.code_hash,
        staking_config.staking_contract_info.address.to_string(),
        Some(false),
    )?];
    Ok(Response::default().add_messages(msgs))
}

fn try_panic_withdraw(
    deps: DepsMut,
    info: MessageInfo,
    ids: Option<Vec<Uint128>>,
) -> StdResult<Response> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;
    let constants = CONFIG.load(deps.storage)?;
    check_if_admin(
        &deps.querier,
        AdminPermissions::DerivativeAdmin,
        info.sender.to_string(),
        &constants.admin_contract_info,
    )?;

    let msgs = vec![withdraw_msg(
        staking_config.staking_contract_info.code_hash,
        staking_config.staking_contract_info.address.to_string(),
        ids,
    )?];

    Ok(Response::default().add_messages(msgs))
}

/// Updates fee's information if provided
fn update_fees(
    deps: DepsMut,
    info: MessageInfo,
    staking_fee: Option<Fee>,
    unbonding_fee: Option<Fee>,
) -> StdResult<Response> {
    let constants = CONFIG.load(deps.storage)?;
    check_if_admin(
        &deps.querier,
        AdminPermissions::DerivativeAdmin,
        info.sender.to_string(),
        &constants.admin_contract_info,
    )?;

    let mut staking_config = STAKING_CONFIG.load(deps.storage)?;
    let fee_info: FeeInfo = FeeInfo {
        staking_fee: staking_fee.unwrap_or(staking_config.fee_info.staking_fee),
        unbonding_fee: unbonding_fee.unwrap_or(staking_config.fee_info.unbonding_fee),
    };
    staking_config.fee_info = fee_info.clone();
    STAKING_CONFIG.save(deps.storage, &staking_config)?;

    Ok(
        Response::default().set_data(to_binary(&ExecuteAnswer::UpdateFees {
            status: Success,
            fee: fee_info,
        })?),
    )
}

fn receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    from: Addr,
    amount: Uint256,
    msg: Option<Binary>,
) -> StdResult<Response> {
    if let Some(x) = msg {
        match from_binary(&x)? {
            ReceiverMsg::Stake {} => try_stake(deps, env, info, from, amount, Some(x)),
            ReceiverMsg::Unbond {} => try_unbond(deps, env, info, from, amount, Some(x)),
            #[allow(unreachable_patterns)]
            _ => Err(StdError::generic_err(format!(
                "Invalid msg provided, expected {} or {}",
                to_binary(&ReceiverMsg::Stake {})?,
                to_binary(&ReceiverMsg::Unbond {})?
            ))),
        }
    } else {
        Ok(Response::default())
    }
}
/// Try to stake SHD received tokens
///
/// Interacts directly with the Staking contract
///
/// @param amount of receiving tokens
fn try_stake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    // Staker address
    from: Addr,
    _amount: Uint256,
    _msg: Option<Binary>,
) -> StdResult<Response> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;
    let amount = Uint128::try_from(_amount)?;
    if info.sender != staking_config.shade_contract_info.address {
        return Err(StdError::generic_err("Sender is not SHD contract"));
    }

    if amount == Uint128::zero() {
        return Err(StdError::generic_err("No SHD was sent for staking"));
    }

    let (fee, deposit) = get_fee(amount, &staking_config.fee_info.staking_fee)?;
    // get available SHD + available rewards
    let (_, _, claiming) = get_delegatable(deps.querier, &env.contract.address, &staking_config)?;

    // get staked SHD
    let bonded = get_staked_shd(deps.querier, &env.contract.address, &staking_config)?;
    let starting_pool = (claiming + bonded).saturating_sub(deposit.u128() + fee.u128());

    let token_info = get_token_info(
        deps.querier,
        RESPONSE_BLOCK_SIZE,
        staking_config.shade_contract_info.code_hash.clone(),
        staking_config.shade_contract_info.address.to_string(),
    )?;
    let total_supply = token_info.total_supply.unwrap_or(Uint128::zero()).u128();
    // mint appropriate amount
    let mint = if starting_pool == 0 || total_supply == 0 {
        deposit
    } else {
        // unwrap is ok because multiplying 2 u128 ints can not overflow a u256
        let numer = Uint256::from(deposit)
            .checked_mul(Uint256::from(total_supply))
            .unwrap();
        // unwrap is ok because starting pool can not be zero
        Uint128::try_from(numer.checked_div(Uint256::from(starting_pool)).unwrap())?
    };
    if mint == Uint128::zero() {
        return Err(StdError::generic_err("The amount of SHD deposited is not enough to receive any of the derivative token at the current price"));
    }
    // claim pending rewards
    let mut messages = vec![mint_msg(
        from.to_string(),
        mint,
        Some(format!(
            "Minted {} u_{} to stake {} SHD",
            mint, token_info.symbol, deposit
        )),
        staking_config.derivative_contract_info.entropy.clone(),
        RESPONSE_BLOCK_SIZE,
        staking_config.derivative_contract_info.code_hash.clone(),
        staking_config.derivative_contract_info.address.to_string(),
    )?];

    // send fee to collector
    messages.push(send_msg(
        staking_config.fee_info.staking_fee.collector.to_string(),
        fee,
        None,
        Some(format!(
            "Payment of fee for staking SHD using contract {}",
            env.contract.address
        )),
        staking_config.shade_contract_info.entropy.clone(),
        RESPONSE_BLOCK_SIZE,
        staking_config.shade_contract_info.code_hash.clone(),
        staking_config.shade_contract_info.address.to_string(),
    )?);

    // Stake available SHD
    if deposit > Uint128::zero() {
        messages.push(generate_stake_msg(deposit, Some(true), &staking_config)?);
    }

    Ok(Response::new()
        .set_data(to_binary(&ExecuteAnswer::Stake {
            shd_staked: deposit,
            tokens_returned: mint,
        })?)
        .add_messages(messages))
}

fn try_unbond(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    // address unbonding
    from: Addr,
    _amount: Uint256,
    _msg: Option<Binary>,
) -> StdResult<Response> {
    let mut response = Response::new();
    let mut staking_config = STAKING_CONFIG.load(deps.storage)?;
    let derivative_token_info = get_token_info(
        deps.querier,
        RESPONSE_BLOCK_SIZE,
        staking_config.derivative_contract_info.code_hash.clone(),
        staking_config.derivative_contract_info.address.to_string(),
    )?;
    let staking_info = get_staking_contract_config(deps.querier, &staking_config)?;
    let amount = Uint128::try_from(_amount)?;
    if info.sender != staking_config.derivative_contract_info.address {
        return Err(StdError::generic_err(
            "Sender is not derivative (SNIP20) contract",
        ));
    }

    if amount == Uint128::zero() {
        return Err(StdError::generic_err("0 amount sent to unbond"));
    }

    let (_, _, delegatable) =
        get_delegatable(deps.querier, &env.contract.address, &staking_config)?;

    let staked = get_staked_shd(deps.querier, &env.contract.address, &staking_config)?;
    let pool = delegatable + staked;
    // unwrap is ok because multiplying 2 u128 ints can not overflow a u256
    let number = Uint256::from(amount)
        .checked_mul(Uint256::from(pool))
        .unwrap();
    // unwrap is ok because derivative token supply could not have been 0 if we were able
    // to burn
    let unbond_amount = Uint128::try_from(
        number
            .checked_div(Uint256::from(derivative_token_info.total_supply.unwrap()))
            .unwrap(),
    )?;
    // calculate the amount going to the user
    let (_, shd_to_be_received) = get_fee(unbond_amount, &staking_config.fee_info.unbonding_fee)?;

    if shd_to_be_received.is_zero() {
        return Err(StdError::generic_err(format!(
            "Redeeming {} derivative tokens would be worth less than 1 SHD",
            amount
        )));
    }

    let unbonding = InProcessUnbonding {
        id: Uint128::zero(),
        amount: shd_to_be_received,
        owner: from,
        complete: Uint128::from(env.block.time.seconds())
            .checked_add(staking_info.unbond_period)?,
    };
    PENDING_UNBONDING.save(deps.storage, &unbonding)?;

    #[allow(unused_assignments)]
    let mut amount_to_unbond = Uint128::zero();

    if shd_to_be_received.u128() > staked {
        // In case the SHD to be receive is more than actual staked
        // Then unbond all staked and claim rewards
        amount_to_unbond = Uint128::from(staked);

        // Since rewards become available after claiming we need to freeze them
        // unwrap shouldn't panic because `shd_to_be_receive` is higher than `staked`
        staking_config.unbonded += shd_to_be_received.u128().checked_sub(staked).unwrap()
    } else {
        amount_to_unbond = shd_to_be_received
    };

    STAKING_CONFIG.save(deps.storage, &staking_config)?;

    response = response.add_submessage(SubMsg::reply_always(
        unbond_msg(
            amount_to_unbond,
            staking_config.staking_contract_info.code_hash.clone(),
            staking_config.staking_contract_info.address.to_string(),
            Some(true),
        )?,
        UNBOND_REPLY_ID,
    ));

    Ok(response
        .add_message(burn_msg(
            amount,
            Some(format!(
                "Burn {} derivatives to receive {} SHD",
                amount, shd_to_be_received
            )),
            staking_config.derivative_contract_info.entropy,
            RESPONSE_BLOCK_SIZE,
            staking_config.derivative_contract_info.code_hash.clone(),
            staking_config.derivative_contract_info.address.to_string(),
        )?)
        .set_data(to_binary(&ExecuteAnswer::Unbond {
            shd_to_be_received,
            tokens_redeemed: amount,
            estimated_time_of_maturity: Uint128::from(env.block.time.seconds())
                .checked_add(staking_info.unbond_period)?,
        })?))
}
/// Returns StdResult<u128>
///
/// gets the amount of available SHD
/// by querying contract balance and subtracting unbonded
///
/// # Arguments
///
/// * `config` - a mutable reference to the StakingConfig
#[cfg(not(test))]
#[allow(dead_code)]
// Allow warn code because mock queries make warnings to show up
fn get_available_shd<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    contract_addr: &Addr,
    config: &StakingInfo,
) -> StdResult<u128> {
    let balance = balance_query(
        querier,
        contract_addr.to_string(),
        config.shade_contract_vk.clone(),
        RESPONSE_BLOCK_SIZE,
        config.shade_contract_info.code_hash.to_string(),
        config.shade_contract_info.address.to_string(),
    )?;

    let available = balance
        .amount
        .checked_sub(Uint128::from(config.unbonded))
        .unwrap_or(Uint128::zero());
    Ok(available.u128())
}
#[cfg(test)]
fn get_available_shd<C: CustomQuery>(
    _: QuerierWrapper<C>,
    _: &Addr,
    _: &StakingInfo,
) -> StdResult<u128> {
    Ok(100000000_u128)
}
/// Returns StdResult<u128>
///
/// gets the amount of staked SHD
/// by querying staking contract balance
///
/// # Arguments
///
/// * `config` - a mutable reference to the StakingConfig
#[cfg(not(test))]
fn get_staked_shd<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    contract_addr: &Addr,
    config: &StakingInfo,
) -> StdResult<u128> {
    let balance = staking_balance_query(
        contract_addr.to_string(),
        config.staking_contract_vk.clone(),
        querier,
        config.staking_contract_info.code_hash.to_string(),
        config.staking_contract_info.address.to_string(),
    )?;

    Ok(balance.amount.u128())
}
#[cfg(test)]
fn get_staked_shd<C: CustomQuery>(
    _: QuerierWrapper<C>,
    _: &Addr,
    _: &StakingInfo,
) -> StdResult<u128> {
    Ok(300000000)
}
/// Returns StdResult<u128>
///
/// Gets amount of rewards generated
/// in staking contract
///
/// # Arguments
///
/// * `config` - a mutable reference to the StakingConfig
#[cfg(not(test))]
fn get_rewards<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    contract_addr: &Addr,
    config: &StakingInfo,
) -> StdResult<u128> {
    let rewards = rewards_query(
        contract_addr.to_string(),
        config.staking_contract_vk.clone(),
        querier,
        config.staking_contract_info.code_hash.to_string(),
        config.staking_contract_info.address.to_string(),
    )?;
    let item = rewards
        .rewards
        .iter()
        .find(|r| r.token == config.shade_contract_info.address);

    if let Some(reward) = item {
        Ok(reward.amount.u128())
    } else {
        Ok(0)
    }
}
#[cfg(test)]
#[allow(dead_code)]
// Allow warn code because mock queries make warnings to show up
fn get_rewards<C: CustomQuery>(_: QuerierWrapper<C>, _: &Addr, _: &StakingInfo) -> StdResult<u128> {
    Ok(100000000)
}

#[cfg(test)]
#[allow(dead_code)]
// Allow warn code because mock queries make warnings to show up
fn get_staking_contract_config<C: CustomQuery>(
    _: QuerierWrapper<C>,
    _: &StakingInfo,
) -> StdResult<StakingConfig> {
    Ok(StakingConfig {
        admin_auth: RawContract {
            address: String::from("mock_address"),
            code_hash: String::from("mock_code_hash"),
        },
        query_auth: RawContract {
            address: String::from("mock_address"),
            code_hash: String::from("mock_code_hash"),
        },
        unbond_period: Uint128::from(300_u32),
        max_user_pools: Uint128::from(5_u32),
        reward_cancel_threshold: Uint128::from(0_u32),
    })
}

#[cfg(not(test))]
fn get_staking_contract_config<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    staking_info: &StakingInfo,
) -> StdResult<StakingConfig> {
    config_query(
        querier,
        staking_info.staking_contract_info.code_hash.clone(),
        staking_info.staking_contract_info.address.to_string(),
    )
}
/// Returns StdResult<u128>
///
/// Returns the amount of SHD available, the amount of claimable rewards,
/// and the maximum amount of SHD available to stake if rewards al claimed
///
/// # Arguments
///
/// * `contract_addr` - this contract's address
/// * `staking_config` - a reference to the StakingInfo
#[cfg(not(test))]
fn get_delegatable<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    contract_addr: &Addr,
    staking_config: &StakingInfo,
) -> StdResult<(u128, u128, u128)> {
    let rewards = get_rewards(querier, contract_addr, staking_config)?;

    let available = get_available_shd(querier, contract_addr, staking_config)?;
    Ok((available, rewards, rewards + available))
}

#[cfg(test)]
fn get_delegatable<C: CustomQuery>(
    _: QuerierWrapper<C>,
    _: &Addr,
    _: &StakingInfo,
) -> StdResult<(u128, u128, u128)> {
    Ok((100000000, 50000000, 100000000 + 50000000))
}
/// Returns StdResult<(u128, u128)>
///
/// calculates a fee for the specified amount and returns the fee amount and the remaining
/// amount
///
/// # Arguments
///
/// * `rate` - fee rate
/// * `amount` - the pre-fee amount
pub fn get_fee(amount: Uint128, fee_config: &Fee) -> StdResult<(Uint128, Uint128)> {
    // first unwrap is ok because multiplying a u128 by a u32 can not overflow a u256
    // second unwrap is ok because we know we aren't dividing by zero
    let _fee = Uint256::from(amount)
        .checked_mul(Uint256::from(fee_config.rate))
        .unwrap()
        .checked_div(Uint256::from(10_u32.pow(fee_config.decimal_places as u32)))
        .unwrap();
    let fee = Uint128::try_from(_fee)?;
    let remainder = amount.saturating_sub(fee);
    Ok((fee, remainder))
}
#[cfg(not(test))]
fn get_token_info<C: CustomQuery>(
    querier: QuerierWrapper<C>,
    block_size: usize,
    callback_code_hash: String,
    contract_addr: String,
) -> StdResult<TokenInfo> {
    let token_info = token_info_query(querier, block_size, callback_code_hash, contract_addr)?;
    if token_info.total_supply.is_none() {
        return Err(StdError::generic_err(
            "Token supply must be public on derivative token",
        ));
    }

    Ok(token_info)
}

#[cfg(test)]
fn get_token_info<C: CustomQuery>(
    _querier: QuerierWrapper<C>,
    _block_size: usize,
    _callback_code_hash: String,
    _contract_addr: String,
) -> StdResult<TokenInfo> {
    Ok(TokenInfo {
        name: String::from("STKD-SHD"),
        symbol: String::from("STKDSHD"),
        decimals: 6,
        total_supply: Some(Uint128::from(2000_u128)),
    })
}
#[cfg(not(test))]
fn check_if_admin(
    querier: &QuerierWrapper,
    permission: AdminPermissions,
    user: String,
    admin_auth: &Contract,
) -> StdResult<()> {
    validate_admin(querier, permission, user, admin_auth)
}

#[cfg(test)]
fn check_if_admin(
    _: &QuerierWrapper,
    _: AdminPermissions,
    user: String,
    _: &Contract,
) -> StdResult<()> {
    if user != String::from("admin") {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

/// Returns StdResult<CosmoMsg>
///
/// Generates a CosmoMsg sending SHD into
/// Staking contract with the corresponding msg callback to stake it
///
/// # Arguments
///
/// * `amount` - amount intended to stake
/// * `staking_config` - a reference to the StakingInfo
fn generate_stake_msg(
    amount: Uint128,
    compound: Option<bool>,
    staking_config: &StakingInfo,
) -> StdResult<CosmosMsg> {
    let memo =
        Some(to_binary(&format!("Staking {} SHD into staking contract", amount))?.to_base64());
    let msg = Some(to_binary(&Action::Stake { compound })?);
    send_msg(
        staking_config.staking_contract_info.address.to_string(),
        amount,
        msg,
        memo,
        staking_config.shade_contract_info.entropy.clone(),
        RESPONSE_BLOCK_SIZE,
        staking_config.shade_contract_info.code_hash.clone(),
        staking_config.shade_contract_info.address.to_string(),
    )
}

pub fn try_set_key(deps: DepsMut, info: MessageInfo, key: String) -> StdResult<Response> {
    ViewingKey::set(deps.storage, info.sender.as_str(), key.as_str());
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetViewingKey {
            status: Success,
        })?),
    )
}

pub fn try_create_key(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    entropy: String,
) -> StdResult<Response> {
    let key = ViewingKey::create(
        deps.storage,
        &info,
        &env,
        info.sender.as_str(),
        entropy.as_ref(),
    );

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::CreateViewingKey { key })?))
}

fn set_contract_status(
    deps: DepsMut,
    info: MessageInfo,
    status_level: ContractStatusLevel,
) -> StdResult<Response> {
    let constants = CONFIG.load(deps.storage)?;
    check_if_admin(
        &deps.querier,
        AdminPermissions::DerivativeAdmin,
        info.sender.to_string(),
        &constants.admin_contract_info,
    )?;

    CONTRACT_STATUS.save(deps.storage, &status_level)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetContractStatus {
            status: Success,
        })?),
    )
}

fn revoke_permit(deps: DepsMut, info: MessageInfo, permit_name: String) -> StdResult<Response> {
    RevokedPermits::revoke_permit(
        deps.storage,
        PREFIX_REVOKED_PERMITS,
        info.sender.as_str(),
        &permit_name,
    );

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::RevokePermit { status: Success })?))
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    (3..=30).contains(&len)
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = (3..=20).contains(&len);

    len_is_valid
        && symbol
            .bytes()
            .all(|byte| (b'A'..=b'Z').contains(&byte) || (b'a'..=b'z').contains(&byte))
}

// Copied from secret-toolkit-viewing-key-0.7.0
pub fn new_viewing_key(
    sender: &Addr,
    env: &Env,
    seed: &[u8],
    entropy: &[u8],
) -> (String, [u8; 32]) {
    pub const VIEWING_KEY_PREFIX: &str = "api_key_";
    // 16 here represents the lengths in bytes of the block height and time.
    let entropy_len = 16 + sender.to_string().len() + entropy.len();
    let mut rng_entropy = Vec::with_capacity(entropy_len);
    rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
    rng_entropy.extend_from_slice(&env.block.time.seconds().to_be_bytes());
    rng_entropy.extend_from_slice(sender.as_bytes());
    rng_entropy.extend_from_slice(entropy);

    let mut rng = Prng::new(seed, &rng_entropy);

    let rand_slice = rng.rand_bytes();

    let key = sha_256(&rand_slice);

    let viewing_key = VIEWING_KEY_PREFIX.to_string() + &base64::encode(key);
    (viewing_key, rand_slice)
}

/************ QUERIES ************/
fn query_contract_status(storage: &dyn Storage) -> StdResult<Binary> {
    let contract_status = CONTRACT_STATUS.load(storage)?;

    to_binary(&QueryAnswer::ContractStatus {
        status: contract_status,
    })
}

fn query_staking_info(deps: &Deps, env: &Env) -> StdResult<Binary> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;

    let derivative_info = get_token_info(
        deps.querier,
        RESPONSE_BLOCK_SIZE,
        staking_config.derivative_contract_info.code_hash.clone(),
        staking_config.derivative_contract_info.address.to_string(),
    )?;
    let bonded = get_staked_shd(deps.querier, &env.contract.address, &staking_config)?;
    let rewards = get_rewards(deps.querier, &env.contract.address, &staking_config)?;
    let available = get_available_shd(deps.querier, &env.contract.address, &staking_config)?;

    let total_supply = derivative_info.total_supply.unwrap_or(Uint128::zero());

    let pool = bonded + rewards + available;
    let price = if total_supply == Uint128::zero() || pool == 0 {
        Uint128::from(10_u128.pow(derivative_info.decimals as u32))
    } else {
        // unwrap is ok because multiplying a u128 by 1 mill can not overflow u256
        let number = Uint256::from(pool)
            .checked_mul(Uint256::from(10_u128.pow(derivative_info.decimals as u32)))
            .unwrap();
        // unwrap is ok because we already checked if the total supply is 0
        Uint128::try_from(number.checked_div(Uint256::from(total_supply)).unwrap())?
    };

    let staking_contract_config = get_staking_contract_config(deps.querier, &staking_config)?;

    to_binary(&QueryAnswer::StakingInfo {
        unbonding_time: staking_contract_config.unbond_period,
        bonded_shd: Uint128::from(bonded),
        available_shd: Uint128::from(available),
        rewards: Uint128::from(rewards),
        total_derivative_token_supply: total_supply,
        price,
    })
}

fn query_fee_info(deps: &Deps) -> StdResult<Binary> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;

    to_binary(&QueryAnswer::FeeInfo {
        staking_fee: staking_config.fee_info.staking_fee,
        unbonding_fee: staking_config.fee_info.unbonding_fee,
    })
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, OwnedDeps, QueryResponse};
    use shade_protocol::Contract;

    use crate::msg::{ContractInfo as CustomContractInfo, Fee, FeeInfo, ResponseStatus};

    use super::*;

    pub const VIEWING_KEY_SIZE: usize = 32;
    fn init_helper() -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[]);
        let env = mock_env();
        let info = mock_info("instantiator", &[]);

        let init_msg = InstantiateMsg {
            name: "sec-sec".to_string(),
            symbol: "SECSEC".to_string(),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            derivative_contract_info: CustomContractInfo {
                address: Addr::unchecked("derivative_snip20_info_address"),
                code_hash: String::from("derivative_snip20_info_codehash"),
                entropy: Some(String::from("4359o74nd8dnkjerjrh")),
            },
            staking_contract_info: CustomContractInfo {
                address: Addr::unchecked("staking_contract_info_address"),
                code_hash: String::from("staking_contract_info_code_hash"),
                entropy: Some(String::from("4359o74nd8dnkjerjrh")),
            },
            authentication_contract_info: CustomContractInfo {
                address: Addr::unchecked("authentication_contract_info_address"),
                code_hash: String::from("authentication_contract_info_code_hash"),
                entropy: Some(String::from("ljkdsfgh9548605874easfnd")),
            },
            shade_contract_info: CustomContractInfo {
                address: Addr::unchecked("shade_contract_info_address"),
                code_hash: String::from("shade_contract_info_code_hash"),
                entropy: Some(String::from("5sa4d6aweg473g87766h7712")),
            },
            admin_contract_info: Contract {
                address: Addr::unchecked("shade_contract_info_address"),
                code_hash: String::from("shade_contract_info_code_hash"),
            },
            fee_info: FeeInfo {
                staking_fee: Fee {
                    collector: Addr::unchecked("collector_address"),
                    rate: 5,
                    decimal_places: 2_u8,
                },
                unbonding_fee: Fee {
                    collector: Addr::unchecked("collector_address"),
                    rate: 5,
                    decimal_places: 2_u8,
                },
            },
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }
    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(response) => {
                let bin_err = (&response as &dyn Any)
                    .downcast_ref::<QueryResponse>()
                    .expect("An error was expected, but no error could be extracted");
                match from_binary(bin_err).unwrap() {
                    QueryAnswer::ViewingKeyError { msg } => msg,
                    _ => panic!("Unexpected query answer"),
                }
            }
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected result from init"),
            },
        }
    }

    #[test]
    fn test_init_sanity() {
        let (init_result, mut deps) = init_helper();
        let env = mock_env();
        let info = mock_info("instantiator", &[]);
        let prnd = Binary::from("lolz fun yay".as_bytes());
        let staking_contract_info = CustomContractInfo {
            address: Addr::unchecked("staking_contract_info_address"),
            code_hash: String::from("staking_contract_info_code_hash"),
            entropy: Some(String::from("4359o74nd8dnkjerjrh")),
        };

        let authentication_contract = CustomContractInfo {
            address: Addr::unchecked("authentication_contract_info_address"),
            code_hash: String::from("authentication_contract_info_code_hash"),
            entropy: Some(String::from("ljkdsfgh9548605874easfnd")),
        };
        let shade_contract_info = CustomContractInfo {
            address: Addr::unchecked("shade_contract_info_address"),
            code_hash: String::from("shade_contract_info_code_hash"),
            entropy: Some(String::from("5sa4d6aweg473g87766h7712")),
        };
        let derivative_contract_info = CustomContractInfo {
            address: Addr::unchecked("derivative_snip20_info_address"),
            code_hash: String::from("derivative_snip20_info_codehash"),
            entropy: Some(String::from("4359o74nd8dnkjerjrh")),
        };

        // Generate viewing key for staking contract
        let entropy: String = staking_contract_info.entropy.clone().unwrap();
        let (staking_contract_vk, new_seed) =
            new_viewing_key(&info.sender.clone(), &env, &prnd.0, entropy.as_ref());

        // Generate viewing key for SHD contract
        let entropy: String = shade_contract_info.entropy.clone().unwrap();
        let (shade_contract_vk, _new_seed) =
            new_viewing_key(&info.sender.clone(), &env, &new_seed, entropy.as_ref());

        let msgs: Vec<CosmosMsg> = vec![
            // Register receive Derivative contract
            register_receive_msg(
                env.contract.code_hash.clone(),
                derivative_contract_info.entropy,
                RESPONSE_BLOCK_SIZE,
                derivative_contract_info.code_hash,
                derivative_contract_info.address.to_string(),
            )
            .unwrap(),
            // Register receive SHD contract
            register_receive_msg(
                env.contract.code_hash,
                shade_contract_info.entropy.clone(),
                RESPONSE_BLOCK_SIZE,
                shade_contract_info.code_hash.clone(),
                shade_contract_info.address.to_string(),
            )
            .unwrap(),
            // Set viewing key for SHD
            set_viewing_key_msg(
                shade_contract_vk,
                shade_contract_info.entropy,
                RESPONSE_BLOCK_SIZE,
                shade_contract_info.code_hash,
                shade_contract_info.address.to_string(),
            )
            .unwrap(),
            // Set viewing key for staking contract
            set_viewing_key_msg(
                staking_contract_vk,
                authentication_contract.entropy,
                RESPONSE_BLOCK_SIZE,
                authentication_contract.code_hash,
                authentication_contract.address.to_string(),
            )
            .unwrap(),
        ];
        assert_eq!(init_result.unwrap(), Response::default().add_messages(msgs));

        let constants = CONFIG.load(&deps.storage).unwrap();

        assert_eq!(
            CONTRACT_STATUS.load(&deps.storage).unwrap(),
            ContractStatusLevel::NormalRun
        );
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.symbol, "SECSEC".to_string());

        ViewingKey::set(deps.as_mut().storage, "lebron", "lolz fun yay");
        let is_vk_correct = ViewingKey::check(&deps.storage, "lebron", "lolz fun yay");
        assert!(
            is_vk_correct.is_ok(),
            "Viewing key verification failed!: {}",
            is_vk_correct.err().unwrap()
        );
    }
    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        // let bob_canonical = deps.as_mut().api.addr_canonicalize("bob").unwrap();

        let result = ViewingKey::check(&deps.storage, "bob", key.as_str());
        assert!(result.is_ok());

        // let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        // assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        // Set valid VK
        let actual_vk = "x".to_string().repeat(VIEWING_KEY_SIZE);
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: actual_vk.clone(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey { status: Success }).unwrap(),
        );

        let result = ViewingKey::check(&deps.storage, "bob", actual_vk.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_set_contract_status() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = CONTRACT_STATUS.load(&deps.storage).unwrap();
        assert!(matches!(
            contract_status,
            ContractStatusLevel::StopAll { .. }
        ));
    }
    #[test]
    fn test_receive_msg_sender_is_not_shd_contract() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked(""),
            amount: Uint256::from(100000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Stake {}).unwrap()),
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(handle_result.is_err());
        let error = extract_error_msg(handle_result);

        assert_eq!(error, "Sender is not SHD contract");
    }

    #[test]
    fn test_receive_stake_msg_successfully() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked(""),
            amount: Uint256::from(100000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Stake {}).unwrap()),
        };
        let info = mock_info("shade_contract_info_address", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
    }

    #[test]
    fn test_receive_unbond_msg_sender_is_not_derivative_contract() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked(""),
            amount: Uint256::from(100000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Unbond {}).unwrap()),
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(handle_result.is_err());
        let error = extract_error_msg(handle_result);

        assert_eq!(error, "Sender is not derivative (SNIP20) contract");
    }

    #[test]
    fn test_receive_unbond_msg_successfully() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked(""),
            amount: Uint256::from(100000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Unbond {}).unwrap()),
        };
        let info = mock_info("derivative_snip20_info_address", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
    }

    #[test]
    fn test_sanity_unbonding_processing_storage() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let env = mock_env();
        // Unbond from bob account
        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked("bob"),
            amount: Uint256::from(100000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Unbond {}).unwrap()),
        };
        let info = mock_info("derivative_snip20_info_address", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let unbonding_processing = PENDING_UNBONDING.load(&deps.storage).unwrap();

        assert_eq!(
            unbonding_processing,
            InProcessUnbonding {
                id: Uint128::zero(),
                owner: Addr::unchecked("bob"),
                amount: Uint128::from(21375000000000_u128),
                complete: Uint128::from(env.block.time.seconds())
                    .checked_add(Uint128::from(300_u32))
                    .unwrap(),
            }
        )
    }

    #[test]
    fn test_update_fees_should_fail_no_admin_sender() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::UpdateFees {
            staking_fee: None,
            unbonding_fee: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(handle_result.is_err());
        let error = extract_error_msg(handle_result);

        assert_eq!(
            error,
            "This is an admin command. Admin commands can only be run from admin address"
        );
    }

    #[test]
    fn test_update_fees_successfully_sender_is_admin_no_new_config_provided() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let staking_info_before_tx = STAKING_CONFIG.load(&deps.storage).unwrap();
        let handle_msg = ExecuteMsg::UpdateFees {
            staking_fee: None,
            unbonding_fee: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let staking_info_after_tx = STAKING_CONFIG.load(&deps.storage).unwrap();

        assert_eq!(
            staking_info_before_tx.fee_info,
            staking_info_after_tx.fee_info
        );
    }

    #[test]
    fn test_update_fees_successfully_sender_is_admin() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let staking_info_before_tx = STAKING_CONFIG.load(&deps.storage).unwrap();
        let handle_msg = ExecuteMsg::UpdateFees {
            staking_fee: Some(Fee {
                collector: Addr::unchecked("new_collector"),
                rate: 5_u32,
                decimal_places: 2_u8,
            }),
            unbonding_fee: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let staking_info_after_tx = STAKING_CONFIG.load(&deps.storage).unwrap();

        assert_ne!(
            staking_info_before_tx.fee_info,
            staking_info_after_tx.fee_info
        );

        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        let fee_info_returned = match answer {
            ExecuteAnswer::UpdateFees { fee, status: _ } => fee,
            _ => panic!("NOPE"),
        };
        let fee_info = STAKING_CONFIG.load(&deps.storage).unwrap().fee_info;

        assert_eq!(fee_info_returned, fee_info)
    }

    #[test]
    fn test_staking_returned_tokens() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Receive {
            sender: Addr::unchecked(""),
            from: Addr::unchecked("bob"),
            amount: Uint256::from(300000000 as u32),
            msg: Some(to_binary(&ReceiverMsg::Stake {}).unwrap()),
        };
        let info = mock_info("shade_contract_info_address", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let expected_tokens_return = Uint128::from(3800_u128);
        let (_, tokens_returned) = match from_binary(&handle_result.unwrap().data.unwrap()).unwrap()
        {
            ExecuteAnswer::Stake {
                shd_staked,
                tokens_returned,
            } => (shd_staked, tokens_returned),
            other => panic!("Unexpected: {:?}", other),
        };
        assert_eq!(tokens_returned, expected_tokens_return)
    }

    #[test]
    fn test_staking_info_query() {
        let (init_result, deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::StakingInfo {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let (
            unbonding_time,
            bonded_shd,
            available_shd,
            rewards,
            total_derivative_token_supply,
            price,
        ) = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::StakingInfo {
                unbonding_time,
                bonded_shd,
                available_shd,
                rewards,
                total_derivative_token_supply,
                price,
            } => (
                unbonding_time,
                bonded_shd,
                available_shd,
                rewards,
                total_derivative_token_supply,
                price,
            ),
            other => panic!("Unexpected: {:?}", other),
        };

        assert_eq!(unbonding_time, Uint128::from(300_u32));
        assert_eq!(bonded_shd, Uint128::from(300000000_u128));
        assert_eq!(available_shd, Uint128::from(100000000_u128));
        assert_eq!(rewards, Uint128::from(100000000_u128));
        assert_eq!(total_derivative_token_supply, Uint128::from(2000_u128));
        assert_eq!(price, Uint128::from(250000000000_u128));
    }

    #[test]
    fn test_fee_info() {
        let (init_result, deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::FeeInfo {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let (staking_fee, unbonding_fee) = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::FeeInfo {
                staking_fee,
                unbonding_fee,
            } => (staking_fee, unbonding_fee),
            other => panic!("Unexpected: {:?}", other),
        };

        assert_eq!(
            staking_fee,
            Fee {
                collector: Addr::unchecked("collector_address"),
                rate: 5,
                decimal_places: 2_u8,
            }
        );
        assert_eq!(
            unbonding_fee,
            Fee {
                collector: Addr::unchecked("collector_address"),
                rate: 5,
                decimal_places: 2_u8,
            }
        );
    }
    #[test]
    fn test_handle_panic_unbond_not_admin_user() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = ExecuteMsg::PanicUnbond {
            amount: Uint128::from(100000000_u128),
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(handle_result.is_err());
        let error = extract_error_msg(handle_result);

        assert_eq!(
            error,
            "This is an admin command. Admin commands can only be run from admin address"
        );
    }

    #[test]
    fn test_handle_panic_unbond_msg() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::PanicUnbond {
            amount: Uint128::from(100000000_u128),
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let staking_config = STAKING_CONFIG.load(&deps.storage).unwrap();

        let msgs = vec![unbond_msg(
            Uint128::from(100000000_u128),
            staking_config.staking_contract_info.code_hash,
            staking_config.staking_contract_info.address.to_string(),
            Some(false),
        )
        .unwrap()];

        assert_eq!(
            handle_result.unwrap(),
            Response::default().add_messages(msgs)
        );
    }
}
