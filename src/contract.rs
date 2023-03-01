/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response,
    StdError, StdResult, Storage, Uint256,
};
use secret_toolkit::permit::RevokedPermits;
use secret_toolkit::snip20::{register_receive_msg, set_viewing_key_msg};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};
use secret_toolkit_crypto::{sha_256, Prng};

use crate::msg::{Config, StakingInfo};
use crate::msg::{
    ContractStatusLevel, ExecuteAnswer, ExecuteMsg, InstantiateMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::state::{
    CONFIG, CONTRACT_STATUS, PREFIX_REVOKED_PERMITS, RESPONSE_BLOCK_SIZE, STAKING_CONFIG,
};

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
    let admin = match msg.admin {
        Some(admin_addr) => deps.api.addr_validate(admin_addr.as_str())?,
        None => info.sender.clone(),
    };

    CONFIG.save(
        deps.storage,
        &Config {
            admin,
            name: msg.name,
            symbol: msg.symbol,
            contract_address: env.contract.address.clone(),
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
            staking_contract_info: msg.staking_contract_info,
            fee_info: msg.fee_info,
        },
    )?;

    let msgs: Vec<CosmosMsg> = vec![
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
        //Receiver interface
        ExecuteMsg::Receive {
            sender: _,
            from,
            amount,
            msg,
        } => try_stake(deps, env, info, from, amount, msg),
        ExecuteMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, info, entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, info, key),
        ExecuteMsg::ChangeAdmin { address, .. } => change_admin(deps, info, address),
        ExecuteMsg::SetContractStatus { level, .. } => set_contract_status(deps, info, level),
        ExecuteMsg::RevokePermit { permit_name, .. } => revoke_permit(deps, info, permit_name),
    };

    pad_handle_result(response, RESPONSE_BLOCK_SIZE)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    pad_query_result(
        match msg {
            QueryMsg::ContractStatus {} => query_contract_status(deps.storage),
            QueryMsg::WithPermit {
                permit: _,
                query: _,
            } => Err(StdError::generic_err("Not implemented")),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

/************ HANDLES ************/
/// Try to stake SHD received tokens
///
/// Interacts directly with the Staking contract
///
/// @param amount of receiving tokens
fn try_stake(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    // Staker address
    _from: Addr,
    _amount: Uint256,
    _msg: Option<Binary>,
) -> StdResult<Response> {
    let staking_config = STAKING_CONFIG.load(deps.storage)?;
    if info.sender != staking_config.shade_contract_info.address {
        return Err(StdError::generic_err("Sender is not SHD contract"));
    }

    Ok(Response::default())
}

fn change_admin(deps: DepsMut, info: MessageInfo, address: String) -> StdResult<Response> {
    let address = deps.api.addr_validate(address.as_str())?;

    let mut constants = CONFIG.load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    constants.admin = address;
    CONFIG.save(deps.storage, &constants)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ChangeAdmin { status: Success })?))
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
    check_if_admin(&constants.admin, &info.sender)?;

    CONTRACT_STATUS.save(deps.storage, &status_level)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetContractStatus {
            status: Success,
        })?),
    )
}

fn check_if_admin(config_admin: &Addr, account: &Addr) -> StdResult<()> {
    if config_admin != account {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, OwnedDeps, QueryResponse};

    use crate::msg::{ContractInfo as CustomContractInfo, FeeInfo, ResponseStatus};

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
            admin: Some("admin".to_string()),
            symbol: "SECSEC".to_string(),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
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
            fee_info: FeeInfo {
                collector: Addr::unchecked("collector_address"),
                fee_rate: 5,
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

        // Generate viewing key for staking contract
        let entropy: String = staking_contract_info.entropy.clone().unwrap();
        let (staking_contract_vk, new_seed) =
            new_viewing_key(&info.sender.clone(), &env, &prnd.0, entropy.as_ref());

        // Generate viewing key for SHD contract
        let entropy: String = shade_contract_info.entropy.clone().unwrap();
        let (shade_contract_vk, _new_seed) =
            new_viewing_key(&info.sender.clone(), &env, &new_seed, entropy.as_ref());

        let msgs: Vec<CosmosMsg> = vec![
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
        assert_eq!(constants.admin, Addr::unchecked("admin".to_string()));
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
    fn test_handle_change_admin() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::ChangeAdmin {
            address: "bob".to_string(),
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = CONFIG.load(&deps.storage).unwrap().admin;
        assert_eq!(admin, Addr::unchecked("bob".to_string()));
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
            msg: None,
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(handle_result.is_err());
        let error = extract_error_msg(handle_result);

        assert_eq!(error, "Sender is not SHD contract");
    }

    #[test]
    fn test_receive_msg_successfully() {
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
            msg: None,
        };
        let info = mock_info("shade_contract_info_address", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
    }
}
