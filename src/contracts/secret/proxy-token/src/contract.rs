/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    log, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr, InitResponse,
    Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};

use crate::msg::{
    space_pad, ContractStatusLevel, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::rand::sha_256;
use crate::receiver::Snip20ReceiveMsg;
use crate::state::{
    get_receiver_hash, read_viewing_key, set_receiver_hash, write_viewing_key, Config, Constants,
    ReadonlyBalances, ReadonlyConfig,
};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let init_config = msg.config();

    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,6}",
        ));
    }
    if msg.decimals > 18 {
        return Err(StdError::generic_err("Decimals must not exceed 18"));
    }

    let admin = msg.admin.unwrap_or_else(|| env.message.sender.clone());

    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    let mut config = Config::from_storage(&mut deps.storage);
    config.set_constants(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        admin: admin.clone(),
        prng_seed: prng_seed_hashed.to_vec(),
        swap_addr: msg.swap_addr,
        swap_code_hash: msg.swap_code_hash,
        token_addr: msg.token_addr.clone(),
        token_code_hash: msg.token_code_hash.clone(),
        total_supply_is_public: init_config.public_total_supply(),
    })?;
    config.set_minters(vec![admin])?;
    config.set_total_supply(0);
    config.set_contract_status(ContractStatusLevel::NormalRun);

    // Ferenginar FTW
    let message = secret_toolkit::snip20::register_receive_msg(
        env.contract_code_hash,
        None,
        256,
        msg.token_code_hash,
        msg.token_addr,
    )?;
    Ok(InitResponse {
        messages: vec![message],
        log: vec![],
    })
}

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();

    match contract_status {
        ContractStatusLevel::StopAll | ContractStatusLevel::StopAllButRedeems => {
            let response = match msg {
                HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_response(response);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }

    let response = match msg {
        // Base
        HandleMsg::RegisterReceive { code_hash, .. } => try_register_receive(deps, env, code_hash),
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Receiver interface (This is the proper proxy)
        HandleMsg::Receive {
            sender,
            amount,
            msg,
        } => try_forward_send(deps, env, sender, amount, msg),

        // Burn
        HandleMsg::Burn { amount, .. } => try_burn(deps, env, amount),

        // Mint
        HandleMsg::Mint {
            amount, recipient, ..
        } => try_mint(deps, env, recipient, amount),

        // Other
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
        HandleMsg::AddMinters { minters, .. } => add_minters(deps, env, minters),
        HandleMsg::RemoveMinters { minters, .. } => remove_minters(deps, env, minters),
        HandleMsg::SetMinters { minters, .. } => set_minters(deps, env, minters),
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::TokenInfo {} => query_token_info(&deps.storage),
        QueryMsg::Minters { .. } => query_minters(deps),
        _ => authenticated_queries(deps, msg),
    }
}

/// Burn tokens
///
/// Remove `amount` tokens from the system irreversibly, from signer account
///
/// @param amount the amount of money to burn
fn try_burn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    _amount: Uint128,
) -> StdResult<HandleResponse> {
    let constants = Config::from_storage(&mut deps.storage).constants()?;
    if constants.swap_addr != env.message.sender {
        return Err(StdError::generic_err(
            "only the swap contract can use the proxy to burn tokens",
        ));
    }

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Burn { status: Success })?),
    };

    Ok(res)
}

fn try_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    let minters = config.minters();
    if !minters.contains(&env.message.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let amount_raw = amount.u128();

    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_sub(amount_raw) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "This mint attempt would send more of the base token than is available",
        ));
    }
    config.set_total_supply(total_supply);

    let constants = config.constants()?;
    let message = secret_toolkit::snip20::transfer_msg(
        address,
        amount,
        None,
        256,
        constants.token_code_hash,
        constants.token_addr,
    )?;
    let res = HandleResponse {
        messages: vec![message],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Mint { status: Success })?),
    };

    Ok(res)
}

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;

        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(&deps, &address),
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn query_minters<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let minters = ReadonlyConfig::from_storage(&deps.storage).minters();

    let response = QueryAnswer::Minters { minters };
    to_binary(&response)
}

fn query_token_info<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128(config.total_supply()))
    } else {
        None
    };

    to_binary(&QueryAnswer::TokenInfo {
        name: constants.name,
        symbol: constants.symbol,
        decimals: constants.decimals,
        total_supply,
    })
}

pub fn query_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;

    let amount = Uint128(ReadonlyBalances::from_storage(&deps.storage).account_amount(&address));
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    let mut consts = config.constants()?;
    consts.admin = address;
    config.set_constants(&consts)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetViewingKey { status: Success })?),
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let constants = ReadonlyConfig::from_storage(&deps.storage).constants()?;
    let prng_seed = constants.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::CreateViewingKey { key })?),
    })
}

fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    status_level: ContractStatusLevel,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.set_contract_status(status_level);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}

fn try_add_receiver_api_callback<S: ReadonlyStorage>(
    messages: &mut Vec<CosmosMsg>,
    storage: &S,
    recipient: &HumanAddr,
    msg: Option<Binary>,
    sender: HumanAddr,
    from: HumanAddr,
    amount: Uint128,
) -> StdResult<()> {
    let receiver_hash = get_receiver_hash(storage, recipient);
    if let Some(receiver_hash) = receiver_hash {
        let receiver_hash = receiver_hash?;
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient.clone())?;

        messages.push(callback_msg);
    } else {
        return Err(StdError::not_found("Receiver not found for this recipient"));
    }
    Ok(())
}

fn try_forward_send<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    sender: HumanAddr,
    amount: Uint128,
    msg: Binary,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if constants.token_addr != env.message.sender {
        return Err(StdError::generic_err(
            "only the base contract can use the proxy",
        ));
    }

    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_add(amount.u128()) {
        total_supply = new_total_supply;
    } else {
        // This will probably never happen, as long as the contracts decimals are correctly configured.
        return Err(StdError::generic_err(
            "This send attempt would increase the total supply above the supported maximum",
        ));
    }
    config.set_total_supply(total_supply);

    let mut messages = vec![];
    try_add_receiver_api_callback(
        &mut messages,
        &deps.storage,
        &constants.swap_addr,
        Some(msg),
        sender.clone(),
        sender,
        amount,
    )?;
    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Receive { status: Success })?),
    };
    Ok(res)
}

fn try_register_receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    code_hash: String,
) -> StdResult<HandleResponse> {
    set_receiver_hash(&mut deps.storage, &env.message.sender, code_hash);
    let res = HandleResponse {
        messages: vec![],
        log: vec![log("register_status", "success")],
        data: Some(to_binary(&HandleAnswer::RegisterReceive {
            status: Success,
        })?),
    };
    Ok(res)
}

fn add_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_add: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.add_minters(minters_to_add)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddMinters { status: Success })?),
    })
}

fn remove_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_remove: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.remove_minters(minters_to_remove)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemoveMinters { status: Success })?),
    })
}

fn set_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_set: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.set_minters(minters_to_set)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMinters { status: Success })?),
    })
}

fn is_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<bool> {
    let consts = config.constants()?;
    if &consts.admin != account {
        return Ok(false);
    }

    Ok(true)
}

fn check_if_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<()> {
    if !is_admin(config, account)? {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    3 <= len && len <= 30
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = 3 <= len && len <= 6;

    len_is_valid && symbol.bytes().all(|byte| b'A' <= byte && byte <= b'Z')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::InitConfig;
    use crate::msg::ResponseStatus;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, QueryResponse};
    use secret_toolkit::snip20::TokenInfoResponse;
    use std::any::Any;

    // Helper functions
    const INSTANTIATOR: &str = "instantiator";
    const TOKEN_ADDR: &str = "secret1m2332v066t7ll6z9cr4ceyrfzvufj29thqfqjg";
    const TOKEN_HASH: &str = "secret1j8n6qxtpd8mlwkjmmk8vel8pdsq8hs996j6atr";
    const SWAP_ADDR: &str = "0xefbaf03ba2f8b21c231874fd8f9f1c69203f585cae481691812d8289916eff7a";
    const SWAP_HASH: &str = "5c36abd74f5959dd9e8bcecb2ea308befeaff2a50b9bcbd2338c079266f9f0bf";
    const SCRT_USER: &str = "secret1lqkcrz4s9mcexd3x53acc5k9xt3zkwnag9z6am";

    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env(INSTANTIATOR, &[]);

        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            admin: Some(INSTANTIATOR.into()),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            token_addr: TOKEN_ADDR.into(),
            token_code_hash: TOKEN_HASH.to_string(),
            swap_addr: SWAP_ADDR.into(),
            swap_code_hash: SWAP_HASH.to_string(),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(InitConfig::new(true)),
        };

        (init(&mut deps, env, init_msg), deps)
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

    fn ensure_success(handle_result: &HandleResponse) -> bool {
        let handle_result: HandleAnswer =
            from_binary(&handle_result.data.clone().unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Receive { status }
            | HandleAnswer::Burn { status }
            | HandleAnswer::RegisterReceive { status }
            | HandleAnswer::SetViewingKey { status }
            | HandleAnswer::Mint { status }
            | HandleAnswer::ChangeAdmin { status }
            | HandleAnswer::SetContractStatus { status }
            | HandleAnswer::SetMinters { status }
            | HandleAnswer::AddMinters { status }
            | HandleAnswer::RemoveMinters { status } => {
                matches!(status, ResponseStatus::Success {..})
            }
            _ => panic!("HandleAnswer not supported for success extraction"),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() -> StdResult<()> {
        let (init_result, deps) = init_helper();
        let message = secret_toolkit::snip20::register_receive_msg(
            "".to_string(),
            None,
            256,
            TOKEN_HASH.to_string(),
            HumanAddr(TOKEN_ADDR.to_string()),
        )?;
        let expected_result = InitResponse {
            messages: vec![message],
            log: vec![],
        };
        assert_eq!(init_result?, expected_result);

        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), 0);
        assert_eq!(config.contract_status(), ContractStatusLevel::NormalRun);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, INSTANTIATOR.into());
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(constants.token_addr.0, TOKEN_ADDR.to_string());
        assert_eq!(constants.swap_addr.0, SWAP_ADDR.to_string());
        assert_eq!(constants.token_code_hash, TOKEN_HASH.to_string());
        assert_eq!(constants.swap_code_hash, SWAP_HASH.to_string());
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, true);
        Ok(())
    }

    #[test]
    fn mint_and_redeem_eth_scrt() -> StdResult<()> {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Check that the total supply starts at zero
        let query_msg = QueryMsg::TokenInfo {};
        let query_response = query(&deps, query_msg)?;
        let token_info: TokenInfoResponse = from_binary(&query_response)?;
        assert_eq!(token_info.token_info.total_supply, Some(Uint128(0)));

        // Registed the swap contract with the proxy
        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: SWAP_HASH.into(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(SWAP_ADDR, &[]), handle_msg)?;
        assert!(ensure_success(&handle_response));

        // try to send a Receive from an address that isn't the token
        let send_message = Binary(b"custom message".to_vec());
        let handle_msg = HandleMsg::Receive {
            sender: SCRT_USER.into(),
            amount: Uint128(1000),
            msg: send_message.clone(),
        };
        let handle_result = handle(&mut deps, mock_env(SCRT_USER, &[]), handle_msg);
        let error_message = extract_error_msg(handle_result);
        assert_eq!(error_message, "only the base contract can use the proxy");

        // Send Receive from token to the proxy
        let send_message = Binary(b"custom message".to_vec());
        let handle_msg = HandleMsg::Receive {
            sender: SCRT_USER.into(),
            amount: Uint128(1000),
            msg: send_message.clone(),
        };
        let handle_response = handle(&mut deps, mock_env(TOKEN_ADDR, &[]), handle_msg)?;
        assert!(ensure_success(&handle_response));

        // The proxy forwards the message to the swap unmodified
        let receiver_msg = Snip20ReceiveMsg::new(
            SCRT_USER.into(),
            SCRT_USER.into(),
            Uint128(1000),
            Some(send_message),
        );
        let expected_message = receiver_msg.into_cosmos_msg(SWAP_HASH.into(), SWAP_ADDR.into())?;
        assert_eq!(handle_response.messages, vec![expected_message]);

        // Check that after the receive, the total supply went up
        let query_msg = QueryMsg::TokenInfo {};
        let query_response = query(&deps, query_msg)?;
        let token_info: TokenInfoResponse = from_binary(&query_response)?;
        assert_eq!(token_info.token_info.total_supply, Some(Uint128(1000)));

        // The swap replies with a burn. This is a no-op but just to make sure its there.
        let handle_msg = HandleMsg::Burn {
            amount: Uint128(1000),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(SWAP_ADDR, &[]), handle_msg)?;
        assert!(ensure_success(&handle_response));

        // Try to mint before registering the minter. should fail
        let handle_msg = HandleMsg::Mint {
            amount: Uint128(500),
            recipient: SCRT_USER.into(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env(SWAP_ADDR, &[]), handle_msg);
        let error_message = extract_error_msg(handle_result);
        assert_eq!(error_message, "Minting is allowed to minter accounts only");

        // Add the swap as a minter so that the mint can succeed
        let handle_msg = HandleMsg::AddMinters {
            minters: vec![SWAP_ADDR.into()],
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(INSTANTIATOR, &[]), handle_msg)?;
        assert!(ensure_success(&handle_response));

        // Mint the tokens. This returns a send request to the token, releasing funds to the recipient
        let handle_msg = HandleMsg::Mint {
            amount: Uint128(500),
            recipient: SCRT_USER.into(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(SWAP_ADDR, &[]), handle_msg)?;
        assert!(ensure_success(&handle_response));
        let expected_messages = vec![secret_toolkit::snip20::transfer_msg(
            SCRT_USER.into(),
            Uint128(500),
            None,
            256,
            TOKEN_HASH.into(),
            TOKEN_ADDR.into(),
        )?];
        assert_eq!(handle_response.messages, expected_messages);

        Ok(())
    }
}
