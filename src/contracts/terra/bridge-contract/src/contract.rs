use crate::msg::ResponseStatus::Success;
use crate::msg::{HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg};
use crate::secret::validate_address;
use crate::state::{config, config_read, Contract, Mint, State, Swap, TokenWhiteList};
use crate::token_messages::TokenMsgs;
use cosmwasm_std::{
    log, to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse, Querier,
    StdError, StdResult, Storage, Uint128,
};

pub fn _add_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: &Env,
    token_address: &HumanAddr,
    minimum_amount: Uint128,
) -> StdResult<TokenMsgs> {
    let params = Contract {
        address: deps.api.canonical_address(token_address)?,
        minimum_amount,
    };

    TokenWhiteList::add(&mut deps.storage, &params)?;

    let callback = TokenMsgs::RegisterReceive {};

    Ok(callback)
}

pub fn _rm_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    token_address: &HumanAddr,
) -> StdResult<()> {
    let address = deps.api.canonical_address(token_address)?;

    TokenWhiteList::remove(&mut deps.storage, &address)
}

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        owner: msg.owner,
        paused: false,
    };

    config(&mut deps.storage).save(&state)?;

    TokenWhiteList::new(&mut deps.storage)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::PauseSwap {} => pause_swap(deps, env),
        HandleMsg::UnpauseSwap {} => unpause_swap(deps, env),
        HandleMsg::ChangeOwner { owner } => change_owner(deps, env, owner),
        HandleMsg::AddToken {
            address,
            minimum_amount,
            ..
        } => add_token_contract(deps, env, address, minimum_amount),
        HandleMsg::RemoveToken { address, .. } => remove_token_contract(deps, env, address),
        HandleMsg::UnlockFromExtChain {
            address,
            identifier,
            amount,
            token,
            ..
        } => unlock_token(deps, env, address, identifier, amount, token),
        HandleMsg::Receive {
            amount, msg, from, ..
        } => lock_token(deps, env, from, amount, msg),
    }
}

fn unlock_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    address: HumanAddr,
    _identifier: String,
    amount: Uint128,
    token: HumanAddr,
) -> StdResult<HandleResponse> {
    // let params = TokenContractParams::load(&deps.storage).map_err(|_e| {
    //     StdError::generic_err("You fool you must set the token contract parameters first")
    // })?;
    let state = config(&mut deps.storage).load()?;
    if state.paused {
        return Err(StdError::generic_err("Swap contract is currently paused"));
    }

    let canonical = deps.api.canonical_address(&token)?;
    let params = TokenWhiteList::get(&deps.storage, &canonical)?;

    // let mint_store = Mint {
    //     address: deps.api.canonical_address(&address)?,
    //     identifier,
    //     amount,
    // };
    // mint_store.store(&mut deps.storage)?;

    let contract_addr = deps.api.human_address(&params.address)?;
    let mint_msg = TokenMsgs::Mint {
        amount,
        recipient: address.clone(),
    };

    Ok(HandleResponse {
        messages: vec![mint_msg.to_cosmos_msg(contract_addr)?],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::UnlockFromExtChain {
            status: Success,
        })?),
    })
}

fn pause_swap<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut params = config(&mut deps.storage).load()?;

    if params.owner != env.message.sender {
        return Err(StdError::generic_err(
            "Cannot pause swap from non owner address",
        ));
    }

    params.paused = true;

    config(&mut deps.storage).save(&params)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::PauseSwap { status: Success })?),
    })
}

fn unpause_swap<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut params = config(&mut deps.storage).load()?;

    if params.owner != env.message.sender {
        return Err(StdError::generic_err(
            "Cannot resume swap from non owner address",
        ));
    }

    params.paused = false;

    config(&mut deps.storage).save(&params)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::UnpauseSwap { status: Success })?),
    })
}

fn lock_token<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: Uint128,
    msg: Option<Binary>,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;
    if state.paused {
        return Err(StdError::generic_err("Swap contract is currently paused"));
    }

    let params = TokenWhiteList::get(
        &deps.storage,
        &deps.api.canonical_address(&env.message.sender)?,
    )
    .map_err(|_| StdError::generic_err("Unknown token"))?;

    // get params from receive callback msg
    let destination = String::from_utf8_lossy(msg.unwrap().as_slice()).to_string();

    // validate that destination is valid Secret Network address
    let _ = validate_address(&destination)?;

    if amount < params.minimum_amount {
        return Err(StdError::generic_err(format!(
            "Cannot swap amount under minimum of: {}",
            params.minimum_amount
        )));
    }

    let source = from.to_string();
    let token = env.message.sender;

    // store the swap details
    let mut swap_store = Swap {
        source,
        amount,
        destination,
        token,
        nonce: 0, // gets automatically set by .store()
    };
    let nonce = swap_store.store(&mut deps.storage)?;

    // send secret-20 burn message to token contract
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("tx_id", nonce)],
        data: Some(to_binary(&HandleAnswer::Receive {
            status: Success,
            nonce,
        })?),
    })
}

pub fn remove_token_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let params = config_read(&deps.storage).load()?;

    if params.owner != env.message.sender {
        return Err(StdError::generic_err(
            "Cannot remove token from non owner address",
        ));
    }

    _rm_token(deps, &address)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemoveToken { status: Success })?),
    })
}

pub fn change_owner<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut params = config(&mut deps.storage).load()?;

    if params.owner != env.message.sender {
        return Err(StdError::generic_err(
            "Cannot change owner from non owner address",
        ));
    }

    params.owner = owner;

    config(&mut deps.storage).save(&params)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeOwner { status: Success })?),
    })
}

pub fn add_token_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
    minimum_amount: Uint128,
) -> StdResult<HandleResponse> {
    let params = config_read(&deps.storage).load()?;

    if params.owner != env.message.sender {
        return Err(StdError::generic_err(
            "Cannot add token from non owner address",
        ));
    }

    let callback = _add_token(deps, &env, &address, minimum_amount)?;

    Ok(HandleResponse {
        messages: vec![callback.to_cosmos_msg(address)?],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddToken { status: Success })?),
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::Swap { nonce, token } => query_swap(deps, nonce, token),
        QueryMsg::MintById { identifier } => query_mint(deps, identifier),
        QueryMsg::Tokens {} => query_tokens(deps),
    }
}

pub fn query_tokens<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let tokens = TokenWhiteList::all(&deps.storage)?;

    let token_names: Vec<HumanAddr> = tokens
        .iter()
        .map(|a| deps.api.human_address(&a.address).unwrap())
        .collect();

    Ok(to_binary(&QueryAnswer::Tokens {
        result: token_names,
    })?)
}

pub fn query_swap<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    nonce: u32,
    token: HumanAddr,
) -> StdResult<Binary> {
    let swap = Swap::get(&deps.storage, &token, nonce).map_err(|_| {
        StdError::generic_err(format!(
            "Failed to get swap for token {} for key: {}",
            token.0, nonce
        ))
    })?;

    Ok(to_binary(&QueryAnswer::Swap { result: swap })?)
}

pub fn query_mint<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    identifier: String,
) -> StdResult<Binary> {
    let mint = Mint::exists(&deps.storage, &identifier);

    Ok(to_binary(&QueryAnswer::Mint { result: mint })?)
}

#[cfg(test)]
mod tests {}
