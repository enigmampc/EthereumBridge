use crate::state::Swap;
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub owner: HumanAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    AddToken {
        address: HumanAddr,
        minimum_amount: Uint128, // Minimum amount allowed to swap
    },
    RemoveToken {
        address: HumanAddr,
    },
    ChangeOwner {
        owner: HumanAddr,
    },
    PauseSwap {},
    UnpauseSwap {},

    Receive {
        from: HumanAddr,
        msg: Option<Binary>,
        amount: Uint128,
    },
    UnlockFromExtChain {
        address: HumanAddr,
        identifier: String,
        amount: Uint128,
        token: HumanAddr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    Swap { nonce: u32, token: HumanAddr },
    MintById { identifier: String },
    Tokens {},
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    AddToken { status: ResponseStatus },
    RemoveToken { status: ResponseStatus },
    Receive { status: ResponseStatus, nonce: u32 },
    UnlockFromExtChain { status: ResponseStatus },
    ChangeOwner { status: ResponseStatus },
    UnpauseSwap { status: ResponseStatus },
    PauseSwap { status: ResponseStatus },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    Swap { result: Swap },
    Mint { result: bool },
    Tokens { result: Vec<HumanAddr> },
}
