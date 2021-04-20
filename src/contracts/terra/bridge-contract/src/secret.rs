use cosmwasm_std::{StdError, StdResult};
use ethereum_types::Address;
use std::str::FromStr;

pub fn validate_address(address: &str) -> StdResult<Address> {
    return if address.starts_with("secret1") {
        Address::from_str(address.trim_start_matches("secret1"))
            .map_err(|_| StdError::parse_err(address, "Failed to parse Secret Network address"))
    } else {
        Address::from_str(address)
            .map_err(|_| StdError::parse_err(address, "Failed to parse Secret Network address"))
    };
}
