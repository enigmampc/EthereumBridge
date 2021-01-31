#!/bin/bash

set -xe

docker_name=secretdev

function secretcli2() {
  secretcli "$@";
}

function wait_for_tx() {
  until (secretcli q tx "$1"); do
      sleep 5
  done
}

export SGX_MODE=HW

deployer_name=t4

deployer_address=$(secretcli2 keys show -a $deployer_name)
echo "Deployer address: '$deployer_address'"

secretcli2 tx compute store "../compiled/token.wasm.gz" --from $deployer_name --gas 2000000 -b block -y
token_code_id=$(secretcli2 query compute list-code | jq '.[-1]."id"')
token_code_hash=$(secretcli2 query compute list-code | jq '.[-1]."data_hash"')
echo "Stored token: '$token_code_id', '$token_code_hash'"

secretcli2 tx compute store "../compiled/swap.wasm.gz" --from $deployer_name --gas 2000000 -b block -y
swap_code_id=$(secretcli2 query compute list-code | jq '.[-1]."id"')
swap_code_hash=$(secretcli2 query compute list-code | jq '.[-1]."data_hash"')
echo "Stored swap: '$swap_code_id', '$swap_code_hash'"

secretcli2 tx compute store "../compiled/proxy.wasm.gz" --from $deployer_name --gas 2000000 -b block -y
proxy_code_id=$(secretcli2 query compute list-code | jq '.[-1]."id"')
proxy_code_hash=$(secretcli2 query compute list-code | jq '.[-1]."data_hash"')
echo "Stored pair: '$proxy_code_id', '$proxy_code_hash'"

echo "Deploying token..."
label=$(date +"%T")

export STORE_TX_HASH=$(
  secretcli2 tx compute instantiate "$token_code_id" '{"admin": "'"$deployer_address"'", "symbol": "TST", "decimals": 6, "initial_balances": [{"address": "'"$deployer_address"'", "amount": "1000000000"}], "prng_seed": "YWE", "name": "test"}' --from $deployer_name --gas 1500000 --label "$label" -b block -y |
  jq -r .txhash
)
wait_for_tx "$STORE_TX_HASH" "Waiting for instantiate to finish on-chain..."
token_contract=$(secretcli2 query compute list-contract-by-code $token_code_id | jq '.[-1].address')
echo "token address: '$token_contract'"

echo "Deploying swap..."
label=$(date +"%T")
export STORE_TX_HASH=$(
  secretcli tx compute instantiate "$swap_code_id" '{"owner": "'"$deployer_address"'"}' --from $deployer_name --gas 1500000 --label "$label" -b block -y |
  jq -r .txhash
)
wait_for_tx "$STORE_TX_HASH" "Waiting for instantiate to finish on-chain..."

swap_contract=$(secretcli2 query compute list-contract-by-code $swap_code_id | jq '.[-1].address')
echo "swap address: '$swap_contract'"


echo "Deploying proxy..."
label=$(date +"%T")
export STORE_TX_HASH=$(
  secretcli tx compute instantiate "$proxy_code_id" '{"token_addr": '$token_contract', "token_code_hash": '$token_code_hash', "swap_code_hash": '$swap_code_hash', "swap_addr": '$swap_contract', "symbol": "TST", "decimals": 6, "prng_seed": "YWE", "name": "test"}' --from $deployer_name --gas 1500000 --label "$label" -b block -y |
  jq -r .txhash
)
wait_for_tx "$STORE_TX_HASH" "Waiting for instantiate to finish on-chain..."
proxy_contract=$(secretcli2 query compute list-contract-by-code $proxy_code_id | jq '.[-1].address')
echo "proxy address: '$proxy_contract'"

secretcli tx compute execute "$(echo "$swap_contract" | tr -d '"')" '{"add_token": {"address": '$proxy_contract', "code_hash": '$proxy_code_hash', "minimum_amount": "0"}}' --from $deployer_name -y --gas 1500000 -b block

secretcli tx compute execute "$(echo "$token_contract" | tr -d '"')" '{"send": {"recipient": '$proxy_contract', "amount": "100", "msg": "MHg0MjE5NDUyN0RkY2NBRUUxODkzMTNENzc0NThhZTQ5MWZBNDEyNTZB"}}' --from $deployer_name -y --gas 1500000 -b block
