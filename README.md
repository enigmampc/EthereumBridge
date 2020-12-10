# Ethereum Bridge
This is a quick guide that explains how to setup a bridge between Secret and Ethereum.

## General

The Ethereum bridge transfers (value, data) between assets on the Ethereum network (ETH/ERC20) and Secret tokens, specified by the 
SNIP-20 spec. The bridge is bi-directional, so those SNIP-20 assets can then be redeemed for their Ethereum equivalent.

### Architecture
The bridge uses a leader->signer architecture. The leader is responsible for watching the chain for new events. Once a 
new event is found, a transaction is proposed. 

The signers then take that proposed transaction, __validate that the proposed tx was indeed triggered by an on-chain event__
and then sign (or broadcast an approval for) the transaction.

On the ETH side, once the amount of signers passes the threshold it is executed automatically, while on the SCRT side we 
need an extra step done by the leader - broadcasting the signed transaction. The difference is due to how multisig is
implemented on the different networks.

On the SCRT side each pair of assets (e.g. ETH<->secretETH) is managed by 2 secret contracts. The first is the SNIP-20
contract itself, which manages the token. This is the contract that a user will interact with to manage his token. That way,
from the user's perspective, there is no difference between a bridged asset, and any other SNIP-20 asset (secret-secret, for instance). 

In the future the bridge may also scale to other networks beyond Ethereum

## Setup

### Tests

### Dependencies 
* jq
* secretcli 
* ganache-cli running locally on port 8545
* mongodb on port 27017
* Secret network dev environment

#### Run ganache

```ganache-cli```

#### Run secret network dev environment

```docker run -it --rm -p 26657:26657 -p 26656:26656 -p 1317:1317 --name secretdev enigmampc/secret-network-sw-dev:v1.0.2```

#### Make sure secretcli is runnable

You should be able to run secretcli directly (copy it to /usr/bin/ or something)
```
secretcli status 
```

#### Install dev dependencies

```
pip install -r requirements-dev.txt
```

#### Install Solidity contract dependencies
```
brownie pm install OpenZeppelin/openzeppelin-contracts@3.2.0
```

#### Run setup script
```
user@pc:.../EthereumBridge/tests/utils$ ./setup_secret_keys.sh 3 ../../keys/
```

#### Run Tests

```sh
export SGX_MODE=SW
python -m pytest tests/
```

### Run Local bridge

#### Upload Eth contracts and Secret Contracts

Use the scripts in ./deployment/deploy.py to deploy your eth & scrt contracts

#### Run the dockerfile

Use the example docker-compose file to customize your leader & signer parameters

## Manual swap


### Secret20 -> Ethereum/ERC-20 

Call the `send` method of the Secret20 token, with the recipient being the swap contract, and the `msg` field containing the
__base64 encoded__ ethereum address

```
secretcli tx compute execute '{"send": {"recipient": "secret1hx84ff3h4m8yuvey36g9590pw9mm2p55cwqnm6", "amount": "200", "msg": "MHhGQmE5OGFEMjU2QTM3MTJhODhhYjEzRTUwMTgzMkYxRTNkNTRDNjQ1"}}' --label <secret-contract-label> --from <key> --gas 350000'
```

### Ethereum -> Secret20

Call the method `swap` on our MultiSig contract, specifying the amount sent in the `value`, and the destination in the arguments.
Python example (see: swap_eth.py):
```python
    ...
    tx_hash = send_contract_tx(multisig_wallet.tracked_contract, 'swap',
                               account, bytes.fromhex(private_key), "secret13l72vhjngmg55ykajxdnlalktwglyqjqv9pkq4", value=200)
    ...
```

### ERC20 -> Secret20

Give the multisig contract allowance, then call the `swapToken` function on our multisig contract, which has the signature
`swapToken(bytes memory recipient, uint256 amount, address token)`. 
The first parameter being the destination address, the second being the amount of tokens, and the 3rd the address of the ERC-20
token we wish to transfer.

Note that the transaction will fail if attempted to transfer from a token which is not on the token whitelist

```python
TRANSFER_AMOUNT = 100

_ = erc20_contract.tracked_contract.functions.approve(multisig_wallet.address, TRANSFER_AMOUNT). \
    transact({'from': address})


tx_hash = multisig_wallet.tracked_contract.functions.swapToken(dest_address.encode(),
                                                       TRANSFER_AMOUNT,
                                                       erc20_contract.address). \
    transact({'from': web3_provider.eth.coinbase}).hex().lower()
```

##### Config Parameters

All these parameters can be overwritten by setting an environment variable with the same name. Set common variables in one
of the files in the ./config/ directory, and the rest by setting environment variables

* db_name - name of database
* signatures_threshold - number of signatures required to authorize transaction 
* eth_confirmations - number of blocks to wait on ethereum before confirming transactions
* eth_start_block - block number to start scanning events from  
* sleep_interval - time between checks for new swaps
* network - name of ethereum network
* chain_id - secret network chain-id
* multisig_wallet_address - Ethereum multisig contract address
* scrt_swap_address - address of secret contract handling our swaps
* swap_code_hash - code hash of the secret contract handling our swaps
* keys_base_path - path to directory with secret network key, and transactional key (id_tx_io.json)
* secretcli_home - path to secretcli config directory (/home/{user}/.secretcli)
* eth_address - ethereum address
* eth_private_key - ethereum private key
* secret_node - address of secret network rpc node
* eth_node - address of ethereum node (or service like infura)
* enclave_key - path to enclave key
* multisig_acc_addr - secret network multisig address
* multisig_key_name - secret network multisig name
* secret_signers - list of the public keys of addresses that comprise the address in `multisig_acc_addr`
* SWAP_ENV - either "TESTNET", "MAINNET" or "LOCAL" depending on environment
* mode - either "signer" or "leader" depending on operating mode
* db_username - database username
* db_password - database password
* db_host - hostname of database service provider

