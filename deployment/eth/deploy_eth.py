import json
import os
from typing import Tuple

from src.util.config import config
from src.util.web3 import web3_provider

signer_accounts = ["0x70154CB69220ABFbC7BDB07967e6437a2FfFb5bd"]

private_key = os.getenv('PRIVATE_KEY', '')


def add_token(token: str, min_amount: int, contract_address: str = None):
    with open('./src/contracts/ethereum/compiled/MultiSigSwapWallet.json', 'r') as f:
        contract_source_code = json.loads(f.read())
    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key(private_key)
    contract = w3.eth.contract(address=contract_address or config.multisig_wallet_address,
                               abi=contract_source_code['abi'],
                               bytecode=contract_source_code['data']['bytecode']['object'])
    nonce = w3.eth.getTransactionCount(account.address, "pending")
    tx = contract.functions.addToken(w3.toChecksumAddress(token), min_amount)
    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce, 'gasPrice': 120000000000})
    signed_tx = account.sign_transaction(raw_tx)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f"Done adding token: {tx_receipt=}")


def deploy_eth(contract: str, ctor: Tuple):
    with open(contract, 'r') as f:
        contract_source_code = json.loads(f.read())
    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key(private_key)
    print(f"Deploying on {config.network} from address {account.address}")
    # balance = w3.eth.getBalance(account.address, "latest")
    # if balance < 1000000000000:
    #     print("You gotta have some cash dawg")
    #     return
    # Instantiate and deploy contract
    contract = w3.eth.contract(abi=contract_source_code['abi'], bytecode=contract_source_code['data']['bytecode']['object'])
    tx = contract.constructor(*ctor)
    nonce = w3.eth.getTransactionCount(account.address, "pending")
    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
    signed_tx = account.sign_transaction(raw_tx)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    # .transact()
    # Get transaction hash from deployed contract
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f"Deployed at: {tx_receipt.contractAddress}")
    return tx_receipt.contractAddress


if __name__ == '__main__':

    contracts = [{
        "contract": './src/contracts/ethereum/compiled/MultiSigSwapWallet.json',
        "params": (signer_accounts, config.signatures_threshold, "0x70154CB69220ABFbC7BDB07967e6437a2FfFb5bd")
    },
        {
        "contract": './src/contracts/ethereum/compiled/TetherToken.json',
        "params": (0, "Tether", "USDT", 6)
    }]

    multisig = deploy_eth(contracts[0]["contract"], contracts[0]["params"])
    token = deploy_eth(contracts[1]["contract"], contracts[1]["params"])

    add_token(token, 1, multisig)
