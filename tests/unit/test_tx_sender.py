import json

from src.util.coins import CoinHandler
from src.db import database
from src.util.eth.tx_sender import TxSender
from src.util.config import config
from src.util.web3 import web3_provider


def create_tx():

    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key("9e9c1518c040444a8a549da38d42ecdbce5bc77deb6c136c180b1b1327c52c76")
    # balance = w3.eth.getBalance(account.address, "latest")
    # if balance < 1000000000000:
    #     print("You gotta have some cash dawg")
    #     return

    nonce = w3.eth.getTransactionCount(account.address, "pending")

    signed_tx = account.sign_transaction(dict(nonce=nonce,
                                              gasPrice=w3.eth.gasPrice,
                                              gas=100000,
                                              to='0x55810874c137605b96e9d2B76C3089fcC325ed5d',
                                              value=100000,
                                              data=b''))
    return signed_tx.rawTransaction
    # tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    # # .transact()
    # # Get transaction hash from deployed contract
    # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    # print(f"Deployed at: {tx_receipt.contractAddress}")
    # multisig_wallet = w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_source_code['abi'])
    # print("All done")


def test_tx_sender():
    tx = create_tx()

    sender = TxSender()
    sender.broadcast_transaction(tx)
    import time
    while True:
        if sender.is_alive():
            print("Still sending..")
        else:
            break
        time.sleep(5)
