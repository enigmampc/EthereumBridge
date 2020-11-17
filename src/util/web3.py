import json
import os
from threading import Lock
from typing import List, Tuple, Optional, Generator

from web3 import Web3, HTTPProvider
from web3.contract import Contract as Web3Contract
from web3.datastructures import AttributeDict
from web3.logs import DISCARD
from web3.types import BlockData

from src.util.common import project_base_path
from src.util.config import config


def web3_provider(address_: str) -> Web3:
    if address_.startswith('http'):  # HTTP
        return Web3(Web3.HTTPProvider(address_))
    if address_.startswith('ws'):  # WebSocket
        return Web3(Web3.WebsocketProvider(address_))
    return Web3(Web3.IPCProvider(address_))


w3: Web3 = web3_provider(config.eth_node)

w3_lock = Lock()
event_lock = Lock()


def get_block(block_identifier, full_transactions: bool = False):
    with w3_lock:
        res = w3.eth.getBlock(block_identifier, full_transactions)
    return res


def extract_tx_by_address(address, block: BlockData) -> list:
    # Note: block attribute dict has to be generated with full_transactions=True flag
    return [tx for tx in block.transactions if tx.to and address.lower() == tx.to.lower()]


def event_log(tx_hash: str, events: List[str], provider: Web3, contract: Web3Contract) -> \
        Tuple[str, Optional[AttributeDict]]:
    """
    Extracts logs of @event from tx_hash if present
    :param tx_hash:
    :param events: Case sensitive events name
    :param provider:
    :param contract: Web3 Contract
    :return: event name and log represented in 'AttributeDict' or 'None' if not found
    """

    receipt = provider.eth.getTransactionReceipt(tx_hash)
    for event in events:
        # we discard warning as we do best effort to find wanted event, not always there
        # as we listen to the entire contract tx, might
        log = getattr(contract.events, event)().processReceipt(receipt, DISCARD)
        if log:
            data_index = 0
            return event, log[data_index]
    # todo: fix this - seems like some weird return
    return '', None


def normalize_address(address: str):
    """Converts address to address acceptable by web3"""
    return Web3.toChecksumAddress(address.lower())


def contract_event_in_range(contract, event_name: str, from_block: int = 0,
                            to_block: Optional[int] = None) -> Generator:
    """
    scans the blockchain, and yields blocks that has contract tx with the provided event

    Note: Be cautions with the range provided, as the logic creates query for each block which could be a bottleneck.
    :param from_block: starting block, defaults to 0
    :param to_block: end block, defaults to 'latest'
    :param provider:
    :param logger:
    :param contract:
    :param event_name: name of the contract emit event you wish to be notified of
    """
    if to_block is None:
        to_block = w3.eth.blockNumber

    with w3_lock:

        if isinstance(w3.provider, HTTPProvider):
            for block_num in range(from_block, to_block + 1):
                block = w3.eth.getBlock(block_num, full_transactions=True)
                contract_transactions = extract_tx_by_address(contract.address, block)

                if not contract_transactions:
                    continue
                for tx in contract_transactions:
                    _, log = event_log(tx_hash=tx.hash, events=[event_name], provider=w3, contract=contract.tracked_contract)
                    if log is None:
                        continue
                    yield log
        else:
            event = getattr(contract.tracked_contract.events, event_name)
            event_filter = event.createFilter(fromBlock=from_block, toBlock=to_block)

            for tx in event_filter.get_new_entries():
                _, log = event_log(tx_hash=tx.hash, events=[event_name], provider=w3, contract=contract.tracked_contract)

                if log is None:
                    continue

                yield log


def estimate_gas_price():
    return w3.eth.gasPrice


def send_contract_tx(contract: Web3Contract, function_name: str, from_acc: str, private_key: bytes,
                     gas: int = 0, gas_price: int = 0, value: int = 0, args: Tuple = ()):
    """
    Creates the contract tx and signs it with private_key to be transmitted as raw tx

    """

    tx = getattr(contract.functions, function_name)(*args). \
        buildTransaction(
        {
            'from': from_acc,
            'chainId': w3.eth.chainId,
            # gas_price is in gwei
            'gasPrice': gas_price * 1e9 if gas_price else estimate_gas_price(),
            'gas': gas or None,
            'nonce': w3.eth.getTransactionCount(from_acc, block_identifier='pending'),
            'value': value
        })
    signed_txn = w3.eth.account.sign_transaction(tx, private_key)
    return w3.eth.sendRawTransaction(signed_txn.rawTransaction)


def erc20_contract():
    abi_path = os.path.join(project_base_path(), 'src', 'contracts', 'ethereum', 'abi', 'IERC20.json')
    with open(abi_path, "r") as f:
        abi = json.load(f)['abi']
    return w3.eth.contract(abi=abi)
