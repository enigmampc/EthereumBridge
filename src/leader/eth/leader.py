import base64
from subprocess import CalledProcessError
from threading import Event, Thread

from web3.exceptions import TransactionNotFound
from pymongo.errors import DuplicateKeyError
from mongoengine.errors import NotUniqueError

import src.contracts.ethereum.message as message
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.secret.secret_contract import swap_query_res, get_swap_id
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.db.collections.token_map import TokenPairing
from src.util.common import Token
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import query_scrt_swap
from src.util.web3 import erc20_contract, w3


class EtherLeader(Thread):
    """
    secretETH --> Swap TX --> ETH

    On Ethereum the leader monitors the sETH Secret Contract. When it sees a new swap, it will
    broadcast a submit transaction on-chain.

    The account set here must have enough ETH for all the transactions you're planning on doing
    """
    network = "Ethereum"

    def __init__(self, multisig_wallet: MultisigWallet, private_key: bytes, account: str,
                 dst_network: str, config: Config, **kwargs):
        self.config = config
        self.multisig_wallet = multisig_wallet

        self.erc20 = erc20_contract()

        token_map = {}
        pairs = TokenPairing.objects(dst_network=dst_network, src_network=self.network)
        for pair in pairs:
            token_map.update({pair.dst_address: Token(pair.src_address, pair.src_coin)})

        self.private_key = private_key
        self.default_account = account
        self.token_map = token_map
        self.logger = get_logger(db_name=self.config['db_name'],
                                 logger_name=config.get('logger_name', self.__class__.__name__))
        self.stop_event = Event()
        super().__init__(group=None, name="EtherLeader", target=self.run, **kwargs)

    def stop(self):
        self.logger.info("Stopping")
        self.stop_event.set()

    def run(self):
        self.logger.info("Starting")
        self._scan_swap()

    def _scan_swap(self):
        """ Scans secret network contract for swap events """
        self.logger.info(f'Starting with {self.private_key=}, {self.default_account=} {self.token_map=}')
        while not self.stop_event.is_set():
            for token in self.token_map:
                try:
                    doc = SwapTrackerObject.get_or_create(src=token)
                    next_nonce = doc.nonce + 1

                    self.logger.debug(f'Scanning token {token} for query #{next_nonce}')

                    swap_data = query_scrt_swap(next_nonce, self.config["scrt_swap_address"], token)

                    self._handle_swap(swap_data, token, self.token_map[token].address)
                    doc.nonce = next_nonce
                    doc.save()
                    next_nonce += 1

                except CalledProcessError as e:
                    if b'ERROR: query result: encrypted: Failed to get swap for token' not in e.stderr:
                        self.logger.error(f"Failed to query swap: stdout: {e.stdout} stderr: {e.stderr}")
                        # if b'ERROR: query result: encrypted: Failed to get swap for key' not in e.stderr:

            self.stop_event.wait(self.config['sleep_interval'])

    def _handle_swap(self, swap_data: str, src_token: str, dst_token: str):
        swap_json = swap_query_res(swap_data)
        # this is an id, and not the TX hash since we don't actually know where the TX happened, only the id of the
        # swap reported by the contract
        swap_id = get_swap_id(swap_json)
        dest_address = base64.b64decode(swap_json['destination']).decode()
        data = b""
        amount = int(swap_json['amount'])
        if dst_token == 'native':
            # use address(0) for native ethereum
            msg = message.Submit(dest_address, amount, int(swap_json['nonce']),
                                 '0x0000000000000000000000000000000000000000', data)

        else:
            self.erc20.address = dst_token
            data = self.erc20.encodeABI(fn_name='transfer', args=[dest_address, amount])
            msg = message.Submit(dst_token,
                                 0,  # if we are swapping token, no ether should be rewarded
                                 int(swap_json['nonce']),
                                 dst_token,
                                 data)
        # todo: check we have enough ETH
        swap = Swap(src_network="Secret", src_tx_hash=swap_id, unsigned_tx=data, src_coin=src_token,
                    dst_coin=dst_token, dst_address=dest_address, amount=str(amount), dst_network="Ethereum",
                    status=Status.SWAP_FAILED)
        try:
            tx_hash = self._broadcast_transaction(msg)
            swap.dst_tx_hash = tx_hash
            swap.status = Status.SWAP_CONFIRMED
        except (ValueError, TransactionNotFound) as e:
            self.logger.critical(f"Failed to broadcast transaction for msg {repr(msg)}: {e}")
        finally:
            try:
                swap.save()
            except (DuplicateKeyError, NotUniqueError):
                pass

    def _broadcast_transaction(self, msg: message.Submit):
        tx_hash = self.multisig_wallet.submit_transaction(self.default_account, self.private_key, msg)
        self.logger.info(msg=f"Submitted tx: hash: {tx_hash.hex()}, msg: {msg}")
        return tx_hash.hex()
