from subprocess import CalledProcessError
from threading import Event, Thread

from mongoengine.errors import NotUniqueError
from pymongo.errors import DuplicateKeyError
from web3.exceptions import TransactionNotFound

import src.contracts.ethereum.message as message
from src.contracts.ethereum.ethr_contract import broadcast_transaction
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.secret.secret_contract import swap_query_res, get_swap_id
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.db.collections.token_map import TokenPairing
from src.util.coins import Erc20Info, Coin
from src.util.common import Token
from src.util.config import Config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.logger import get_logger
from src.util.oracle.oracle import BridgeOracle
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

    def __init__(
        self,
        multisig_wallet: MultisigWallet,
        signer: CryptoManagerBase,
        dst_network: str,
        config: Config,
        **kwargs
    ):
        self.config = config
        self.multisig_wallet = multisig_wallet
        self.erc20 = erc20_contract()

        token_map = {}
        pairs = TokenPairing.objects(dst_network=dst_network, src_network=self.network)
        for pair in pairs:
            token_map.update({pair.dst_address: Token(pair.src_address, pair.src_coin)})
        self.signer = signer
        # self.private_key = private_key
        # self.default_account = account
        self.token_map = token_map
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or self.__class__.__name__
        )
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
        self.logger.info(f'Starting for account {self.signer.address} with tokens: {self.token_map=}')
        while not self.stop_event.is_set():
            for token in self.token_map:
                try:
                    swap_tracker = SwapTrackerObject.get_or_create(src=token)
                    next_nonce = swap_tracker.nonce + 1

                    self.logger.debug(f'Scanning token {token} for query #{next_nonce}')

                    swap_data = query_scrt_swap(next_nonce, self.config.scrt_swap_address, token)

                    self._handle_swap(swap_data, token, self.token_map[token].address)
                    swap_tracker.nonce = next_nonce
                    swap_tracker.save()
                    next_nonce += 1

                except CalledProcessError as e:
                    if b'ERROR: query result: encrypted: Failed to get swap for token' not in e.stderr:
                        self.logger.error(f"Failed to query swap: stdout: {e.stdout} stderr: {e.stderr}")
                        # if b'ERROR: query result: encrypted: Failed to get swap for key' not in e.stderr:

            self.stop_event.wait(self.config.sleep_interval)

    @staticmethod
    def _validate_fee(amount: int, fee: int):
        return amount > fee

    def _tx_native_params(self, amount, dest_address):
        if self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
            fee = gas_price * 1e9 * self.multisig_wallet.SUBMIT_GAS
        else:
            fee = 1

        tx_dest = dest_address
        # use address(0) for native ethereum swaps
        tx_token = '0x0000000000000000000000000000000000000000'
        tx_amount = amount - fee
        data = b''

        return data, tx_dest, tx_amount, tx_token, fee

    def _tx_erc20_params(self, amount, dest_address, dst_token):
        if self.config.network == "mainnet":
            decimals = Erc20Info.decimals(dst_token)
            x_rate = BridgeOracle.x_rate(Coin.Ethereum, Erc20Info.coin(dst_token))
            gas_price = BridgeOracle.gas_price()
            fee = BridgeOracle.calculate_fee(self.multisig_wallet.SUBMIT_GAS,
                                             gas_price,
                                             decimals,
                                             x_rate,
                                             amount)
        # for testing mostly
        else:
            fee = 1

        data = self.erc20.encodeABI(fn_name='transfer', args=[dest_address, amount - fee])
        tx_dest = dst_token
        tx_token = dst_token
        tx_amount = 0

        return data, tx_dest, tx_amount, tx_token, fee

    def _handle_swap(self, swap_data: str, src_token: str, dst_token: str):
        swap_json = swap_query_res(swap_data)
        # this is an id, and not the TX hash since we don't actually know where the TX happened, only the id of the
        # swap reported by the contract
        swap_id = get_swap_id(swap_json)
        dest_address = swap_json['destination']
        self.logger.info(f'{swap_json}')
        amount = int(swap_json['amount'])

        if dst_token == 'native':
            data, tx_dest, tx_amount, tx_token, fee = self._tx_native_params(amount, dest_address)
        else:
            self.erc20.address = dst_token
            data, tx_dest, tx_amount, tx_token, fee = self._tx_erc20_params(amount, dest_address, dst_token)

        if not self._validate_fee(amount, fee):
            self.logger.error("Tried to swap an amount too low to cover fee")
            swap = Swap(src_network="Secret", src_tx_hash=swap_id, unsigned_tx=data, src_coin=src_token,
                        dst_coin=dst_token, dst_address=dest_address, amount=str(amount), dst_network="Ethereum",
                        status=Status.SWAP_FAILED)
            try:
                swap.save()
            except (DuplicateKeyError, NotUniqueError):
                pass
            return

        msg = message.Submit(tx_dest,
                             tx_amount,  # if we are swapping token, no ether should be rewarded
                             int(swap_json['nonce']),
                             tx_token,
                             fee,
                             data)
        # todo: check we have enough ETH
        swap = Swap(src_network="Secret", src_tx_hash=swap_id, unsigned_tx=data, src_coin=src_token,
                    dst_coin=dst_token, dst_address=dest_address, amount=str(amount), dst_network="Ethereum",
                    status=Status.SWAP_FAILED)
        try:
            tx_hash = self._broadcast_transaction(msg)
            swap.dst_tx_hash = tx_hash
            swap.status = Status.SWAP_SUBMITTED
        except (ValueError, TransactionNotFound) as e:
            self.logger.critical(f"Failed to broadcast transaction for msg {repr(msg)}: {e}")
        finally:
            try:
                swap.save()
            except (DuplicateKeyError, NotUniqueError):
                pass

    def _chcek_remaining_funds(self):
        remaining_funds = w3.eth.getBalance(self.signer.address)
        self.logger.info(f'ETH leader remaining funds: {w3.fromWei(remaining_funds, "ether")} ETH')
        fund_warning_threshold = self.config.eth_funds_warning_threshold
        if remaining_funds < w3.toWei(fund_warning_threshold, 'ether'):
            self.logger.warning(f'ETH leader {self.signer.address} has less than {fund_warning_threshold} ETH left')

    def _broadcast_transaction(self, msg: message.Submit):
        if self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
        else:
            gas_price = None

        self._chcek_remaining_funds()

        data = self.multisig_wallet.encode_data('submitTransaction', *msg.args())
        tx = self.multisig_wallet.raw_transaction(
            self.signer.address, 0, data, gas_price,
            gas_limit=self.multisig_wallet.SUBMIT_GAS
        )
        tx = self.multisig_wallet.sign_transaction(tx, self.signer)

        tx_hash = broadcast_transaction(tx)

        self.logger.info(msg=f"Submitted tx: hash: {tx_hash.hex()}, msg: {msg}")
        return tx_hash.hex()
