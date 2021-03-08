from subprocess import CalledProcessError
from threading import Event, Thread
from typing import List, Tuple

from mongoengine.errors import NotUniqueError
from pymongo.errors import DuplicateKeyError
from web3.exceptions import TransactionNotFound

import src.contracts.ethereum.message as message
from src.contracts.ethereum.ethr_contract import broadcast_transaction
from src.contracts.ethereum.event_listener import EthEventListener
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.secret.secret_contract import swap_query_res, get_swap_id
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.scrt_retry import ScrtRetry
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.db.collections.token_map import TokenPairing
from src.leader.eth.eth_confirmationer import EthConfirmer
from src.util.coins import CoinHandler
from src.util.common import Token, swap_retry_address
from src.util.config import Config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.logger import get_logger
from src.util.oracle.oracle import BridgeOracle
from src.util.secretcli import query_scrt_swap
from src.util.web3 import erc20_contract, w3


def _parse_db_tx(tx: Swap) -> Tuple[str, int]:
    nonce, token = tx.src_tx_hash.split('|')
    return token, int(nonce)


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
        config: Config,
        **kwargs
    ):
        self.config = config
        self.multisig_wallet = multisig_wallet
        self.erc20 = erc20_contract()
        self.pending_txs: List[str] = []
        self.token_map = {}

        self.signer = signer
        self._coins = CoinHandler()
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or self.__class__.__name__
        )
        self.stop_event = Event()

        self.threads = {
            'confirmer': EthConfirmer(self.multisig_wallet, self.logger),
            'events': EthEventListener(self.multisig_wallet, config)
        }
        super().__init__(group=None, name="EtherLeader", target=self.run, **kwargs)

    @property
    def event_listener(self):
        return self.threads['events']

    @property
    def confirmer(self):
        return self.threads['confirmer']

    def running(self):
        return self.is_alive() and self.event_listener.is_alive()

    def stop(self):
        self.logger.info("Stopping")
        self.event_listener.stop()
        self.stop_event.set()

    def run(self):
        self.logger.info("Starting")

        # todo: fix so tracker doesn't start from 0
        from_block = SwapTrackerObject.get_or_create(src="Ethereum").nonce

        self.event_listener.register(self.confirmer.submit, ['Submission'], from_block=from_block)
        self.event_listener.register(self.confirmer.withdraw, ['Withdraw'], from_block=from_block)
        self.event_listener.register(self.confirmer.failed_withdraw, ['WithdrawFailure'], from_block=from_block)
        self.event_listener.start()

        self._scan_swap()

    def _refresh_token_map(self):
        token_map = {}
        pairs = TokenPairing.objects(src_network=self.network)
        for pair in pairs:
            token_map.update({pair.dst_address: Token(pair.src_address, pair.src_coin)})

        self.token_map = token_map

    # def _retry(self, tx: Swap):
    #     ScrtRetry(swap=tx.id, original_contract=tx.dst_address).save()
    #     tx.dst_address = swap_retry_address
    #     tx.status = Status.SWAP_UNSIGNED
    #     tx.save()

    def _scan_swap(self):
        """ Scans secret network contract for swap events """
        self.logger.info(f'Starting for account {self.signer.address} with tokens: {self.token_map=}')
        while not self.stop_event.is_set():

            num_of_tokens = TokenPairing.objects(src_network=self.network).count()
            if num_of_tokens != len(self.token_map.keys()):
                self._refresh_token_map()
                self.logger.info(f'Refreshed tracked tokens. Now tracking {len(self.token_map.keys())} tokens')

            for transaction in Swap.objects(status=Status.SWAP_RETRY, src_network="Secret"):
                # self._handle_swap(swap_data, token, self.token_map[token].address)
                try:
                    token, nonce = _parse_db_tx(transaction)
                    swap_data = query_scrt_swap(nonce, self.config.scrt_swap_address, token)
                    # self._retry(transaction)
                    self._handle_swap(swap_data, token, self.token_map[token].address, True)
                except Exception as e:  # pylint: disable=broad-except
                    self.logger.error(f'Failed to retry swap: {e}')
                    transaction.update(status=Status.SWAP_FAILED)

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

    def _tx_native_params(self, amount: int, dest_address: str, retry: bool) -> Tuple[bytes, str, int, str, int]:
        # if fee isn't 0 this will fail because tx_token isn't the ERC20 address from which to collect the fee
        if retry:
            fee = 0
        elif self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
            fee = int(gas_price * 1e9 * self.multisig_wallet.SUBMIT_GAS)
            self.logger.info(f'calculated fee: {fee}')
        else:
            fee = 1

        if fee >= amount:
            raise ValueError

        tx_dest = dest_address
        # use address(0) for native ethereum swaps
        tx_token = '0x0000000000000000000000000000000000000000'
        tx_amount = int(amount - fee)
        data = b''
        # self.logger.info(f'{tx_dest}, {tx_amount}, {tx_token}, {fee}')
        return data, tx_dest, tx_amount, tx_token, fee

    def _tx_erc20_params(self, amount, dest_address, dst_token: str, retry: bool) -> Tuple[bytes, str, int, str, int]:
        # if fee isn't 0 this will fail because tx_token isn't the ERC20 address from which to collect the fee
        if retry:
            fee = 0
        elif self.config.network == "mainnet":
            decimals = self._coins.decimals(dst_token)
            try:
                x_rate = BridgeOracle.x_rate('ETH', self._coins.coin(dst_token))
            except Exception:  # pylint: disable=broad-except
                self.logger.warning(f"Failed to get price for token {dst_token} - falling back to db price")
                eth = TokenPairing.objects().get(name="Ethereum").price
                token = TokenPairing.objects().get(src_address=dst_token).price
                x_rate = float(eth) / float(token)

            self.logger.info(f'Calculated exchange rate: {x_rate=}')
            gas_price = BridgeOracle.gas_price()
            fee = BridgeOracle.calculate_fee(self.multisig_wallet.SUBMIT_GAS,
                                             gas_price,
                                             decimals,
                                             x_rate,
                                             amount)
            self.logger.info(f'Fee taken: {fee}')
        # for testing mostly
        else:
            fee = 1

        if fee >= amount:
            raise ValueError

        checksum_addr = w3.toChecksumAddress(dest_address)
        data = self.erc20.encodeABI(fn_name='transfer', args=[checksum_addr, amount - fee])
        tx_dest = dst_token
        tx_token = dst_token
        tx_amount = 0

        return data, tx_dest, tx_amount, tx_token, fee

    def _handle_swap(self, swap_data: str, src_token: str, dst_token: str, retry=False):
        swap_json = swap_query_res(swap_data)
        # this is an id, and not the TX hash since we don't actually know where the TX happened, only the id of the
        # swap reported by the contract
        swap_id = get_swap_id(swap_json)
        dest_address = swap_json['destination']
        self.logger.debug(f'{swap_json}')
        amount = int(swap_json['amount'])

        swap_failed = False
        fee = 0
        data = b''
        nonce = int(swap_json['nonce'])
        swap = None

        try:
            if dst_token == 'native':
                data, tx_dest, tx_amount, tx_token, fee = self._tx_native_params(amount, dest_address, retry)
            else:
                self.erc20.address = dst_token
                data, tx_dest, tx_amount, tx_token, fee = self._tx_erc20_params(amount, dest_address, dst_token, retry)

            if retry:

                original_nonce = nonce
                nonce = int(self.multisig_wallet.get_token_nonce(swap_retry_address) + 1)  # + 1 to advance the counter

                swap = Swap.objects.get(src_tx_hash=swap_id)
                swap.status = Status.SWAP_FAILED

                self.update_retry_db(f"{original_nonce}|{tx_token}", f"{nonce}|{swap_retry_address.lower()}")

                tx_token = w3.toChecksumAddress(swap_retry_address)

            msg = message.Submit(w3.toChecksumAddress(tx_dest),
                                 tx_amount,  # if we are swapping token, no ether should be rewarded
                                 nonce,
                                 tx_token,
                                 fee,
                                 data)

        except ValueError as e:
            self.logger.error(f"Error: {e}")
            swap_failed = True

        # this could have already been set by retry
        if not swap:
            swap = Swap(src_network="Secret", src_tx_hash=swap_id, unsigned_tx=data, src_coin=src_token,
                        dst_coin=dst_token, dst_address=dest_address, amount=str(amount), dst_network="Ethereum",
                        status=Status.SWAP_FAILED)

        if swap_failed or not self._validate_fee(amount, fee):
            self._save_failed_swap(swap, swap_id)
        else:
            self._broadcast_and_save(msg, swap, swap_id)

    def _save_failed_swap(self, swap, swap_id):
        self.logger.error(f"Swap failed. Check that amount is not too low to cover fee "
                          f"and that destination address is valid: {swap_id}")
        try:
            swap.save()
        except (DuplicateKeyError, NotUniqueError):
            pass

    @staticmethod
    def update_retry_db(original_id, retry_id):
        try:
            ScrtRetry(retry_id=retry_id, original_id=original_id).save()
        except (NotUniqueError, DuplicateKeyError) as e:
            raise NotUniqueError('Failed to send swap again - possible duplicate') from e

    def _broadcast_and_save(self, msg: message.Submit, swap: Swap, swap_id: str):
        try:
            tx_hash = self._broadcast_transaction(msg)
            swap.dst_tx_hash = tx_hash

            swap.status = Status.SWAP_SUBMITTED
            self.pending_txs.append(swap_id)
        except (ValueError, TransactionNotFound) as e:
            self.logger.critical(f"Failed to broadcast transaction for msg {repr(msg)}: {e}")
        finally:
            try:
                swap.save()
            except (DuplicateKeyError, NotUniqueError):
                pass

    def _check_remaining_funds(self):
        remaining_funds = w3.eth.getBalance(self.signer.address)
        self.logger.info(f'ETH leader remaining funds: {w3.fromWei(remaining_funds, "ether")} ETH')
        fund_warning_threshold = self.config.eth_funds_warning_threshold
        if remaining_funds < w3.toWei(fund_warning_threshold, 'ether'):
            self.logger.warning(f'ETH leader {self.signer.address} has less than {fund_warning_threshold} ETH left - '
                                f'{remaining_funds}')

    def _broadcast_transaction(self, msg: message.Submit):
        if self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
            self.logger.info(f'Current {gas_price=}Gwei')
        else:
            gas_price = None

        self._check_remaining_funds()

        data = self.multisig_wallet.encode_data('submitTransaction', *msg.args())
        tx = self.multisig_wallet.raw_transaction(
            self.signer.address, 0, data, gas_price,
            gas_limit=self.multisig_wallet.SUBMIT_GAS
        )
        tx = self.multisig_wallet.sign_transaction(tx, self.signer)

        tx_hash = broadcast_transaction(tx)

        self.logger.info(msg=f"Submitted tx: hash: {tx_hash.hex()}, msg: {msg}")
        return tx_hash.hex()
