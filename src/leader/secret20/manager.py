from threading import Thread, Event, Lock
from typing import Dict

from web3.datastructures import AttributeDict
from mongoengine.errors import NotUniqueError

from src.contracts.ethereum.event_listener import EthEventListener
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.secret.secret_contract import mint_json
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.signatures import Signatures
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.signer.secret20.signer import SecretAccount
from src.util.common import Token
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import create_unsigned_tx, account_info
from src.util.web3 import w3


class SecretManager(Thread):
    """Registers to contract event and manages tx state in DB"""

    def __init__(
        self,
        contract: MultisigWallet,
        token_to_secret_map: Dict[str, Token],
        s20_multisig_account: SecretAccount,
        config: Config,
        **kwargs
    ):
        self.contract = contract
        self.s20_map = token_to_secret_map
        self.config = config
        self.multisig = s20_multisig_account
        self.event_listener = EthEventListener(contract, config)

        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or f"{self.__class__.__name__}-{self.multisig.name}"
        )
        self.stop_signal = Event()
        self.account_num = 0
        self.sequence_lock = Lock()
        self.sequence = 0
        self.update_sequence()
        self.event_listener.register(self._handle, contract.tracked_event(),)
        super().__init__(group=None, name="SecretManager", target=self.run, **kwargs)

    @property
    def _sequence(self):
        return self.sequence

    @_sequence.setter
    def _sequence(self, val):
        with self.sequence_lock:
            self.sequence = val

    def stop(self):
        self.logger.info("Stopping..")
        self.event_listener.stop()
        self.stop_signal.set()

    def run(self):
        """Scans for signed transactions and updates status if multisig threshold achieved"""
        self.logger.info("Starting..")

        to_block = w3.eth.blockNumber - self.config.eth_confirmations

        self.catch_up(to_block)

        self.event_listener.start()
        self.logger.info("Done catching up")

        while not self.stop_signal.is_set():
            for transaction in Swap.objects(status=Status.SWAP_RETRY):
                self._retry(transaction)

            for transaction in Swap.objects(status=Status.SWAP_UNSIGNED):
                self.logger.debug(f"Checking unsigned tx {transaction.id}")
                if Signatures.objects(tx_id=transaction.id).count() >= self.config.signatures_threshold:
                    self.logger.info(f"Found tx {transaction.id} with enough signatures to broadcast")
                    transaction.status = Status.SWAP_SIGNED
                    transaction.save()
                    self.logger.info(f"Set status of tx {transaction.id} to signed")
                else:
                    self.logger.debug(f"Tx {transaction.id} does not have enough signatures")
            self.stop_signal.wait(self.config.sleep_interval)

    def catch_up(self, to_block: int):
        from_block = SwapTrackerObject.last_processed('Ethereum') + 1
        self.logger.debug(f'Starting to catch up from block {from_block}')
        if self.config.eth_start_block > from_block:
            self.logger.debug(f'Due to config fast forwarding to block {self.config.eth_start_block}')
            from_block = self.config.eth_start_block
            SwapTrackerObject.update_last_processed('Ethereum', from_block)

        if to_block <= 0 or to_block < from_block:
            return

        self.logger.debug(f'Catching up to current block: {to_block}')

        evt_filter = self.contract.contract.events.Swap.createFilter(fromBlock=from_block, toBlock=to_block)
        for event in evt_filter.get_all_entries():
            self._handle(event)

        evt_filter = self.contract.contract.events.SwapToken.createFilter(fromBlock=from_block, toBlock=to_block)
        for event in evt_filter.get_all_entries():
            self._handle(event)

        # for event_name in self.contract.tracked_event():
        #     for event in self.event_listener.events_in_range(event_name, from_block, to_block):
        #         self.logger.info(f'Found new event at block: {event["blockNumber"]}')

        SwapTrackerObject.update_last_processed('Ethereum', to_block)

    def _get_s20(self, foreign_token_addr: str) -> Token:
        return self.s20_map[foreign_token_addr]

    def _retry(self, tx: Swap):
        for signature in Signatures.objects(tx_id=tx.id):
            signature.delete()
        tx.status = Status.SWAP_UNSIGNED
        tx.sequence = self.sequence
        tx.save()
        self.sequence = self.sequence + 1

    def _handle(self, event: AttributeDict):
        """Extracts tx data from @event and add unsigned_tx to db"""
        if not self.contract.verify_destination(event):
            return

        amount = str(self.contract.extract_amount(event))

        try:
            block_number, tx_hash, recipient, token = self.contract.parse_swap_event(event)
            if token is None:
                token = 'native'
        except ValueError:
            return

        try:
            s20 = self._get_s20(token)
            mint = mint_json(amount, tx_hash, recipient, s20.address)
            unsigned_tx = create_unsigned_tx(
                self.config.scrt_swap_address,
                mint,
                self.config.chain_id,
                self.config.enclave_key,
                self.config.swap_code_hash,
                self.multisig.address
            )

            tx = Swap(src_tx_hash=tx_hash, status=Status.SWAP_UNSIGNED, unsigned_tx=unsigned_tx, src_coin=token,
                      dst_coin=s20.name, dst_address=s20.address, src_network="Ethereum", sequence=self.sequence,
                      amount=amount)
            tx.save(force_insert=True)
            self.sequence = self.sequence + 1
            self.logger.info(f"saved new Ethereum -> Secret transaction {tx_hash}, for {amount} {s20.name}")
            # SwapTrackerObject.update_last_processed(src=Source.ETH.value, update_val=block_number)
        except (IndexError, AttributeError) as e:
            self.logger.error(f"Failed on tx {tx_hash}, block {block_number}, "
                              f"due to missing config: {e}")
        except RuntimeError as e:
            self.logger.error(f"Failed to create swap tx for eth hash {tx_hash}, block {block_number}. Error: {e}")
        except NotUniqueError as e:
            self.logger.error(f"Tried to save duplicate TX, might be a catch up issue - {e}")
        # return block_number, tx_hash, recipient, s20
        SwapTrackerObject.update_last_processed('Ethereum', block_number)

    def _account_details(self):
        details = account_info(self.multisig.address)
        return details["value"]["account_number"], details["value"]["sequence"]

    def update_sequence(self):
        self.account_num, self.sequence = self._account_details()
