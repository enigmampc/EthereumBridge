import json
from collections import namedtuple
from threading import Thread, Event
from typing import Dict

from mongoengine import OperationError

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.signatures import Signatures
from src.util.common import temp_file
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import sign_tx as secretcli_sign, decrypt, account_info

SecretAccount = namedtuple('SecretAccount', ['address', 'name'])


class Secret20Signer(Thread):
    """Signs on the SCRT side, after verifying Ethereum tx stored in the db"""

    def __init__(self, multisig: SecretAccount, contract: MultisigWallet, config: Config, **kwargs):
        self.multisig = multisig
        self.contract = contract
        self.config = config
        self.stop_event = Event()
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or f"SecretSigner-{self.multisig.name}"
        )
        super().__init__(group=None, name=f"SecretSigner-{self.multisig.name}", target=self.run, **kwargs)
        self.setDaemon(True)  # so tests don't hang
        self.account_num, _ = self._account_details()
        # signals.post_init.connect(self._tx_signal, sender=ETHSwap)  # TODO: test this with deployed db on machine

    def stop(self):
        self.logger.info("Stopping..")
        self.stop_event.set()

    def run(self):
        """Scans the db for unsigned swap tx and signs them"""
        self.logger.info("Starting..")
        while not self.stop_event.is_set():
            failed = False
            for tx in Swap.objects(status=Status.SWAP_UNSIGNED):

                # if there are 2 transactions that depend on each other (sequence number), and the first fails we mark
                # the next as "retry"
                if failed:
                    tx.status = Status.SWAP_RETRY
                    continue

                self.logger.info(f"Found new unsigned swap event {tx}")
                try:
                    self._validate_and_sign(tx)
                    self.logger.info(
                        f"Signed transaction successfully id:{tx.id}")
                except ValueError as e:
                    self.logger.error(f'Failed to sign transaction: {tx} error: {e}')
                    failed = True
            self.stop_event.wait(self.config.sleep_interval)

    def _validate_and_sign(self, tx: Swap):
        """
        Makes sure that the tx is valid and signs it

        :raises: ValueError
        """
        if self._is_signed(tx):
            self.logger.debug(f"This signer already signed this transaction. Waiting for other signers... id:{tx.id}")
            return

        if not self._is_valid(tx):
            self.logger.error(f"Validation failed. Signer: {self.multisig.name}. Tx id:{tx.id}.")
            tx.status = Status.SWAP_FAILED
            tx.save()
            raise ValueError

        try:
            signed_tx = self._sign_with_secret_cli(tx.unsigned_tx, tx.sequence)
        except RuntimeError as e:
            tx.status = Status.SWAP_FAILED
            tx.save()
            raise ValueError from e

        try:
            Signatures(tx_id=tx.id, signer=self.multisig.name, signed_tx=signed_tx).save()
        except OperationError as e:
            self.logger.error(f'Failed to save tx in database: {tx}')
            raise ValueError from e

    def _is_signed(self, tx: Swap) -> bool:
        """ Returns True if tx was already signed by us, else False """
        return Signatures.objects(tx_id=tx.id, signer=self.multisig.name).count() > 0

    def _is_valid(self, tx: Swap) -> bool:
        """Assert that the data in the unsigned_tx matches the tx on the chain"""
        log = self.contract.get_events_by_tx(tx.src_tx_hash)
        if not log:  # because for some reason event_log can return None???
            return False

        try:
            unsigned_tx = json.loads(tx.unsigned_tx)

            res = self._decrypt(unsigned_tx)
            self.logger.debug(f'Decrypted unsigned tx successfully {res}')
            json_start_index = res.find('{')
            json_end_index = res.rfind('}') + 1
            decrypted_data = json.loads(res[json_start_index:json_end_index])

        except json.JSONDecodeError:
            self.logger.error(f'Tried to load tx with hash: {tx.src_tx_hash} {tx.id}'
                              f'but got data as invalid json, or failed to decrypt')
            return False

        # extract address and value from unsigned transaction
        try:
            tx_amount = int(decrypted_data['mint_from_ext_chain']['amount'])
            tx_address = decrypted_data['mint_from_ext_chain']['address']
        except KeyError:
            self.logger.error(f"Failed to validate tx data: {tx}, {decrypted_data}, "
                              f"failed to get amount or destination address from tx")
            return False

        # extract amount from on-chain swap tx
        try:
            eth_on_chain_amount = self.contract.extract_amount(log)
            eth_on_chain_address = self.contract.extract_addr(log)
        except AttributeError:
            self.logger.error(f"Failed to validate tx data: {tx}, {log}, "
                              f"failed to get amount or address from on-chain eth tx")
            return False

        # check that amounts on-chain and in the db match the amount we're minting
        if tx_amount != eth_on_chain_amount or tx_amount != int(tx.amount):
            self.logger.error(f"Failed to validate tx data: {tx} ({tx_amount}, {eth_on_chain_amount}, {int(tx.amount)})"
                              f" amounts do not match")
            return False

        # check that the address we're minting to matches the target from the TX
        if tx_address != eth_on_chain_address:
            self.logger.error(f"Failed to validate tx data: {tx}, ({tx_address}, {eth_on_chain_address}),"
                              f" addresses do not match")
            return False

        return True

    def _sign_with_secret_cli(self, unsigned_tx: str, sequence: int) -> str:
        with temp_file(unsigned_tx) as unsigned_tx_path:
            res = secretcli_sign(unsigned_tx_path, self.multisig.address, self.multisig.name,
                                 self.account_num, sequence)

        return res

    @staticmethod
    def _decrypt(unsigned_tx: Dict):
        msg = unsigned_tx['value']['msg'][0]['value']['msg']
        return decrypt(msg)

    def _account_details(self):
        details = account_info(self.multisig.address)
        return details["value"]["account_number"], details["value"]["sequence"]
