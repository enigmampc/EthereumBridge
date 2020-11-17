import json
from datetime import datetime
from threading import Thread, Event
from typing import List

from mongoengine import OperationError

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.signatures import Signatures
from src.db.collections.token_map import TokenPairing
from src.leader.secret20.manager import SecretManager
from src.signer.secret20.signer import SecretAccount
from src.util.common import temp_file, temp_files, Token
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import broadcast, multisig_tx, query_data_success, get_uscrt_balance

BROADCAST_VALIDATION_COOLDOWN = 60
SCRT_BLOCK_TIME = 7


def _set_retry(tx: Swap):
    tx.status = Status.SWAP_RETRY
    tx.save()


class Secret20Leader(Thread):
    """ Broadcasts signed Secret-20 minting tx after successful ETH or ERC20 swap event """
    network = "Secret"

    def __init__(
        self,
        secret_multisig: SecretAccount,
        contract: MultisigWallet,
        src_network: str,
        config: Config,
        *args, **kwargs
    ):
        super().__init__(*args, **kwargs)

        token_map = {}
        pairs = TokenPairing.objects(dst_network=self.network, src_network=src_network)
        for pair in pairs:
            token_map.update({pair.src_address: Token(pair.dst_address, pair.dst_coin)})

        self.multisig_name = secret_multisig.name
        self.config = config
        self.manager = SecretManager(contract, token_map, secret_multisig, config)
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or f"{self.__class__.__name__}-{self.multisig_name}"
        )
        self.stop_event = Event()

        super().__init__(group=None, name="SecretLeader", target=self.run, **kwargs)

    def _catch_up(self):
        """ Scans the DB for signed swap tx at startup """
        # Note: As Collection.objects() call is cached, there shouldn't be collisions with DB signals
        for tx in Swap.objects(status=Status.SWAP_SIGNED).order_by('sequence'):
            self._create_and_broadcast(tx)

    def stop(self):
        self.logger.info("Stopping")
        self.manager.stop()
        self.stop_event.set()

    def run(self):
        self.logger.info("Starting")
        self.manager.start()
        self._scan_swap()

    def _scan_swap(self):
        while not self.stop_event.is_set():
            failed_prev = False
            for tx in Swap.objects(status=Status.SWAP_SIGNED, src_network="Ethereum"):
                # if there are 2 transactions that depend on each other (sequence number), and the first fails we mark
                # the next as "retry"
                if failed_prev:
                    self.logger.info(f"Previous TX failed, retrying {tx.id}")
                    _set_retry(tx)
                    continue

                self.logger.info(f"Found tx ready for broadcasting {tx.id}")
                failed_prev = not self._create_and_broadcast(tx)
            failed_prev = False
            for tx in Swap.objects(status=Status.SWAP_SUBMITTED, src_network="Ethereum"):
                if failed_prev:
                    self.logger.info(f"Previous TX failed, retrying {tx.id}")
                    _set_retry(tx)
                    continue
                failed_prev = not self._broadcast_validation(tx)

            self.logger.debug('done scanning for swaps. sleeping..')
            self.stop_event.wait(self.config.sleep_interval)

    def _create_and_broadcast(self, tx: Swap) -> bool:
        # reacts to signed tx in the DB that are ready to be sent to secret20
        signatures = [signature.signed_tx for signature in Signatures.objects(tx_id=tx.id)]
        if len(signatures) < self.config.signatures_threshold:  # sanity check
            self.logger.error(msg=f"Tried to sign tx {tx.id}, without enough signatures"
                                  f" (required: {self.config.signatures_threshold}, have: {len(signatures)})")
            return False

        try:
            signed_tx = self._create_multisig(tx.unsigned_tx, tx.sequence, signatures)
            scrt_tx_hash = self._broadcast(signed_tx)
            self.logger.info(f"Broadcasted {tx.id} successfully - {scrt_tx_hash}")
            tx.status = Status.SWAP_SUBMITTED
            tx.dst_tx_hash = scrt_tx_hash
            tx.save()
            self.logger.info(f"Changed status of tx {tx.id} to submitted")
            return True
        except (RuntimeError, OperationError) as e:
            self.logger.error(msg=f"Failed to create multisig and broadcast, error: {e}")
            tx.status = Status.SWAP_FAILED
            tx.save()
            return False

    def _create_multisig(self, unsigned_tx: str, sequence: int, signatures: List[str]) -> str:
        """Takes all the signatures of the signers from the db and generates the signed tx with them."""

        # creates temp-files containing the signatures, as the 'multisign' command requires files as input
        with temp_file(unsigned_tx) as unsigned_tx_path:
            with temp_files(signatures, self.logger) as signed_tx_paths:
                return multisig_tx(unsigned_tx_path, self.multisig_name,
                                   self.manager.account_num, sequence, *signed_tx_paths)

    def _check_remaining_funds(self):
        remaining_funds = get_uscrt_balance(self.manager.multisig.address)
        self.logger.debug(f'SCRT leader remaining funds: {remaining_funds / 1e6} SCRT')
        fund_warning_threshold = self.config.scrt_funds_warning_threshold
        if remaining_funds < fund_warning_threshold * 1e6:  # 1e6 uSCRT == 1 SCRT
            self.logger.warning(f'SCRT leader has less than {fund_warning_threshold} SCRT left')

    def _broadcast(self, signed_tx) -> str:
        self._check_remaining_funds()

        # Note: This operation costs Scrt
        with temp_file(signed_tx) as signed_tx_path:
            return json.loads(broadcast(signed_tx_path))['txhash']

    def _broadcast_validation(self, document: Swap) -> bool:  # pylint: disable=unused-argument
        """validation of submitted broadcast signed tx

        **kwargs needs to be here even if unused, because this function gets passed arguments from mongo internals
        """
        if not document.status == Status.SWAP_SUBMITTED or not document.src_network == "Ethereum":
            return False

        tx_hash = document.dst_tx_hash
        try:
            res = query_data_success(tx_hash)

            if res and res["mint_from_ext_chain"]["status"] == "success":
                self.logger.info("Updated status to confirmed")
                document.update(status=Status.SWAP_CONFIRMED)
                return True

            # maybe the block took a long time - we wait 60 seconds before we mark it as failed
            # The returned value is just here to let us know if we need to retry the next transactions
            if (datetime.utcnow() - document.updated_on).total_seconds() < BROADCAST_VALIDATION_COOLDOWN:
                return True

            # TX isn't on-chain. We can retry it
            document.update(status=Status.SWAP_RETRY)

            # update sequence number - just in case we failed because we are out of sync
            self.manager.update_sequence()
            self.logger.critical(f"Failed confirming broadcast for tx: {repr(document)}, Hash: {tx_hash}, res: {res}")
            return False
        except (ValueError, KeyError) as e:
            # TX failed for whatever reason. Might be a duplicate, out of gas, or any other reason
            self.logger.error(f"Failed confirming broadcast for tx: {repr(document)}. Error: {e}")
            # The DB update can fail, but if it does we want to crash - this can lead to
            # duplicate amounts and confusion. Better to just stop and make sure
            # everything is kosher before continuing
            document.update(status=Status.SWAP_FAILED)
            self.manager.update_sequence()
            return False
