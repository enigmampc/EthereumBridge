import json
from abc import ABC, abstractmethod
from datetime import datetime
from subprocess import CalledProcessError
from typing import Iterable, List, Tuple, Any
import threading

from mongoengine import OperationError, NotUniqueError
from pymongo.errors import DuplicateKeyError

from ..contracts.secret import secret_contract
from ..db import Swap, Status, SwapTrackerObject, Signatures
from ..util.common import Token, SecretAccount, temp_file, temp_files
from ..util.config import Config
from ..util.logger import get_logger
from ..util import secretcli

from .common import Network, SwapEvent, SwapDirection
from .db import TokenPair


class SwapFailed(Exception):
    def __init__(self, event: SwapEvent, data: str = ''):
        """
        The `event` field is just the swap event.
        The data field is any additional data that the implementation wants
        to associate with the swap, e.g. contract call arguments.
        """
        super().__init__()
        self.event = event
        self.data = data


def get_tx_hash(nonce: str, token: str):
    """Used for creating the tx_hash that is stored in the "swap" db collection

    This is used in the egress leader because we don't currently pass that information from the secret network to the
    components of the bridge. The issue is that we query the secret contract for new swaps, but it has no way of
    telling the querier what the Secret-Network txhash was when it happened.
    """
    result = f'{nonce}|{token}'
    print(result)
    return result


def get_egress_swap_event(
    swap_contract_address: str,
    secret_coin_address: str,
    native_coin_address: str,
    coin_name: str,
    nonce: int,
):
    swap_data = secretcli.query_scrt_swap(nonce, swap_contract_address, secret_coin_address)
    swap_json = secret_contract.swap_query_res(swap_data)

    swap_event = SwapEvent(
        id=get_tx_hash(swap_json['nonce'], swap_json['token']),
        nonce=str(swap_json['nonce']),
        dst_coin_name=coin_name,
        dst_coin_address=native_coin_address,
        src_coin_address=secret_coin_address,
        direction=SwapDirection.FromSecretNetwork,
        amount=int(swap_json['amount']),
        sender=swap_json['source'],
        recipient=swap_json['destination'],
    )
    return swap_event


class Entity(ABC):
    """High level shared functionality of leaders and signers"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or type(self).__name__ + self.log_identifier()
        )
        self._thread = None
        self._stop_event = threading.Event()

    def log_identifier(self) -> str:
        return ''

    def start_thread(self):
        thread = threading.Thread(target=self.start, name=self.logger.name)
        thread.start()
        self._thread = thread

    def is_alive(self):
        if self._thread is not None:
            return self._thread.is_alive()
        return False

    def start(self):
        """Should be run in a separate thread, will run until `stop` is called"""
        while not self._stop_event.is_set():
            self.work()
            self._wait_for_updates()

    @abstractmethod
    def work(self):
        """This function will run once in a while, allowing the entity to perform tasks"""
        pass

    def _wait_for_updates(self):
        """Sleep for a while, before checking for new swap events"""
        self._stop_event.wait(self.config.sleep_interval)

    def stop(self):
        """Call this to stop the entity"""
        self.logger.info("Stopping")
        self._stop_event.set()


class EgressLeader(Entity):
    """Leads the signers responsible for swaps to foreign networks"""

    def __init__(self, config: Config):
        super().__init__(config)

        pairs = TokenPair.objects(network=self.native_network())
        # self.*_token_map lets us easily find the details of tokens
        # in one network using the address of the token in another.
        self._token_name_map = {}
        self._token_map = {}
        self._secret_token_map = {}
        for pair in pairs:
            self._token_name_map[pair.coin_address] = pair.coin_name
            self._token_map[pair.secret_coin_address] = Token(pair.coin_address, pair.coin_name, pair.decimals)
            self._secret_token_map[pair.coin_address] = Token(
                pair.secret_coin_address, pair.secret_coin_name, pair.decimals
            )

        self._swap_tracker = {sec_addr: SwapTrackerObject.get_or_create(src=sec_addr) for sec_addr in self._token_map}

    def work(self):
        """This is the high-level entry point for the leader"""
        for swap_event in self._get_new_swap_events():
            try:
                tx_hash = self._handle_swap(swap_event)
                self._store_swap(swap_event, tx_hash)
            except SwapFailed as err:
                self._store_failed_swap(err.event, err.data)

        completed_swaps = self.get_completed_swap_ids()
        for swap in completed_swaps:
            self.logger.info(f"marking swap {swap} as complete")
            self._mark_swap_complete(swap)

        failed_swaps = self.get_failed_swap_ids()
        for swap in failed_swaps:
            self.logger.info(f"marking swap {swap} as failed")
            self._mark_swap_failed(swap)

    def _get_new_swap_events(self) -> Iterable[SwapEvent]:
        """Leads the signers responsible for swaps out of the Secret Network"""
        for secret_coin_address, token in self._token_map.items():
            try:
                swap_tracker = self._swap_tracker[secret_coin_address]
                next_nonce = swap_tracker.nonce + 1
                self.logger.debug(f'Scanning token {secret_coin_address} for query #{next_nonce}')

                swap_event = get_egress_swap_event(
                    self.config.scrt_swap_address, secret_coin_address, token.address, token.name, next_nonce,
                )
                yield swap_event

                swap_tracker.nonce = next_nonce
                swap_tracker.save()

            # If one coin fails to give the information we need, just continue
            except CalledProcessError as e:
                if b'ERROR: query result: encrypted: Failed to get swap for token' not in e.stderr:
                    self.logger.error(f"Failed to query swap: stdout: {e.stdout} stderr: {e.stderr}")

    def _handle_swap(self, swap_event: SwapEvent) -> str:
        if swap_event.dst_coin_address == self.native_coin_address():
            return self.handle_native_swap(swap_event)
        else:
            return self.handle_non_native_swap(swap_event)

    @classmethod
    def _store_swap(cls, swap_event: SwapEvent, tx_hash: str):
        # TODO should we do something better than just this assertion?
        assert swap_event.direction == SwapDirection.FromSecretNetwork

        swap = Swap(
            src_network="Secret",
            src_tx_hash=swap_event.id,
            src_coin=swap_event.src_coin_address,
            dst_coin=swap_event.dst_coin_address,
            dst_network=cls.native_network().name,
            dst_address=swap_event.recipient,
            dst_tx_hash=tx_hash,
            unsigned_tx=swap_event.data,
            amount=str(swap_event.amount),
            status=Status.SWAP_SUBMITTED
        )
        try:
            swap.save()
        except (DuplicateKeyError, NotUniqueError):
            pass
        return

    @classmethod
    def _store_failed_swap(cls, swap_event: SwapEvent, data: str = ''):
        # TODO should we do something better than just this assertion?
        assert swap_event.direction == SwapDirection.FromSecretNetwork

        swap = Swap(
            src_network="Secret",
            src_tx_hash=swap_event.id,
            src_coin=swap_event.src_coin_address,
            dst_coin=swap_event.dst_coin_address,
            dst_network=cls.native_network().name,
            dst_address=swap_event.recipient,
            unsigned_tx=data,
            amount=str(swap_event.amount),
            status=Status.SWAP_FAILED
        )
        try:
            swap.save()
        except (DuplicateKeyError, NotUniqueError):
            pass
        return

    @staticmethod
    def _mark_swap_complete(swap_id: str):
        swap = Swap.objects().get(src_tx_hash=swap_id)
        if swap.status != Status.SWAP_SUBMITTED:
            return
        swap.update(status=Status.SWAP_CONFIRMED)

    @staticmethod
    def _mark_swap_failed(swap_id: str):
        swap = Swap.objects().get(src_tx_hash=swap_id)
        if swap.status != Status.SWAP_SUBMITTED:
            return
        swap.update(status=Status.SWAP_FAILED)

    @classmethod
    @abstractmethod
    def native_network(cls) -> Network:
        pass

    @classmethod
    @abstractmethod
    def native_coin_address(cls) -> str:
        pass

    @abstractmethod
    def handle_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a native coin, back to the native coin"""
        pass

    @abstractmethod
    def handle_non_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a non-native coin, back to the non-native coin

        An example of a non-native coin would be an ERC-20 coin.
        """
        pass

    @abstractmethod
    def get_completed_swap_ids(self) -> List[str]:
        pass

    @abstractmethod
    def get_failed_swap_ids(self) -> List[str]:
        pass


class EgressSigner(Entity):
    """Signs confirmations of swaps to other networks from the Secret Network"""

    def __init__(self, config: Config):
        super().__init__(config)

        self._secret_token_map = {}
        pairs = TokenPair.objects(network=self.native_network())
        for pair in pairs:
            self._secret_token_map[pair.coin_address] = Token(pair.secret_coin_address, pair.secret_coin_name)

    def work(self):
        for submission in self.get_new_submissions():
            native_coin_address, nonce = self.get_token_and_nonce(submission)
            swap_data = self._get_swap(native_coin_address, nonce)
            if self.verify_submission(submission, swap_data):
                self.approve(submission)

    def _get_swap(self, native_coin_address: str, nonce: int) -> SwapEvent:
        secret_coin_address = self._secret_token_map[native_coin_address].address
        coin_name = self._secret_token_map[native_coin_address].name
        swap_event = get_egress_swap_event(
            self.config.scrt_swap_address, secret_coin_address, native_coin_address, coin_name, nonce
        )
        return swap_event

    @classmethod
    @abstractmethod
    def native_network(cls) -> Network:
        pass

    @abstractmethod
    def get_new_submissions(self) -> Iterable[Any]:
        yield

    @abstractmethod
    def get_token_and_nonce(self, submission: Any) -> Tuple[str, int]:
        """return the address of the token on the foreign network, and the swap nonce"""
        pass

    @abstractmethod
    def verify_submission(self, submission_data: Any, swap_event: SwapEvent) -> bool:
        pass

    @abstractmethod
    def approve(self, submission: Any):
        pass


class IngressLeader(Entity):
    """Leads the signers responsible for swaps to the Secret Network"""
    _BROADCAST_VALIDATION_COOLDOWN = 60

    def __init__(self, config: Config, s20_multisig_account: SecretAccount):
        super().__init__(config)

        self._multisig = s20_multisig_account

        self._secret_token_map = {}
        pairs = TokenPair.objects(network=self.native_network())
        for pair in pairs:
            self._secret_token_map[pair.coin_address] = Token(pair.secret_coin_address, pair.secret_coin_name)

        self._account_num = 0
        self._sequence = 0
        self._update_sequence()

    def _update_sequence(self):
        details = secretcli.account_info(self._multisig.address)
        value = details["value"]
        self._account_num = value["account_number"]
        self._sequence = value["sequence"]

    def work(self):
        for swap_event in self.get_new_swap_events():
            self._handle_new_swap(swap_event)

        self._handle_unsigned_swaps()
        self._handle_signed_swaps()
        self._handle_submitted_swaps()
        self._handle_retry_swaps()

    def _handle_new_swap(self, swap_event: SwapEvent):
        # TODO should we do something better than just this assertion?
        assert swap_event.direction == SwapDirection.ToSecretNetwork

        amount = str(swap_event.amount)
        mint = secret_contract.mint_json(
            amount,
            swap_event.id,
            swap_event.recipient,
            swap_event.dst_coin_address
        )
        try:
            unsigned_tx = secretcli.create_unsigned_tx(
                self.config.scrt_swap_address,
                mint,
                self.config.chain_id,
                self.config.enclave_key,
                self.config.swap_code_hash,
                self._multisig.address
            )
        except RuntimeError as e:
            self.logger.error(f"Failed to create swap tx for tx hash {swap_event.id}. Error: {e}")
            return

        swap = Swap(
            src_network=self.native_network().name,
            src_tx_hash=swap_event.id,
            src_coin=swap_event.src_coin_address,
            dst_coin=swap_event.dst_coin_address,
            dst_network="Secret",
            dst_address=swap_event.recipient,
            dst_tx_hash='',  # This is filled in later when submitting the swap
            unsigned_tx=unsigned_tx,
            amount=amount,
            status=Status.SWAP_UNSIGNED,
            sequence=self._sequence,
        )
        try:
            swap.save()
        except (DuplicateKeyError, NotUniqueError) as e:
            self.logger.error(f"Tried to save duplicate TX, might be a catch up issue - {e}")
            return

        self._sequence = self._sequence + 1
        self.logger.info(f"saved new {self.native_network().name} -> Secret transaction {swap_event.id}, "
                         f"for {amount} {swap_event.dst_coin_name}")

    def _handle_unsigned_swaps(self):
        for swap in Swap.objects(status=Status.SWAP_UNSIGNED, src_network=self.native_network().name):
            self.logger.debug(f"Checking unsigned tx {swap.id}")
            if Signatures.objects(tx_id=swap.id).count() >= self.config.signatures_threshold:
                self.logger.info(f"Found tx {swap.id} with enough signatures to broadcast")
                swap.status = Status.SWAP_SIGNED
                swap.save()
                self.logger.info(f"Set status of tx {swap.id} to signed")
            else:
                self.logger.debug(f"Tx {swap.id} does not have enough signatures")

    def _handle_signed_swaps(self):
        failed_prev = False
        for swap in Swap.objects(status=Status.SWAP_SIGNED, src_network=self.native_network().name):
            # if there are 2 transactions that depend on each other (sequence number), and the first fails we mark
            # the next as "retry"
            if failed_prev:
                self.logger.info(f"Previous TX failed, retrying {swap.id}")
                self._set_swap_retry(swap)
                continue

            self.logger.info(f"Found tx ready for broadcasting {swap.id}")
            failed_prev = not self._submit_signed_swap(swap)

    def _submit_signed_swap(self, swap: Swap) -> bool:
        # reacts to signed tx in the DB that are ready to be sent to secret20
        signatures = [signature.signed_tx for signature in Signatures.objects(tx_id=swap.id)]
        if len(signatures) < self.config.signatures_threshold:  # sanity check
            self.logger.error(f"Tried to sign tx {swap.id}, without enough signatures"
                              f" (required: {self.config.signatures_threshold}, have: {len(signatures)})")
            return False

        try:
            signed_tx = self._sign_with_multisig(swap.unsigned_tx, swap.sequence, signatures)
            scrt_tx_hash = self._broadcast_sn_tx(signed_tx)
            self.logger.info(f"Broadcasted {swap.id} successfully - {scrt_tx_hash}")
            swap.status = Status.SWAP_SUBMITTED
            swap.dst_tx_hash = scrt_tx_hash
            swap.save()
            self.logger.info(f"Changed status of tx {swap.id} to submitted")
            return True
        except (RuntimeError, OperationError) as e:
            self.logger.error(f"Failed to create multisig and broadcast, error: {e}")
            swap.status = Status.SWAP_FAILED
            swap.save()
            return False

    def _sign_with_multisig(self, unsigned_tx: str, sequence: int, signatures: List[str]) -> str:
        """Takes all the signatures of the signers from the db and generates the signed tx with them."""
        # creates temp-files containing the signatures, as the 'multisign' command requires files as input
        with temp_file(unsigned_tx) as unsigned_tx_path:
            with temp_files(signatures, self.logger) as signed_tx_paths:
                return secretcli.multisig_tx(
                    unsigned_tx_path, self._multisig.name, self._account_num, sequence, *signed_tx_paths
                )

    def _check_remaining_funds(self):
        remaining_funds = secretcli.get_uscrt_balance(self._multisig.address)
        self.logger.debug(f'SCRT leader remaining funds: {remaining_funds / 1e6} SCRT')
        fund_warning_threshold = self.config.scrt_funds_warning_threshold
        if remaining_funds < fund_warning_threshold * 1e6:  # 1e6 uSCRT == 1 SCRT
            self.logger.warning(f'SCRT leader has less than {fund_warning_threshold} SCRT left')

    def _broadcast_sn_tx(self, signed_tx: str) -> str:
        self._check_remaining_funds()

        # Note: This operation costs Scrt
        with temp_file(signed_tx) as signed_tx_path:
            return json.loads(secretcli.broadcast(signed_tx_path))['txhash']

    def _handle_submitted_swaps(self):
        failed_prev = False
        for swap in Swap.objects(status=Status.SWAP_SUBMITTED, src_network=self.native_network().name):
            if failed_prev:
                self.logger.info(f"Previous TX failed, retrying {swap.id}")
                self._set_swap_retry(swap)
                continue

            failed_prev = not self._validate_submission(swap)

    def _validate_submission(self, swap: Swap) -> bool:  # pylint: disable=unused-argument
        """validation of submitted broadcast signed tx

        **kwargs needs to be here even if unused, because this function gets passed arguments from mongo internals
        """
        tx_hash = swap.dst_tx_hash
        try:
            res = secretcli.query_data_success(tx_hash)

            if res and res["mint_from_ext_chain"]["status"] == "success":
                swap.update(status=Status.SWAP_CONFIRMED)
                self.logger.info(f"Updated status to CONFIRMED for {swap.src_tx_hash}")
                return True

            # maybe the block took a long time - we wait 60 seconds before we mark it as failed
            # The returned value is just here to let us know if we need to retry the next transactions
            if (datetime.utcnow() - swap.updated_on).total_seconds() < self._BROADCAST_VALIDATION_COOLDOWN:
                return True

            # TX isn't on-chain. We can retry it
            self._set_swap_retry(swap)

            # update sequence number - just in case we failed because we are out of sync
            self._update_sequence()
            self.logger.critical(f"Failed confirming broadcast for tx: {repr(swap)}, Hash: {tx_hash}, res: {res}")
            return False
        except (ValueError, KeyError) as e:
            # TX failed for whatever reason. Might be a duplicate, out of gas, or any other reason
            self.logger.error(f"Failed confirming broadcast for tx: {repr(swap)}. Error: {e}")
            # The DB update can fail, but if it does we want to crash - this can lead to
            # duplicate amounts and confusion. Better to just stop and make sure
            # everything is kosher before continuing
            swap.update(status=Status.SWAP_FAILED)
            self._update_sequence()
            return False

    @staticmethod
    def _set_swap_retry(swap: Swap):
        swap.update(status=Status.SWAP_RETRY)

    def _handle_retry_swaps(self):
        for swap in Swap.objects(status=Status.SWAP_RETRY, src_network=self.native_network().name):
            for signature in Signatures.objects(tx_id=swap.id):
                signature.delete()
            swap.status = Status.SWAP_UNSIGNED
            swap.sequence = self._sequence
            swap.save()
            self._sequence = self._sequence + 1

    @classmethod
    @abstractmethod
    def native_network(cls) -> Network:
        pass

    @abstractmethod
    def get_new_swap_events(self) -> Iterable[SwapEvent]:
        pass


class IngressSigner(Entity):
    """Signs confirmations of swaps from other networks to the Secret Network"""

    def __init__(self, config: Config, multisig: SecretAccount):
        self._multisig = multisig  # needed in `super().__init__` because of `def log_identifier`

        super().__init__(config)

        pairs = TokenPair.objects(network=self.native_network())
        self._token_map = {}
        for pair in pairs:
            self._token_map[pair.secret_coin_address] = Token(pair.coin_address, pair.coin_name, pair.decimals)

        self._account_num = secretcli.account_info(self._multisig.address)["value"]["account_number"]

    def log_identifier(self) -> str:
        return '-' + self._multisig.name

    def work(self):
        failed = False
        for swap in Swap.objects(status=Status.SWAP_UNSIGNED):
            # if there are 2 transactions that depend on each other (sequence number), and the first fails we mark
            # the next as "retry"
            if failed:
                swap.status = Status.SWAP_RETRY
                continue

            self.logger.info(f"Found new unsigned swap event {swap}")
            try:
                self._validate_and_sign(swap)
                self.logger.info(f"Signed transaction successfully id: {swap.id}")
            except ValueError as e:
                self.logger.error(f'Failed to sign transaction: {swap} error: {e}')
                failed = True

    def _validate_and_sign(self, swap: Swap):
        """Makes sure that the tx is valid and signs it

        :raises: ValueError
        """
        if Signatures.objects(tx_id=swap.id, signer=self._multisig.name).count() != 0:
            self.logger.debug(f"This signer already signed this transaction. Waiting for other signers... id: {swap.id}")
            return

        if not self._swap_is_valid(swap):
            self.logger.error(f"Validation failed. Signer: {self._multisig.name}. Tx id:{swap.id}.")
            swap.status = Status.SWAP_FAILED
            swap.save()
            raise ValueError

        try:
            signed_tx = self._sign_with_secret_cli(swap.unsigned_tx, swap.sequence)
        except RuntimeError as e:
            swap.status = Status.SWAP_FAILED
            swap.save()
            raise ValueError from e

        try:
            self.logger.info(f"saving signature for {swap.id}")
            Signatures(tx_id=swap.id, signer=self._multisig.name, signed_tx=signed_tx).save()
        except OperationError as e:
            self.logger.error(f'Failed to save tx in database: {swap}')
            raise ValueError from e

    def _swap_is_valid(self, swap: Swap) -> bool:
        """Check that the data in the `swap.unsigned_tx` matches the tx on the chain"""
        try:
            unsigned_tx = json.loads(swap.unsigned_tx)
            res = secretcli.decrypt(unsigned_tx['value']['msg'][0]['value']['msg'])
            self.logger.debug(f'Decrypted unsigned tx successfully {res}')
            json_start_index = res.find('{')
            json_end_index = res.rfind('}') + 1
            decrypted_data = json.loads(res[json_start_index:json_end_index])

        except json.JSONDecodeError:
            self.logger.error(f'Tried to load tx with hash: {swap.src_tx_hash} {swap.id}'
                              f'but got data as invalid json, or failed to decrypt')
            return False

        # extract address and value from unsigned transaction
        try:
            amount = int(decrypted_data['mint_from_ext_chain']['amount'])
            address = decrypted_data['mint_from_ext_chain']['address']
            token = decrypted_data['mint_from_ext_chain']['token']
            native_token = self._token_map[token].address
        except KeyError:
            self.logger.error(f"Failed to validate tx data: {swap}, {decrypted_data}, "
                              f"failed to get amount or destination address from tx")
            return False

        return self.verify_transaction(swap.src_tx_hash, address, amount, native_token)

    def _sign_with_secret_cli(self, unsigned_tx: str, sequence: int) -> str:
        with temp_file(unsigned_tx) as unsigned_tx_path:
            res = secretcli.sign_tx(
                unsigned_tx_path, self._multisig.address, self._multisig.name, self._account_num, sequence
            )

        return res

    @classmethod
    @abstractmethod
    def native_network(cls) -> Network:
        pass

    @abstractmethod
    def verify_transaction(self, tx_hash: str, recipient: str, amount: int, token: str):
        """Check if the tx at the `tx_hash` was sent to the `recipient` with `amount` funds.

        `tx_hash` is the identifier of the tx in the network we're integrating with.
        `recipient` is a Secret Network address
        `amount` refers to the amount of coin passed
        `token` is the address of the token on the non-secret network, or "native".
        """
        pass
