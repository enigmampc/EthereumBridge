from abc import ABC, abstractmethod
from subprocess import CalledProcessError
from typing import Iterable, List, Tuple, Any
import threading

from pymongo.errors import DuplicateKeyError
from mongoengine.errors import NotUniqueError

from src.db import Swap, Status, SwapTrackerObject
from src.util.common import Token
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import query_scrt_swap

from .common import Network, SwapEvent, SwapDirection
from .db import TokenPair
from ..contracts.secret.secret_contract import swap_query_res


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

    This is used in the eth leader because we don't currently pass that information from the secret network to the
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
    swap_data = query_scrt_swap(nonce, swap_contract_address, secret_coin_address)
    swap_json = swap_query_res(swap_data)

    swap_event = SwapEvent(
        id=get_tx_hash(swap_json['nonce'], swap_json['token']),
        nonce=str(swap_json['nonce']),
        dst_coin_name=coin_name,
        dst_coin_address=native_coin_address.lower(),
        src_coin_address=secret_coin_address.lower(),
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
            self._mark_swap_complete(swap)

        failed_swaps = self.get_failed_swap_ids()
        for swap in failed_swaps:
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
    def _store_swap(cls, swap_event: SwapEvent, tx_hash: str, data: str = ''):
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
            unsigned_tx=data,
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
        """Provided method - uses abstract methods to manage the swap process"""
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

    def __init__(self, config: Config):
        super().__init__(config)

    def work(self):
        """Provided method - uses abstract methods to manage the swap process"""
        pass


class IngressSigner(Entity):
    """Signs confirmations of swaps from other networks to the Secret Network"""

    def __init__(self, config: Config):
        super().__init__(config)

    def work(self):
        """Provided method - uses abstract methods to manage the swap process"""
        pass
