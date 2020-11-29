from collections import defaultdict
from collections.abc import MutableMapping
from itertools import count
from threading import Event
from time import sleep
from typing import List, Callable, Iterator, Dict, Tuple, Union, DefaultDict

from web3.contract import LogFilter, LogReceipt, BlockIdentifier

from src.contracts.ethereum.ethr_contract import EthereumContract
from src.contracts.event_provider import EventProvider
from src.util.config import Config
from src.util.logger import get_logger
from src.util.web3 import contract_event_in_range, w3


class EventTracker:
    def __init__(self, contract: EthereumContract, events: List[str] = None, confirmations=0):
        self.contract = contract
        self.confirmations = confirmations
        self.events: List[str] = []
        self.filters: Dict[str, LogFilter] = {}
        self.pending_events: DefaultDict[str, List[LogReceipt]] = defaultdict(list)

        if events is not None:
            for event_name in events:
                self.register_event(event_name, "latest")

    def register_event(self, event_name: str, from_block: BlockIdentifier):
        if event_name not in self.events:
            self.events.append(event_name)

        event = getattr(self.contract.contract.events, event_name)
        event_filter = event.createFilter(fromBlock=from_block)
        self.filters[event_name] = event_filter

    def get_new_events(self, event_name: str) -> List[LogReceipt]:
        current_block_number = w3.eth.blockNumber
        pending_events = self.pending_events[event_name]
        new_events = self.filters[event_name].get_new_entries()

        ready_events = []
        still_pending_events = []
        for events in [pending_events, new_events]:
            for event in events:
                if self._is_event_confirmed(event, current_block_number):
                    ready_events.append(event)
                else:
                    still_pending_events.append(event)

        self.pending_events[event_name] = still_pending_events
        return ready_events

    def _is_event_confirmed(self, event: LogReceipt, block_number: int):
        return event.blockNumber > (block_number - self.confirmations)


class EthEventListener(EventProvider):
    """Tracks the block-chain for new transactions on a given address"""
    _ids = count(0)

    def __init__(self, contract: EthereumContract, config: Config, **kwargs):
        # Note: each event listener can listen to one contract at a time
        self.id = next(self._ids)
        self.tracked_contract = contract
        self.config = config
        self.callbacks = Callbacks()
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=config.log_level,
            logger_name=config.logger_name or f"{self.__class__.__name__}-{self.id}"
        )
        self.events = []
        self.pending_events: List[Tuple[str, LogReceipt]] = []
        self.filters: Dict[str, LogFilter] = {}
        self.confirmations = config.eth_confirmations
        self.stop_event = Event()
        super().__init__(group=None, name=f"EventListener-{config.logger_name}", target=self.run, **kwargs)
        self.setDaemon(True)

    def register(self, callback: Callable, events: List[str], from_block="latest"):
        """
        Allows registration to certain event of contract with confirmations threshold
        Note: events are Case Sensitive

        :param callback: callback function that will be invoked upon event
        :param events: list of events the caller wants to register to
        :param from_block: Starting block
        """
        for event_name in events:
            self.logger.info(f"registering event {event_name}")
            self.events.append(event_name)
            self.callbacks[event_name] = callback

            event = getattr(self.tracked_contract.contract.events, event_name)
            evt_filter = event.createFilter(fromBlock="latest")
            self.filters[event_name] = evt_filter

            if from_block != "latest":
                self.add_events_in_range(event_name, from_block=from_block, to_block=w3.eth.blockNumber)

    def stop(self):
        self.logger.info("Stopping..")
        self.stop_event.set()

    def run(self):
        """Notify registered callbacks upon event occurrence"""
        self.logger.info("Starting..")

        while not self.stop_event.is_set():
            self.logger.debug(f'Scanning for new events of type {self.events}')
            for name, event in self.get_new_events():
                self.logger.info(f"New event found {name}, adding to confirmation handler")
                self.pending_events.append((name, event))
            for name, event in self.confirmation_handler():
                self.logger.info(f"Event {name} passed confirmation limit, executing callback")
                self.callbacks.trigger(name, event)

            sleep(self.config.sleep_interval)

    def confirmation_handler(self):
        blockNum = w3.eth.blockNumber
        # this creates a copy of the list, so we can remove from the original one while still iterating
        for item in list(self.pending_events):
            _name, event = item
            if event.blockNumber <= (blockNum - self.confirmations):
                self.pending_events.remove(item)
                yield item

    def events_in_range(self, event: str, from_block: int, to_block: int = None):
        """ Returns a generator that yields all contract events in range"""
        return contract_event_in_range(self.tracked_contract, event, from_block=from_block,
                                       to_block=to_block)

    def add_events_in_range(self, event_name, from_block: Union[int, str], to_block: int):
        """
        Used to catch up for all the events from when we wanted to start, and where we are now.
        Todo: check on ropsten and mainnet if this behaves the same way
        """
        event = getattr(self.tracked_contract.contract.events, event_name)
        evt_filter = event.createFilter(fromBlock=from_block, toBlock=to_block)
        for event in evt_filter.get_all_entries():
            self.pending_events.append((event_name, event))

    def get_new_events(self):
        """
        Return new events from the filters (starting from events that were generated after the filters were created)
        """
        for name, log_filter in self.filters.items():
            for event in log_filter.get_new_entries():
                yield name, event


class Callbacks(MutableMapping):
    """Utility class that manages events registration by confirmation threshold"""
    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.update(dict(*args, **kwargs))

    def __iter__(self) -> Iterator:
        return iter(self.store)

    def __len__(self) -> int:
        return len(self.store)

    def __delitem__(self, key) -> None:
        del self.store[key]

    def __setitem__(self, key, value):
        if key in self.store:
            self.store[key].extend(value)
        else:
            self.store[key] = [value]

    def __getitem__(self, key):
        if key not in self.store:
            return []
        return self.store[key]

    def trigger(self, event_name: str, event):
        """ call all the callbacks whose confirmation threshold reached """

        for callback in self[event_name]:
            callback(event)
