from threading import Thread, Event
from time import sleep

from src.contracts.ethereum.event_listener import EthEventListener
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.signer.eth.impl import EthSignerImpl, signer_id
from src.util.config import Config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.logger import get_logger


class EtherSigner(Thread):
    """
    secretETH --> Swap TX --> ETH

    On Ethereum the leader monitors the sETH Secret Contract. When it sees a new swap, it will
    broadcast a submit transaction on-chain.
    On detecting a submit transaction from the event listener, the signer signs and broadcasts
    a confirm transaction on-chain. The multisig contract, after receiving a number of confirmations
    greater than the set threshold will trigger the transfer of funds

    Will first attempt to catch up with unsigned transactions by scanning past events,
    and only then will start monitoring new transactions.

    The account set here must have enough ETH for all the transactions you're planning on doing
    """
    def __init__(
        self,
        contract: MultisigWallet,
        signer: CryptoManagerBase,
        dst_network: str,
        config: Config,
        **kwargs
    ):
        self.account = signer.address
        # self.private_key = private_key
        self.event_listener = EthEventListener(contract, config)
        self.stop_event = Event()
        self.logger = get_logger(
            db_name=config.db_name,
            logger_name=config.logger_name or f"{self.__class__.__name__}-{self.account[0:5]}"
        )
        self.config = config
        self.signer = EthSignerImpl(contract, signer, dst_network, config)

        super().__init__(group=None, name=f"{self.__class__.__name__}-{self.account[0:5]}", target=self.run, **kwargs)
        self.setDaemon(True)  # so tests don't hang

    def run(self):
        self.logger.info("Starting..")

        from_block = self.choose_starting_block()

        self.event_listener.register(self.signer.sign, ['Submission'], from_block=from_block)
        self.event_listener.start()
        while not self.stop_event.is_set():
            if not self.event_listener.is_alive():
                self.logger.critical("Event listener stopped - stopping signer")
                self.stop()
            sleep(10)

    def stop(self):
        self.logger.info("Stopping..")
        self.event_listener.stop()
        self.stop_event.set()

    def choose_starting_block(self) -> int:
        """Returns the block from which we start scanning Ethereum for new tx"""
        obj = SwapTrackerObject.get_or_create(src=signer_id(self.account))
        if obj.nonce == -1:
            obj.update(nonce=self.config.eth_start_block)

        return obj.nonce
