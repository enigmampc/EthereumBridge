from threading import Thread

import rlp
from web3.exceptions import TransactionNotFound, TimeExhausted

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.util.eth.transaction import Transaction
from src.util.web3 import w3


class TxSender(Thread):
    retry_limit = 3

    def __init__(self, **kwargs):

        self.to_send = None
        self.tx_hash = None
        self.done = False

        super().__init__(group=None, name=f"TxSender", target=self.run, **kwargs)
        self.setDaemon(True)  # so tests don't hang

        self.retry_count = 0

    def confirm_tx(self):
        try:
            tx_receipt = w3.eth.waitForTransactionReceipt(self.tx_hash)
            if tx_receipt['blockNumber']:
                self.done = True
        except TransactionNotFound:
            return False
        except TimeExhausted:
            if self.retry_count <= self.retry_limit:
                return False
            self.retry_count += 1

    def broadcast_transaction(self, tx: Transaction):
        #raw = rlp.encode(tx)
        self.to_send = tx
        self.run()

    def _broadcast(self):
        self.tx_hash = w3.eth.sendRawTransaction(self.to_send)

    def run(self) -> None:
        while not self.done:
            if not self.confirm_tx():
                self._broadcast()
