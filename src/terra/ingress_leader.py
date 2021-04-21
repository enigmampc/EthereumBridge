from typing import Iterable, Dict, Optional

from ..base import IngressLeader, Network, SwapEvent, SwapDirection
from ..db import SwapTrackerObject
from ..util.common import SecretAccount
from ..util.config import Config
from ..util.gaia import GaiaCli, GaiaCliError


PAGE_TRACKER = "TerraIngressLeader-PageTracker"
TX_TRACKER = "TerraIngressLeader-TxTracker"


class TerraIngressLeader(IngressLeader):
    def __init__(
        self,
        config: Config,
        s20_multisig_account: SecretAccount,
        terra_multisig: str,
        cli: GaiaCli,
    ):
        super().__init__(config, s20_multisig_account)
        self._cli = cli
        self._terra_multisig = terra_multisig

    @classmethod
    def native_network(cls) -> Network:
        return Network.Terra

    def get_new_swap_events(self) -> Iterable[SwapEvent]:
        page_tracker = SwapTrackerObject.get_or_create(PAGE_TRACKER, 1)
        tx_tracker = SwapTrackerObject.get_or_create(TX_TRACKER, 0)
        new_tx_available = True

        while new_tx_available:
            page = page_tracker.nonce
            addr = self._terra_multisig
            self.logger.info(f"fetching page {page} of txs to {addr}")
            try:
                txs_page = self._cli.query_txs_to(addr, page)
            except GaiaCliError as e:
                err_message = e.inner.stderr
                if "page should be within" not in err_message:
                    self.logger.warning(
                        f"unexpected error while querying page {page} of txs to {addr}: {err_message}"
                    )
                new_tx_available = False
                continue

            # Skip txs in this page that we already processed
            last_tx_index = tx_tracker.nonce
            new_txs = txs_page[last_tx_index:] if last_tx_index != 0 else txs_page

            for tx in new_txs:
                tx_hash = tx["txhash"]
                self.logger.info(f"handling tx {tx_hash}")
                try:
                    swap = self._parse_tx(tx)
                    if swap is None:
                        self.logger.info(
                            f"tx {tx_hash} could not be handled. skipping."
                        )
                        continue

                    yield swap
                finally:
                    tx_tracker.nonce += 1
                    tx_tracker.save()

            if len(txs_page) == GaiaCli.DEFAULT_QUERY_LIMIT:
                tx_tracker.nonce = 0
                tx_tracker.save()
                page_tracker.nonce += 1
                page_tracker.save()
            else:
                new_tx_available = False

    def _parse_tx(self, tx: Dict) -> Optional[SwapEvent]:
        tx_hash = tx["txhash"]

        if "logs" not in tx:
            self.logger.info(f"tx {tx_hash} was a failed tx")
            return None

        tx_value = tx["tx"]["value"]
        recipient = tx_value["memo"]
        if not recipient:
            self.logger.info(f"tx {tx_hash} did not contain a recipient in the memo")
            return None

        msgs = tx_value["msg"]
        if len(msgs) != 1:
            self.logger.info(f"tx {tx_hash} contained multiple messages")
            return None

        msg_details = msgs[0]["value"]
        amounts = msg_details["amount"]
        if len(amounts) != 1:
            self.logger.info(
                f"tx {tx_hash} contained no funds, or multiple coins were sent"
            )
            return None

        sender = msg_details["from_address"]
        sent_currency = amounts[0]
        amount = int(sent_currency["amount"])
        denom = sent_currency["denom"]
        if denom not in self._secret_token_map:
            self.logger.info(f"tx {tx_hash} transferred an unsupported token: {denom}")
            return None
        secret_token = self._secret_token_map[denom]
        swap = SwapEvent(
            id=tx_hash,
            nonce=self._sequence,
            dst_coin_name=secret_token.name,
            dst_coin_address=secret_token.address,
            src_coin_address=denom,
            direction=SwapDirection.ToSecretNetwork,
            amount=amount,
            sender=sender,
            recipient=recipient,
        )

        return swap