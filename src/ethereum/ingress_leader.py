from typing import Iterable, Optional, Tuple

from web3.types import LogReceipt

from ..base import IngressLeader, Network, SwapEvent, SwapDirection
from ..contracts.ethereum.event_listener import EventTracker
from ..contracts.ethereum.multisig_wallet import MultisigWallet
from ..db import SwapTrackerObject
from ..util.common import SecretAccount
from ..util.config import Config

SWAP = 'Swap'
SWAP_TOKEN = 'SwapToken'


class EthIngressLeader(IngressLeader):
    def __init__(
        self,
        config: Config,
        s20_multisig_account: SecretAccount,
        contract: MultisigWallet,
    ):
        super(EthIngressLeader, self).__init__(config, s20_multisig_account)

        self._contract = contract
        self._event_tracker = EventTracker(contract, [], config.eth_confirmations)
        self._configure_event_tracker()

    def _configure_event_tracker(self):
        from_block = SwapTrackerObject.last_processed('Ethereum') + 1
        if self.config.eth_start_block > from_block:
            self.logger.debug(f'Due to config fast forwarding to block {self.config.eth_start_block}')
            from_block = self.config.eth_start_block
            SwapTrackerObject.update_last_processed('Ethereum', from_block)

        self._event_tracker.register_event(SWAP, from_block)
        self._event_tracker.register_event(SWAP_TOKEN, from_block)

    @classmethod
    def native_network(cls) -> Network:
        return Network.Ethereum

    def get_new_swap_events(self) -> Iterable[SwapEvent]:
        for event_name in [SWAP, SWAP_TOKEN]:
            for event in self._event_tracker.get_new_events(event_name):
                self.logger.info(f"Found new event of type {event.event}: {event}")
                ret = self._parse_swap_event(event)
                if ret is None:
                    continue
                swap_event, block_number = ret

                yield swap_event

                SwapTrackerObject.update_last_processed('Ethereum', block_number)

    def _parse_swap_event(self, event: LogReceipt) -> Optional[Tuple[SwapEvent, int]]:
        if not self._contract.verify_destination(event):
            return

        try:
            block_number, tx_hash, recipient, token, amount = self._contract.parse_swap_event(event)
        except ValueError:
            return

        try:
            s20 = self._secret_token_map[token]
            swap_event = SwapEvent(
                id=tx_hash,
                nonce=self._sequence,
                dst_coin_name=s20.name,
                dst_coin_address=s20.address,
                src_coin_address=token,
                direction=SwapDirection.ToSecretNetwork,
                amount=amount,
                sender='',
                recipient=recipient,
            )
            return swap_event, block_number
        except (IndexError, AttributeError) as e:
            self.logger.error(f"Failed on tx {tx_hash}, block {block_number}, due to missing config: {e}")
            return
