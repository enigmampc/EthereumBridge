from logging import Logger

from web3.types import EventData

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.util.coins import CoinHandler


def build_hash(nonce, token):
    return f'{nonce}|{token}'


class EthConfirmer:

    def __init__(self, multisig_contract: MultisigWallet, logger: Logger):
        self.multisig_contract = multisig_contract
        self.logger = logger
        self.coins = CoinHandler()

    def withdraw(self, event: EventData):
        self._handle(event, True)

    def failed_withdraw(self, event: EventData):
        self._handle(event, False)

    def _handle(self, event: EventData, success: bool):
        transaction_id = event.transactionHash.hex()
        # data = self.multisig_contract.submission_data(transaction_id)
        # nonce = data['nonce']
        # token = data['token']
        #
        # if token == '0x0000000000000000000000000000000000000000':
        #     scrt_token = self.coins.scrt_address('native')
        # else:
        #     scrt_token = self.coins.scrt_address(token)
        #
        self._set_tx_result(transaction_id, success=success)


    @staticmethod
    def _confirmer_id(token: str):
        return f'confirmer-{token}'

    @staticmethod
    def get_swap(nonce, token):
        return Swap.objects().get(src_tx_hash=build_hash(nonce, token))

    @staticmethod
    def get_swap_by_dst_hash(hash):
        return Swap.objects().get(dst_tx_hash=hash)

    def _set_tx_result(self, txhash, success=True):
        try:
            swap = self.get_swap_by_dst_hash(txhash)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                f'Error handling swap {txhash}: {e}')
            return

        if swap.status != Status.SWAP_SUBMITTED:
            return
        if success:
            swap.update(status=Status.SWAP_CONFIRMED)
        else:
            swap.update(status=Status.SWAP_FAILED)

        nonce, token = swap.src_tx_hash.split('|')

        obj = SwapTrackerObject.get_or_create(self._confirmer_id(token))
        obj.update(nonce=nonce)
