from logging import Logger

from web3.datastructures import AttributeDict
from web3.types import LogReceipt

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db.collections.eth_signatures import EthSignatures
from src.db.collections.eth_swap import Swap, Status
from src.db.collections.scrt_retry import ScrtRetry
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.util.coins import CoinHandler
from src.util.common import swap_retry_address


def build_hash(nonce, token):
    return f'{nonce}|{token}'


class EthConfirmer:

    def __init__(self, multisig_contract: MultisigWallet, logger: Logger):
        self.multisig_contract = multisig_contract
        self.logger = logger
        self.coins = CoinHandler()

    def submit(self, event: LogReceipt):
        self._handle_submit(event)

    @staticmethod
    def _handle_submit(event: LogReceipt):
        EthSignatures(tx_id=event.args.transactionId, tx_hash=event['transactionHash'], signer="leader").save()

    def withdraw(self, event: AttributeDict):
        self._handle(event, True)

    def failed_withdraw(self, event: AttributeDict):
        self._handle(event, False)

    def _handle(self, event: AttributeDict, success: bool):
        transaction_id = event.args.transactionId
        data = self.multisig_contract.submission_data(transaction_id)
        nonce = data['nonce']
        token = data['token']

        if token.lower() == swap_retry_address:
            self.logger.info(f'Retrieving original ID for {nonce}|{token.lower()}')
            retry = ScrtRetry.objects().get(retry_id=f'{nonce}|{token.lower()}')
            nonce, token = retry.original_id.split('|')
            self.logger.info(f'Got original id: {nonce} for token {token.lower()}')
        if token == '0x0000000000000000000000000000000000000000':
            scrt_token = self.coins.scrt_address('native')
        else:
            scrt_token = self.coins.scrt_address(token)

        self._set_tx_result(nonce, scrt_token, success=success)

    @staticmethod
    def _confirmer_id(token: str):
        return f'confirmer-{token}'

    @staticmethod
    def get_swap(nonce, token):
        return Swap.objects().get(src_tx_hash=build_hash(nonce, token))

    def _set_tx_result(self, nonce, token, success=True):
        try:
            swap = self.get_swap(nonce, token)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                f'Error handling swap {build_hash(nonce, token)}: {e}')
            return

        if swap.status != Status.SWAP_SUBMITTED:
            return
        if success:
            swap.update(status=Status.SWAP_CONFIRMED)
        else:
            swap.update(status=Status.SWAP_FAILED)

        obj = SwapTrackerObject.get_or_create(self._confirmer_id(token))
        obj.update(nonce=nonce)
