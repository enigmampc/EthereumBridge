from typing import Dict

from web3.datastructures import AttributeDict

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db import Swap, Status, SwapTrackerObject
from src.util.common import Token


def build_hash(nonce, token):
    result = f'{nonce}|{token}'
    print(result)
    return result


class EthConfirmer:
    def __init__(self, multisig_contract: MultisigWallet, token_map: Dict[str, Token]):
        self.multisig_contract = multisig_contract
        self.token_map = token_map

    def withdraw(self, event: AttributeDict):
        self._handle(event, True)

    def failed_withdraw(self, event: AttributeDict):
        self._handle(event, False)

    def _handle(self, event: AttributeDict, success: bool):
        transaction_id = event.args.transactionId
        data = self.multisig_contract.submission_data(transaction_id)
        nonce = data['nonce']
        token = data['token']

        print(f'{self.token_map=}')
        if token == '0x0000000000000000000000000000000000000000':
            scrt_token = self.token_map['native'].address
        else:
            scrt_token = self.token_map[token].address

        self._set_tx_result(nonce, scrt_token, success=success)

    @staticmethod
    def get_swap(nonce, token):
        return Swap.objects().get(src_tx_hash=build_hash(nonce, token))

    def _set_tx_result(self, nonce, token, success=True):
        swap = self.get_swap(nonce, token)
        if swap.status != Status.SWAP_SUBMITTED:
            return
        if success:
            swap.update(status=Status.SWAP_CONFIRMED)
        else:
            swap.update(status=Status.SWAP_FAILED)
