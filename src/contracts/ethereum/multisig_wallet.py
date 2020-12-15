import os
from typing import Dict, List

from web3 import Web3
from web3.datastructures import AttributeDict

from src.contracts.ethereum.ethr_contract import EthereumContract
from src.contracts.ethereum.message import Submit, Confirm
from src.util.common import project_base_path


class MultisigWallet(EthereumContract):
    SUBMIT_GAS = 400000
    CONFIRM_GAS = 400000

    def __init__(self, provider: Web3, contract_address: str):
        abi_path = os.path.join(project_base_path(), 'src', 'contracts', 'ethereum', 'abi', 'MultiSigSwapWallet.json')
        super().__init__(provider, contract_address, abi_path)

    def submit_transaction(self, from_: str, private_key: bytes, gas_price, message: Submit):
        return self.send_transaction(
            'submitTransaction',
            from_,
            private_key,
            self.SUBMIT_GAS,
            gas_price=gas_price,
            args=message.args()
        )

    def confirm_transaction(self, from_: str, private_key: bytes, gas_price, message: Confirm):
        return self.send_transaction(
            'confirmTransaction',
            from_,
            private_key,
            self.CONFIRM_GAS,
            gas_price=gas_price,
            args=message.args()
        )

    @staticmethod
    def extract_addr(tx_log) -> str:
        return tx_log.args.recipient.decode()

    @staticmethod
    def extract_amount(tx_log) -> int:
        return tx_log.args.amount

    @staticmethod
    def extract_token(tx_log: AttributeDict):
        if tx_log.event == 'SwapToken':
            token_address = tx_log.args.tokenAddress
        elif tx_log.event == 'Swap':
            token_address = 'native'
        else:
            token_address = None

        return token_address

    def verify_destination(self, tx_log) -> bool:
        # returns true if the Ethr was sent to the MultiSigWallet
        # noinspection PyProtectedMember
        return tx_log.address.lower() == self.address.lower()

    def verify_confirmation(self, transaction_id, account: str) -> bool:
        return self.contract.functions.confirmations(transaction_id, account).call()

    def approve_and_sign(self, key: bytes, account: str, submission_id: int, gas_price: int) -> str:
        """
        Sign the transaction with the signer's private key and then broadcast
        Note: This operation costs gas

        :param: gas_price - price in gwei
        """
        msg = Confirm(submission_id)
        tx_hash = self.confirm_transaction(account, key, gas_price, msg)
        return tx_hash

    def submission_data(self, transaction_id) -> Dict[str, any]:
        data = self.contract.functions.transactions(transaction_id).call()

        return {
            'dest': data[0],
            'amount': data[1],
            'data': data[2],
            'executed': data[3],
            'nonce': data[4],
            'token': data[5],
            'fee': data[6],
            'ethr_tx_hash': transaction_id,
        }

    @staticmethod
    def parse_swap_event(event: AttributeDict):
        try:
            block_number = event["blockNumber"]
        except IndexError:
            raise ValueError(f"Failed to decode block number for event {event}") from None

        try:
            tx_hash = event["transactionHash"].hex()
        except (IndexError, AttributeError) as e:
            raise ValueError(f"Failed to decode transaction hash for block {block_number}: {e}") from None

        try:
            recipient = MultisigWallet.extract_addr(event)
        except (ValueError, AttributeError):
            raise ValueError(f"Failed to decode recipient for block {block_number}, transaction: {tx_hash}") from None

        # We use the "or native" part here to cover the case that `event` was neither "swap" nor "SwapToken"
        token = MultisigWallet.extract_token(event) or 'native'

        amount = str(MultisigWallet.extract_amount(event))

        return block_number, tx_hash, recipient, token, amount

    @classmethod
    def tracked_event(cls) -> List[str]:
        return ['Swap', 'SwapToken']
