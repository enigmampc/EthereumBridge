import os

from web3 import Web3

from .ethr_contract import EthereumContract
from src.util.common import project_base_path, Token


class Erc20(EthereumContract):
    def __init__(self, provider: Web3, token: Token, multisig_address: str):
        abi_path = os.path.join(project_base_path(), 'src', 'contracts', 'ethereum', 'abi', 'IERC20.json')
        self.token = token
        super().__init__(provider, token.address, abi_path)

        self.dest_address = multisig_address

    def symbol(self):
        return self.token.name

    @staticmethod
    def extract_addr(tx_log) -> str:
        return tx_log.args.recipient.decode()

    @staticmethod
    def extract_amount(tx_log) -> int:
        # noinspection PyProtectedMember
        return int(tx_log.args._value)  # pylint: disable=protected-access

    def verify_destination(self, tx_log) -> bool:
        # returns true if the ERC20 was sent to the MultiSigWallet (that's how token transfer is preformed)
        # noinspection PyProtectedMember
        return tx_log.args._to.lower() == self.dest_address.lower()    # pylint: disable=protected-access
