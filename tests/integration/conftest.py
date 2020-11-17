import os

from brownie import accounts
from pytest import fixture
from web3 import Web3

import src.contracts.ethereum as contracts_package
import tests.integration as integration_package
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.util.common import module_dir
from src.util.config import Config
from src.util.web3 import normalize_address

contracts_folder = os.path.join(module_dir(contracts_package), 'sol')
brownie_project_folder = os.path.join(module_dir(integration_package), 'brownie_project')

PAYABLE_ADDRESS = "0x1111111111111111111111111111111111111111"


@fixture(scope="module")
def multisig_wallet(web3_provider, configuration: Config, ether_accounts):
    # erc20_contract is here only to deploy and update configuration, can be remove if not working with ERC20
    from brownie.project.IntegrationTests import MultiSigSwapWallet
    # normalize_accounts = [normalize_address(acc.address) for acc in ether_accounts]
    swap_contract = MultiSigSwapWallet.deploy([acc.address for acc in ether_accounts],
                                              configuration.signatures_threshold,
                                              PAYABLE_ADDRESS,
                                              {'from': accounts[0]})
    contract_address = str(swap_contract.address)
    print(f"{contract_address=}")
    return MultisigWallet(web3_provider, contract_address)


@fixture(scope="module")
def ether_accounts(web3_provider, configuration: Config):
    res = []
    for _ in range(configuration.signatures_threshold):
        acc = web3_provider.eth.account.create()
        # account[0] is network.eth.coinbase
        web3_provider.eth.sendTransaction({'from': normalize_address(web3_provider.eth.accounts[0]),
                                           'to': normalize_address(acc.address),
                                           'value': 1000000000000000000})
        res.append(acc)

    return res


@fixture(scope="module")
def web3_provider(configuration):
    # connect to local ganache node, started by brownie
    return Web3(Web3.HTTPProvider(configuration.eth_node))
