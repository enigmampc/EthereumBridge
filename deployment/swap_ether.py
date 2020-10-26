import json

from src.contracts.ethereum.message import Message
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.util.config import Config
from src.util.web3 import web3_provider, send_contract_tx


def swap_eth():

    cfg = Config()

    private_key = "b84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826"  # your private key here
    account = "0xA48e330838A6167a68d7991bf76F2E522566Da33"  # your account here

    with open('./src/contracts/ethereum/compiled/MultiSigSwapWallet.json', 'r') as f:
        contract_source_code = json.loads(f.read())

    w3 = web3_provider(cfg['eth_node_address'])
    # multisig_wallet = MultisigWallet(web3_provider, config.multisig_wallet_address)
    multisig_wallet = MultisigWallet(w3, cfg['multisig_wallet_address'])

    class SwapMessage(Message):
        def args(self):
            return "secret13l72vhjngmg55ykajxdnlalktwglyqjqv9pkq4".encode(),

    m = SwapMessage()
    tx_hash = send_contract_tx(multisig_wallet.contract, 'swap',
                               account, bytes.fromhex(private_key), *m.args(), value=200)
    print(repr(tx_hash))

def swap_erc():
    cfg = Config()
    TRANSFER_AMOUNT = 100
    private_key = "b84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826"  # your private key here
    address = "0xA48e330838A6167a68d7991bf76F2E522566Da33"  # your account here

    # with open('./src/contracts/ethereum/abi/IERC20.json', 'r') as f:
    #     contract_source_code = json.loads(f.read())
    #
    w3 = web3_provider(cfg['eth_node_address'])
    #
    # account = w3.eth.account.from_key(private_key)
    # nonce = w3.eth.getTransactionCount(account.address, "pending")
    # # multisig_wallet = MultisigWallet(web3_provider, config.multisig_wallet_address)
    multisig_wallet = MultisigWallet(w3, cfg['multisig_wallet_address'])
    #
    # try:
    #     erc20_contract = w3.eth.contract(address="0xF6fF95D53E08c9660dC7820fD5A775484f77183A", abi=contract_source_code['abi'])
    #     tx = erc20_contract.functions.approve(multisig_wallet.address, TRANSFER_AMOUNT)
    #
    #     raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
    #     signed_tx = account.sign_transaction(raw_tx)
    #     tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    #
    #     # Get transaction hash from deployed contract
    #     tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    # except Exception:
    #     pass

    class SwapMessage(Message):
        def args(self):
            # return "secret13l72vhjngmg55ykajxdnlalktwglyqjqv9pkq4".encode(), TRANSFER_AMOUNT, "0xF6fF95D53E08c9660dC7820fD5A775484f77183A"
            return '0xF6fF95D53E08c9660dC7820fD5A775484f77183A', 0, 1000, '0xF6fF95D53E08c9660dC7820fD5A775484f77183A', '0xa9059cbb00000000000000000000000055810874c137605b96e9d2b76c3089fcc325ed5d0000000000000000000000000000000000000000000000000000000000000001'

    owners = multisig_wallet.contract.functions.getOwners().call()
    print(owners)

    account = w3.eth.account.from_key("0xb84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826")
    print(f"Deploying on {cfg['network']} from address {account.address}")
    balance = w3.eth.getBalance(account.address, "latest")
    if balance < 1000000000000:
        print("You gotta have some cash dawg")
        return

    # Instantiate and deploy contract
    # contract = w3.eth.contract(abi=contract_source_code['abi'], bytecode=contract_source_code['data']['bytecode']['object'])
    # tx = contract.constructor(signer_accounts, cfg['signatures_threshold'],)

    nonce = w3.eth.getTransactionCount(account.address, "pending")

    tx = multisig_wallet.contract.functions.addToken('0xF6fF95D53E08c9660dC7820fD5A775484f77183A')
    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})

    signed_tx = account.sign_transaction(raw_tx)

    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)

    m = SwapMessage()
    tx_hash = send_contract_tx(multisig_wallet.contract, 'submitTransaction',
                               address, bytes.fromhex(private_key), 1000000, *m.args(), value=0)
    print(repr(tx_hash))


if __name__ == '__main__':
    # swap_eth()
    swap_erc()
