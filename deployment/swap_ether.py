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

    w3 = web3_provider(cfg['eth_node'])
    # multisig_wallet = MultisigWallet(web3_provider, config.multisig_wallet_address)
    multisig_wallet = MultisigWallet(w3, cfg['multisig_wallet_address'])

    class SwapMessage(Message):
        def args(self):
            return "secret1nrys3wd626jgjrre2x8s36p0rrepym58z8d877".encode(),

    m = SwapMessage()
    tx_hash = send_contract_tx(multisig_wallet.contract, 'swap',
                               account, bytes.fromhex(private_key), value=200, args=m.args())
    print(repr(tx_hash))


def swap_erc(amount: int = 1):
    cfg = Config()
    base_amount = 1000000000000000000
    TRANSFER_AMOUNT = base_amount * amount
    private_key = "b84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826"  # your private key here
    address = "0xA48e330838A6167a68d7991bf76F2E522566Da33"  # your account here

    with open('./src/contracts/ethereum/abi/IERC20.json', 'r') as f:
        contract_source_code = json.loads(f.read())
    #
    w3 = web3_provider(cfg['eth_node'])
    #
    account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.getTransactionCount(account.address, "pending")
    # # multisig_wallet = MultisigWallet(web3_provider, config.multisig_wallet_address)
    multisig_wallet = MultisigWallet(w3, "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e")
    #
    try:
        erc20_contract = w3.eth.contract(address="0x1cB0906955623920c86A3963593a02a405Bb97fC", abi=contract_source_code['abi'])
        tx = erc20_contract.functions.approve(multisig_wallet.address, TRANSFER_AMOUNT)

        raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
        signed_tx = account.sign_transaction(raw_tx)
        tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)

        # Get transaction hash from deployed contract
        # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    except Exception:
        pass

    class SwapMessage(Message):
        def args(self):
            return "secret1nrys3wd626jgjrre2x8s36p0rrepym58z8d877".encode(), TRANSFER_AMOUNT, "0x1cB0906955623920c86A3963593a02a405Bb97fC"
    #         return '0xA48e330838A6167a68d7991bf76F2E522566Da33', 0, 0, '0xA48e330838A6167a68d7991bf76F2E522566Da33', '0xa9059cbb00000000000000000000000055810874c137605b96e9d2b76c3089fcc325ed5d0000000000000000000000000000000000000000000000000000000000000001'

    owners = multisig_wallet.contract.functions.getOwners().call()
    print(owners)

    tokens = multisig_wallet.contract.functions.SupportedTokens().call()
    print(tokens)

    # account = w3.eth.account.from_key("0xb84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826")
    # print(f"Deploying on {cfg['network']} from address {account.address}")
    # balance = w3.eth.getBalance(account.address, "latest")
    # if balance < 1000000000000:
    #     print("You gotta have some cash dawg")
    #     return
    #
    # # Instantiate and deploy contract
    # # contract = w3.eth.contract(abi=contract_source_code['abi'], bytecode=contract_source_code['data']['bytecode']['object'])
    # # tx = contract.constructor(signer_accounts, cfg['signatures_threshold'],)
    #

    ### add token
    # tx = multisig_wallet.contract.functions.addToken('0xF6fF95D53E08c9660dC7820fD5A775484f77183A')
    # nonce = w3.eth.getTransactionCount(account.address, "pending")
    # raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
    # #
    # signed_tx = account.sign_transaction(raw_tx)
    # #
    # tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    # #


    # tokens = multisig_wallet.contract.functions.SupportedTokens().call()
    # print(tokens)
    m = SwapMessage()
    tx_hash = send_contract_tx(multisig_wallet.contract, 'swapToken',
                               address, bytes.fromhex(private_key), 1000000, value=0, args=m.args())
    print(repr(tx_hash))


def random_swapper():
    import random, time
    try:
        total = 0
        tx_count = 0
        while True:
            sleep_time = random.randint(10, 600)
            swap_amount = random.randint(1, 10)
            number_of_swaps = random.randint(1, 5)
            for _ in range(number_of_swaps):
                swap_erc(swap_amount)
                total += swap_amount
                tx_count += 1

            print(f"Total sent: {total}, in {tx_count} transactions")
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("Bye!")


if __name__ == '__main__':
    # swap_erc()
    random_swapper()
