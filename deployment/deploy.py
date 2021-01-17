import json
import random
import string
import subprocess

from src.base import Network, NATIVE_COIN_ADDRESS
from src.db import database
from src.db import TokenPairing
from src.util.config import config
from src.util.web3 import web3_provider

signer_accounts = [
    '0xA48e330838A6167a68d7991bf76F2E522566Da33',
    '0x55810874c137605b96e9d2B76C3089fcC325ed5d',
    '0x984C31d834d1F13CCb3458f4623dB21975FE4892',
    '0x552B5078a9044688F6044B147Eb2C8DFb538737e',
]

signer_accounts = ["0xA48e330838A6167a68d7991bf76F2E522566Da33", "0x47a1ABF974091aC52312ec36EEC3c187e951bf88"]

def add_token(token: str, min_amount: int, contract_address: str = None):
    with open('./src/contracts/ethereum/compiled/MultiSigSwapWallet.json', 'r') as f:
        contract_source_code = json.loads(f.read())

    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key("0xb84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826")

    contract = w3.eth.contract(
        address=contract_address or config.multisig_wallet_address,
        abi=contract_source_code['abi'],
        bytecode=contract_source_code['data']['bytecode']['object']
    )

    nonce = w3.eth.getTransactionCount(account.address, "pending")
    tx = contract.functions.addToken(token, min_amount)
    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
    signed_tx = account.sign_transaction(raw_tx)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f"Done adding token: {tx_receipt=}")


def deploy_eth():
    with open('./src/contracts/ethereum/compiled/MultiSigSwapWallet.json', 'r') as f:
        contract_source_code = json.loads(f.read())

    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key("0xb84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826")
    print(f"Deploying on {config.network} from address {account.address}")
    balance = w3.eth.getBalance(account.address, "latest")
    if balance < 1_000_000_000_000:
        print(f"You gotta have some cash dawg, you have only {balance}")
        return

    # Instantiate and deploy contract
    contract = w3.eth.contract(
        abi=contract_source_code['abi'],
        bytecode=contract_source_code['data']['bytecode']['object'],
    )
    tx = contract.constructor(signer_accounts, 1, "0xA48e330838A6167a68d7991bf76F2E522566Da33")

    nonce = w3.eth.getTransactionCount(account.address, "pending")

    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})

    signed_tx = account.sign_transaction(raw_tx)

    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    # .transact()
    # Get transaction hash from deployed contract
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f"Deployed at: {tx_receipt.contractAddress}")
    multisig_wallet = w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_source_code['abi'])
    print("All done")


def rand_str(n):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for i in range(n))


def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, check=True, text=True).stdout


SCRT_TOKEN_CODE_ID = 18
SCRT_SWAP_CODE_ID = 21

TOKENS = [
    {
        "network": Network.CosmosHub.value,
        "address": "uscrt",  # should be uatom on mainnet
        "name": "ATOM",
        "decimals": 6,
        "symbol": "ATOM",
        "display_props": {
            "symbol": "ATOM",
            "image": "https://s2.coinmarketcap.com/static/img/coins/64x64/3794.png",
            "min_to_scrt": "0.02",
            "min_from_scrt": "0.1",
            "label": "secret-atom"
        },
    },
    {
        "network": Network.Ethereum.value,
        "address": "0x1f9061B953bBa0E36BF50F21876132DcF276fC6e",
        "name": "ZEENUS",
        "decimals": 0,
        "symbol": "ZNUS",
        "display_props": {
            "symbol": "ZNUS",
            "image": "https://etherscan.io/token/images/mkr-etherscan-35.png",
            "min_to_scrt": "0.02",
            "min_from_scrt": "0.1",
            "label": "secret-zeenus"
        },
    },
    {
        "network": Network.Ethereum.value,
        "address": "0xc6fDe3FD2Cc2b173aEC24cc3f267cb3Cd78a26B7",
        "name": "YEENUS",
        "decimals": 8,
        "symbol": "YNUS",
        "display_props": {
            "symbol": "YNUS",
            "image": "https://etherscan.io/token/images/mkr-etherscan-35.png",
            "min_to_scrt": "0.02",
            "min_from_scrt": "0.1",
            "label": "secret-yeenus"
        },
    },
    {
        "network": Network.Ethereum.value,
        "address": NATIVE_COIN_ADDRESS,
        "name": "Ethereum",
        "decimals": 18,
        "symbol": "ETH",
        "display_props": {
            "symbol": "ETH",
            "image": "https://etherscan.io/token/images/mkr-etherscan-35.png",
            "min_to_scrt": "0.02",
            "min_from_scrt": "0.1",
            "label": "secret-eth"
        },
    }
]


def deploy_scrt():
    # docker exec -it secretdev secretcli tx compute store "/token.wasm.gz" --from a --gas 2000000 -b block -y
    #
    # docker exec -it secretdev secretcli tx compute store "/swap.wasm.gz" --from a --gas 2000000 -b block -y
    # 0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e

    deployer = run_shell("secretcli keys show t1 | jq -r '.address'").strip()

    swap_contract, swap_contract_hash = init_swap_contract(deployer)
    print(f"Swap contract deployed at: {swap_contract}")
    for token in TOKENS:
        scrt_token, scrt_token_code = init_token_contract(
            deployer, token["decimals"], f'S{token["symbol"]}', f'Secret {token["name"]}',
            swap_contract, label=f'{token["display_props"].get("label")}'
        )
        add_minter(scrt_token, deployer)
        print(f"Secret {token['name']}, Deployed at: {scrt_token}")

        min_amount = int((10 ** token["decimals"]) * float(token["display_props"].get("min_from_scrt")))
        print(f"adding minimum amount {min_amount} for token: {token['name']}")
        add_to_whitelist(swap_contract, scrt_token, scrt_token_code, min_amount)
        uri = config.db_uri
        with database(uri):
            TokenPairing(
                src_network=token['network'], src_coin=token["name"], src_address=token["address"],
                dst_network="Secret", dst_coin=f"secret-{token['name']}", dst_address=scrt_token,
                display_props=token['display_props'],
                decimals=token['decimals'], name=token['name']
            ).save()

    change_owner(swap_contract, config.multisig_acc_addr)


def add_minter(token_addr, minter):
    tx_data = {"add_minters": {"minters": [minter]}}
    cmd = f"secretcli tx compute execute {token_addr} '{json.dumps(tx_data)}' --from t1 -b block -y"
    return run_shell(cmd)


def add_to_whitelist(swap_contract, token_addr, code_hash, min_amount: int):
    print(f"Adding token {token_addr} to {swap_contract}, minimum amount: {str(min_amount)}")
    tx_data = {"add_token": {"address": token_addr, "code_hash": code_hash, "minimum_amount": str(min_amount)}}
    cmd = f"secretcli tx compute execute {swap_contract} '{json.dumps(tx_data)}' --from t1 -b block -y"
    return run_shell(cmd)


def change_owner(swap_contract, new_owner):
    tx_data = {"change_owner": {"owner": new_owner}}
    cmd = f"secretcli tx compute execute {swap_contract} '{json.dumps(tx_data)}' --from t1 -b block -y"
    return run_shell(cmd)


def init_token_contract(
        admin: str, decimals: int, symbol: str, name: str, swap_addr: str = None, label: str = None
) -> (str, str):
    tx_data = {"admin": admin, "name": name, "symbol": symbol, "decimals": decimals,
               "initial_balances": [], "config": {}, "prng_seed": "YWE"}
    if not label:
        label = rand_str(10)

    cmd = f"secretcli tx compute instantiate {SCRT_TOKEN_CODE_ID} --label {label} " \
          f"'{json.dumps(tx_data)}' --from t1 -b block -y"
    run_shell(cmd)

    res = run_shell(f"secretcli query compute list-contract-by-code {SCRT_TOKEN_CODE_ID} | jq -r '.[-1].address'")
    token_addr = res.strip()
    res = run_shell(f"secretcli q compute contract-hash {token_addr}")
    sn_token_codehash = res.strip()[2:]

    if swap_addr:
        add_minter(token_addr, swap_addr)
    return token_addr, sn_token_codehash


def init_swap_contract(owner: str, label: str = None) -> (str, str):
    tx_data = {"owner": owner}
    if not label:
        label = rand_str(10)

    cmd = f"secretcli tx compute instantiate {SCRT_SWAP_CODE_ID} --label {label} '{json.dumps(tx_data)}'" \
          f" --from t1 -b block -y"
    run_shell(cmd)

    res = run_shell(f"secretcli query compute list-contract-by-code {SCRT_SWAP_CODE_ID} | jq -r '.[-1].address'")
    swap_addr = res.strip()

    res = run_shell(f"secretcli q compute contract-hash {swap_addr}")
    swap_code_hash = res.strip()[2:]

    return swap_addr, swap_code_hash


def configure_db():
        # TokenPairing(src_network="Ethereum", src_coin="ETH", src_address=NATIVE_COIN_ADDRESS,
        #              dst_network="Secret", dst_coin="secret-ETH",
        #              dst_address="secret1nk5c3agzt3ytpkl8csfhf4e3qwleauex9ay69t").save()

        TokenPairing.objects().get(
            src_network="Ethereum",
            dst_address="secret13lj8gqvdfn45d03lfrrl087dje5d6unzus2usv",
            dst_coin="secret-YEENUS"
        ).delete()

        # for obj in obs:
        #     obj.delete()
        #
        # TokenPairing(src_network="Ethereum", src_coin="YEENUS",
        #              src_address="0xF6fF95D53E08c9660dC7820fD5A775484f77183A",
        #              dst_network="Secret", dst_coin="secret-NUS",
        #              dst_address="secret17nfn68fdkvvplr8s0tu7qkhxfw08j7rwne5sl2").save()
        #
        # TokenPairing(src_network="Ethereum", src_coin="TUSD", src_address=NATIVE_COIN_ADDRESS,
        #              dst_network="Secret", dst_coin="secret-TUSD",
        #              dst_address="secret1psm5jn08l2ms7sef2pxywr42fa8pay877vpg68").save()


if __name__ == '__main__':
    # deploy_eth()

    # add_token(
    #     "0x1cB0906955623920c86A3963593a02a405Bb97fC",
    #     1000000000000000000,
    #     "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e",
    # )
    # add_token(
    #     "0x1cB0906955623920c86A3963593a02a405Bb97fC",
    #     1000000000000000000,
    #     "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e",
    # )
    # add_token("0xF6fF95D53E08c9660dC7820fD5A775484f77183A", 100000000, "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e")

    deploy_scrt()

    # configure_db()

    # response = add_to_whitelist(
    #     'secret1j8n6qxtpd8mlwkjmmk8vel8pdsq8hs996j6atr',
    #     'secret1m2332v066t7ll6z9cr4ceyrfzvufj29thqfqjg',
    #     'efbaf03ba2f8b21c231874fd8f9f1c69203f585cae481691812d8289916eff7a',
    #     10000
    # )
    # print(response)
