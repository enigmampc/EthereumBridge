import json
import random
import string
import subprocess

from src.db import database
from src.db import TokenPairing
from src.util.config import config
from src.util.web3 import web3_provider

signer_accounts = ['0xA48e330838A6167a68d7991bf76F2E522566Da33', '0x55810874c137605b96e9d2B76C3089fcC325ed5d',
                   '0x984C31d834d1F13CCb3458f4623dB21975FE4892', '0x552B5078a9044688F6044B147Eb2C8DFb538737e']


# def whitelist_token_eth():
#

def add_token(token: str, min_amount: int, contract_address: str = None):


    with open('./src/contracts/ethereum/compiled/MultiSigSwapWallet.json', 'r') as f:
        contract_source_code = json.loads(f.read())

    w3 = web3_provider(config.eth_node)
    account = w3.eth.account.from_key("0xb84db86a570359ca8a16ad840f7495d3d8a1b799b29ae60a2032451d918f3826")

    contract = w3.eth.contract(address=contract_address or config.multisig_wallet_address,
                               abi=contract_source_code['abi'],
                               bytecode=contract_source_code['data']['bytecode']['object'])

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
    if balance < 1000000000000:
        print("You gotta have some cash dawg")
        return

    # Instantiate and deploy contract
    contract = w3.eth.contract(abi=contract_source_code['abi'], bytecode=contract_source_code['data']['bytecode']['object'])
    tx = contract.constructor(signer_accounts, config.signatures_threshold, "0xA48e330838A6167a68d7991bf76F2E522566Da33")

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


SCRT_TOKEN_CODE_ID = 18
SCRT_SWAP_CODE_ID = 21


def deploy_scrt():

    # docker exec -it secretdev secretcli tx compute store "/token.wasm.gz" --from a --gas 2000000 -b block -y
    #
    # docker exec -it secretdev secretcli tx compute store "/swap.wasm.gz" --from a --gas 2000000 -b block -y
    # 0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e
    multisig_account = config.multisig_acc_addr
    deployer = "secret18839huzvv5v6v0z3tm6um2ascnt6vrqfsp8d4g"

    tokens = [{"address": "0x1cB0906955623920c86A3963593a02a405Bb97fC", "name": "True USD", "decimals": 18, "symbol": "TUSD"},
              {"address": "0xF6fF95D53E08c9660dC7820fD5A775484f77183A", "name": "YEENUS", "decimals": 8, "symbol": "YNUS"},
              {"address": "native", "name": "Ethereum", "decimals": 15, "symbol": "ETH"}]

    swap_contract, swap_contract_hash = init_swap_contract(deployer)
    # swap_contract = "secret1u8mgmspdeakpf7u8leq68d5xtkykskwrytevyn"
    # swap_contract_hash = "5C36ABD74F5959DD9E8BCECB2EA308BEFEAFF2A50B9BCBD2338C079266F9F0BF"
    print(f"Swap contract deployed at: {swap_contract}")
    for token in tokens:

        config.token_contract_addr = token

        scrt_token, scrt_token_code = init_token_contract(deployer, token["decimals"], f'S{token["symbol"]}',
                                                          f'Secret {token["name"]}', swap_contract)
        add_minter(scrt_token, deployer)
        print(f"Secret {token['name']}, Deployed at: {scrt_token}")
        add_to_whitelist(swap_contract, scrt_token, scrt_token_code, pow(10, token["decimals"]))

        import os
        uri = os.environ.get("db_uri")
        with database(uri):
            try:
                TokenPairing.objects().get(src_network="Ethereum", src_address=token["address"]).update(dst_address=scrt_token)
                print("Updated DB record")
            except:
                print("Added new pair to db")
                TokenPairing(src_network="Ethereum", src_coin=token["name"], src_address=token["address"],
                             dst_network="Secret", dst_coin=f"secret-{token['name']}", dst_address=scrt_token,
                             decimals=18, name="Ethereum").save()

    change_owner(swap_contract, config.multisig_acc_addr)


    # configuration["swap_code_hash"] = swap_contract_hash
    # configuration["scrt_swap_address"] = swap_contract


def add_minter(token_addr, minter):
    tx_data = {"add_minters": {"minters": [minter]}}
    cmd = f"secretcli tx compute execute {token_addr} '{json.dumps(tx_data)}'" \
          f" --from t1 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def add_to_whitelist(swap_contract, token_addr, code_hash, min_amount: int):
    print(f"Adding token {token_addr} to {swap_contract}, minimum amount: {str(min_amount)}")
    tx_data = {"add_token": {"address": token_addr, "code_hash": code_hash, "minimum_amount": str(min_amount)}}
    cmd = f"secretcli tx compute execute {swap_contract} '{json.dumps(tx_data)}'" \
          f" --from t1 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def change_owner(swap_contract, new_owner):
    tx_data = {"change_owner": {"owner": new_owner}}
    cmd = f"secretcli tx compute execute {swap_contract} '{json.dumps(tx_data)}'" \
          f" --from t1 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def init_token_contract(admin: str, decimals: int, symbol: str,
                        name: str, swap_addr: str = None) -> (str, str):

    tx_data = {"admin": admin, "name": name, "symbol": symbol, "decimals": decimals,
               "initial_balances": [], "config": {}, "prng_seed": "YWE"}

    cmd = f"secretcli tx compute instantiate {SCRT_TOKEN_CODE_ID} --label {rand_str(10)} " \
          f"'{json.dumps(tx_data)}' --from t1 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    res = subprocess.run(f"secretcli query compute list-contract-by-code {SCRT_TOKEN_CODE_ID} | jq '.[-1].address'",
                         shell=True, stdout=subprocess.PIPE)
    token_addr = res.stdout.decode().strip()[1:-1]
    res = subprocess.run(f"secretcli q compute contract-hash {token_addr}",
                         shell=True, stdout=subprocess.PIPE).stdout.decode().strip()[2:]
    sn_token_codehash = res

    if swap_addr:
        add_minter(token_addr, swap_addr)

    return token_addr, sn_token_codehash


def init_swap_contract(owner: str) -> (str, str):

    tx_data = {"owner": owner}

    cmd = f"secretcli tx compute instantiate {SCRT_SWAP_CODE_ID} --label {rand_str(10)} '{json.dumps(tx_data)}'" \
          f" --from t1 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    res = subprocess.run(f"secretcli query compute list-contract-by-code {SCRT_SWAP_CODE_ID} | jq '.[-1].address'",
                         shell=True, stdout=subprocess.PIPE)
    swap_addr = res.stdout.decode().strip()[1:-1]

    res = subprocess.run(f"secretcli q compute contract-hash {swap_addr}",
                         shell=True, stdout=subprocess.PIPE).stdout.decode().strip()[2:]
    swap_code_hash = res

    return swap_addr, swap_code_hash


def configure_db():

    with database():
        # TokenPairing(src_network="Ethereum", src_coin="ETH", src_address="native",
        #              dst_network="Secret", dst_coin="secret-ETH", dst_address="secret1nk5c3agzt3ytpkl8csfhf4e3qwleauex9ay69t").save()
        TokenPairing.objects().get(src_network="Ethereum", dst_address="secret13lj8gqvdfn45d03lfrrl087dje5d6unzus2usv", dst_coin="secret-YEENUS").delete()
        # for obj in obs:
        #     obj.delete()
        #
        # TokenPairing(src_network="Ethereum", src_coin="YEENUS", src_address="0xF6fF95D53E08c9660dC7820fD5A775484f77183A",
        #              dst_network="Secret", dst_coin="secret-NUS", dst_address="secret17nfn68fdkvvplr8s0tu7qkhxfw08j7rwne5sl2").save()
        #
        # TokenPairing(src_network="Ethereum", src_coin="TUSD", src_address="native",
        #              dst_network="Secret", dst_coin="secret-TUSD", dst_address="secret1psm5jn08l2ms7sef2pxywr42fa8pay877vpg68").save()


if __name__ == '__main__':
    # deploy_eth()

    # add_token("0x1cB0906955623920c86A3963593a02a405Bb97fC", 1000000000000000000,
    #           "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e")
    # add_token("0x1cB0906955623920c86A3963593a02a405Bb97fC", 1000000000000000000, "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e")
    # add_token("0xF6fF95D53E08c9660dC7820fD5A775484f77183A", 100000000, "0xd475b764D1B2DCa1FE598247e5D49205E6Ac5E8e")

    deploy_scrt()

    # configure_db()

    # configuration = Config()
    # change_owner("secret1kg399h5gfad7hr80lh54pl3sjd6d72zxc4lpzz", configuration["multisig_acc_addr"])