import json
import random
import string
import subprocess
import secrets
import base64
import os
from src.db import database
from src.db.collections.token_map import TokenPairing
from src.util.config import config
from src.util.web3 import web3_provider


def rand_str(n):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for i in range(n))


SCRT_TOKEN_CODE_ID = 164
SCRT_SWAP_CODE_ID = 1108


def deploy_scrt():
    deployer = "secret1kpkh83pjff8zf42njqhasvpa4spg7rjuemucf7"

    tokens = [
        {"src_network": "Plasm", "src_coin": "Plasm",
         "src_address": "native", "dst_network": "Secret", "dst_coin": "secret-Plasm",
         "dst_address": "", "decimals": 18,
         "name": "Plasm",
         "display_props": {"symbol": "PLM", "image": "/static/plsm.svg",
                           "min_to_scrt": "0", "min_from_scrt": "0", "label": "secret-plm-plsm4"},
         "price": "1308.9295"},
        #

        {"src_network": "Plasm", "src_coin": "parachainAsset", "src_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
         "name": "parachainAsset", "decimals": 6,
         "dst_network": "Secret", "dst_address": "",
         "display_props": {"symbol": "TEMP", "image": "/static/plsm.svg",
                           "min_to_scrt": "0", "min_from_scrt": "0", "label": "secret-temp-plsm4"}},
        #
              ]
    swap_contract, swap_contract_hash = init_swap_contract(deployer)

    print(f"Swap contract deployed at: {swap_contract} - hash {swap_contract_hash}")
    for token in tokens:

        scrt_token, scrt_token_code = init_token_contract(deployer, token["decimals"], f'{token["display_props"]["symbol"]}',
                                                          f'Secret {token["name"]}', swap_contract, label=token["display_props"]["label"])
        add_minter(scrt_token, deployer)
        print(f"Secret {token['name']}, Deployed at: {scrt_token}")

        add_to_whitelist(swap_contract, scrt_token, scrt_token_code, 1)

        uri = os.environ.get("db_uri")
        with database(uri):
            TokenPairing(src_network="Ethereum", src_coin=token["name"], src_address=token["src_address"],
                         dst_network="Secret", dst_coin=f"secret-{token['name']}", dst_address=scrt_token,
                         name=token["name"],
                         decimals=18).save()

    print(f"Changing swap owner to {config.multisig_acc_addr}")


def add_minter(token_addr, minter):
    tx_data = {"add_minters": {"minters": [minter]}}
    cmd = f"secretcli tx compute execute {token_addr} '{json.dumps(tx_data)}'" \
          f" --from t4 -b block -y"
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
          f" --from t4 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def init_token_contract(admin: str, decimals: int, symbol: str,
                        name: str, swap_addr: str = None, label: str = None) -> (str, str):

    if not label:
        label = rand_str(10)

    amount = str(pow(10, decimals) * 100000)

    seed = base64.standard_b64encode(secrets.token_hex(32).encode()).decode()

    tx_data = {"admin": admin, "name": name, "symbol": symbol, "decimals": decimals,
               "initial_balances": [{"address": "secret1399pyvvk3hvwgxwt3udkslsc5jl3rqv4yshfrl", "amount": amount}], "config": {}, "prng_seed": seed}
    cmd = f"secretcli tx compute instantiate {SCRT_TOKEN_CODE_ID} --label {label} " \
          f"'{json.dumps(tx_data)}' --from t4 -b block -y"
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
          f" --from t4 -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    res = subprocess.run(f"secretcli query compute list-contract-by-code {SCRT_SWAP_CODE_ID} | jq '.[-1].address'",
                         shell=True, stdout=subprocess.PIPE)
    swap_addr = res.stdout.decode().strip()[1:-1]
    res = subprocess.run(f"secretcli q compute contract-hash {swap_addr}",
                         shell=True, stdout=subprocess.PIPE).stdout.decode().strip()[2:]
    swap_code_hash = res
    return swap_addr, swap_code_hash


if __name__ == '__main__':
    deploy_scrt()
