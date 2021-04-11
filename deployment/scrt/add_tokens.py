import base64
import json
import secrets
import subprocess

deployer = "secret1kpkh83pjff8zf42njqhasvpa4spg7rjuemucf7"
deployer_name = "t4"

SCRT_TOKEN_CODE_ID = 10

tokens = [
    {"src_network": "Ethereum", "src_coin": "RUNE", "src_address": "0x3155ba85d5f96b2d030a4966af206230e46849cb",
     "name": "THORChain (ERC20)", "decimals": 18,
     "symbol": "RUNE", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "RUNE",
                       "image": "https://tokens.1inch.exchange/0x3155ba85d5f96b2d030a4966af206230e46849cb.png",
                       "min_to_scrt": "0.2", "min_from_scrt": "20", "label": "secret-rune", "hidden": True}},

    {"src_network": "Ethereum", "src_coin": "TORN", "src_address": "0x77777feddddffc19ff86db637967013e6c6a116c",
     "name": "Tornado Cash", "decimals": 18,
     "symbol": "TORN", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "TORN",
                       "image": "https://tokens.1inch.exchange/0x77777feddddffc19ff86db637967013e6c6a116c.png",
                       "min_to_scrt": "0.006", "min_from_scrt": "0.6", "label": "secret-torn", "hidden": True}},

    {"src_network": "Ethereum", "src_coin": "BAT", "src_address": "0x0d8775f648430679a709e98d2b0cb6250d2887ef",
     "name": "Basic Attention Token", "decimals": 18,
     "symbol": "BAT", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "BAT",
                       "image": "https://tokens.1inch.exchange/0x0d8775f648430679a709e98d2b0cb6250d2887ef.png",
                       "min_to_scrt": "0.8", "min_from_scrt": "80", "label": "secret-bat", "hidden": True}},

    {"src_network": "Ethereum", "src_coin": "ZRX", "src_address": "0xe41d2489571d322189246dafa5ebde1f4699f498",
     "name": "0x", "decimals": 18,
     "symbol": "ZRX", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "ZRX",
                       "image": "https://tokens.1inch.exchange/0xe41d2489571d322189246dafa5ebde1f4699f498.png",
                       "min_to_scrt": "0.7", "min_from_scrt": "70", "label": "secret-zrx", "hidden": True}},

    {"src_network": "Ethereum", "src_coin": "ENJ", "src_address": "0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c",
     "name": "Enjin Coin", "decimals": 18,
     "symbol": "ENJ", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "ENJ",
                       "image": "https://tokens.1inch.exchange/0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c.png",
                       "min_to_scrt": "0.4", "min_from_scrt": "40", "label": "secret-enj"}},

    {"src_network": "Ethereum", "src_coin": "MANA", "src_address": "0x0f5d2fb29fb7d3cfee444a200298f468908cc942",
     "name": "Decentraland", "decimals": 18,
     "symbol": "MANA", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "MANA",
                       "image": "https://tokens.1inch.exchange/0x0f5d2fb29fb7d3cfee444a200298f468908cc942.png",
                       "min_to_scrt": "1", "min_from_scrt": "100", "label": "secret-mana"}},

    {"src_network": "Ethereum", "src_coin": "YFL", "src_address": "0x28cb7e841ee97947a86B06fA4090C8451f64c0be",
     "name": "YF Link", "decimals": 18,
     "symbol": "YFL", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "YFL",
                       "image": "https://tokens.1inch.exchange/0x28cb7e841ee97947a86B06fA4090C8451f64c0be.png",
                       "min_to_scrt": "0.005", "min_from_scrt": "0.5", "label": "secret-yfl"}},

    {"src_network": "Ethereum", "src_coin": "ALPHA", "src_address": "0xa1faa113cbe53436df28ff0aee54275c13b40975",
     "name": "AlphaToken", "decimals": 18,
     "symbol": "ALPHA", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "ALPHA",
                       "image": "https://tokens.1inch.exchange/0xa1faa113cbe53436df28ff0aee54275c13b40975.png",
                       "min_to_scrt": "0.5", "min_from_scrt": "55", "label": "secret-alpha"}},

    {"src_network": "Ethereum", "src_coin": "MATIC", "src_address": "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0",
     "name": "Polygon", "decimals": 18,
     "symbol": "MATIC", "dst_network": "Secret", "dst_address": "",
     "display_props": {"symbol": "MATIC",
                       "image": "https://tokens.1inch.exchange/0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0.png",
                       "min_to_scrt": "2.5", "min_from_scrt": "250", "label": "secret-matic"}},

    #


    #
          ]


def add_minter(token_addr, minter):
    tx_data = {"add_minters": {"minters": [minter]}}
    cmd = f"secretcli tx compute execute {token_addr} '{json.dumps(tx_data)}'" \
          f" --from {deployer_name} -b block -y"
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def init_token_contract(admin: str, decimals: int, symbol: str,
                        name: str, swap_addr: str = None, label: str = None) -> (str, str):

    seed = base64.standard_b64encode(secrets.token_hex(32).encode()).decode()

    tx_data = {"admin": admin, "name": name, "symbol": symbol, "decimals": decimals,
               "initial_balances": [], "config": {}, "prng_seed": seed}
    cmd = f"secretcli tx compute instantiate {SCRT_TOKEN_CODE_ID} --label {label} " \
          f"'{json.dumps(tx_data)}' --from {deployer_name} -b block -y"
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


if __name__ == "__main__":
    for token in tokens:
        init_token_contract()
