import json

from typing import Dict


def add_token(token: str, code_hash: str, min_amount: int) -> Dict:
    return {"add_token": {"address": token, "code_hash": code_hash, "minimum_amount": str(min_amount)}}


def mint_json(amount: str, tx_hash, address: str, token: str) -> Dict:
    return {"mint_from_ext_chain": {"amount": amount, "address": address, "identifier": tx_hash, "token": token}}


def swap_json(nonce: int, token: str) -> str:
    return json.dumps({"swap": {"nonce": nonce, "token": token}})


def swap_query_res(res_json: str) -> dict:
    return json.loads(res_json)['swap']['result']


def query_mint(tx_hash: str) -> str:
    return json.dumps({"mint_by_id": {"identifier": tx_hash}})


def parse_query_mint(res_json: str) -> bool:
    return json.loads(res_json)['mint']['result']


def change_admin(address: str):
    return json.dumps({"change_admin": {"address": address}})


def get_swap_id(swap_data: Dict) -> str:
    return str(swap_data["nonce"]) + '|' + swap_data["token"]
