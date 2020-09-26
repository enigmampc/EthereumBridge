import json
from subprocess import PIPE, run as subprocess_run
from typing import List, Dict

from src.contracts.secret.secret_contract import swap_json


def sign_tx(unsigned_tx_path: str, multi_sig_account_addr: str, account_name: str):
    cmd = ['secretcli', 'tx', 'sign', unsigned_tx_path, '--signature-only', '--multisig',
           multi_sig_account_addr, '--from', account_name]

    return run_secret_cli(cmd)


def multisig_tx(unsigned_tx_path: str, multi_sig_account_name: str, *signed_tx):
    cmd = ['secretcli', 'tx', 'multisign', unsigned_tx_path, multi_sig_account_name] + list(signed_tx)

    return run_secret_cli(cmd)


def create_unsigned_tx(secret_contract_addr: str, transaction_data: Dict, chain_id: str, enclave_key: str,
                       code_hash: str, multisig_acc_addr: str) -> str:
    cmd = ['secretcli', 'tx', 'compute', 'execute', secret_contract_addr, f"{json.dumps(transaction_data)}",
           '--generate-only', '--chain-id', f"{chain_id}", '--enclave-key', enclave_key, '--code-hash',
           code_hash, '--from', multisig_acc_addr]
    return run_secret_cli(cmd)


def broadcast(signed_tx_path: str) -> str:
    cmd = ['secretcli', 'tx', 'broadcast', signed_tx_path]
    return run_secret_cli(cmd)


def decrypt(data: str) -> str:
    cmd = ['secretcli', 'query', 'compute', 'decrypt', data]
    return run_secret_cli(cmd)


def query_scrt_swap(nonce: int, contract_addr: str, viewing_key: str) -> str:
    query_str = swap_json(nonce, viewing_key)
    cmd = ['secretcli', 'query', 'compute', 'query', contract_addr, query_str]
    p = subprocess_run(cmd, stdout=PIPE, stderr=PIPE, check=True)
    return p.stdout.decode()


def query_tx(tx_hash: str):
    cmd = ['secretcli', 'query', 'tx', tx_hash]
    return run_secret_cli(cmd)


def run_secret_cli(cmd: List[str]) -> str:
    p = subprocess_run(cmd, stdout=PIPE, stderr=PIPE)

    err = p.stderr
    if err:
        raise RuntimeError(err)

    return p.stdout.decode()
