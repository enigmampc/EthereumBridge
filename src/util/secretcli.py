import os
import json
import subprocess
from shutil import copyfile
from subprocess import PIPE, run as subprocess_run
from typing import List, Dict

from src.contracts.secret.secret_contract import swap_json
from src.util.config import Config, config
from src.util.logger import get_logger

logger = get_logger(logger_name="SecretCLI", loglevel=config.log_level)


def query_encrypted_error(tx_hash: str):
    cmd = ['secretcli', 'q', 'compute', 'tx', tx_hash]
    resp = run_secret_cli(cmd)

    resp_json = json.loads(resp)
    return resp_json["output_error"]


def sign_tx(unsigned_tx_path: str, multi_sig_account_addr: str, account_name: str, account: int, sequence: int):
    cmd = ['secretcli', 'tx', 'sign', unsigned_tx_path, '--signature-only', '--multisig',
           multi_sig_account_addr, '--from', account_name, '--offline', '--account-number', str(account),
           '--sequence', str(sequence)]

    return run_secret_cli(cmd)


def multisig_tx(unsigned_tx_path: str, multi_sig_account_name: str, account: int, sequence: int, *signed_tx):
    cmd = ['secretcli', 'tx', 'multisign', unsigned_tx_path, multi_sig_account_name] + list(signed_tx)
    cmd += ['--offline', '--account-number', str(account), '--sequence', str(sequence)]
    return run_secret_cli(cmd)


def create_unsigned_tx(secret_contract_addr: str, transaction_data: Dict, chain_id: str, enclave_key: str,
                       code_hash: str, multisig_acc_addr: str) -> str:
    cmd = ['secretcli', 'tx', 'compute', 'execute', secret_contract_addr, f"{json.dumps(transaction_data)}",
           '--generate-only', '--chain-id', f"{chain_id}", '--enclave-key', enclave_key, '--code-hash',
           code_hash, '--from', multisig_acc_addr, '--gas', '200000']
    return run_secret_cli(cmd)


def broadcast(signed_tx_path: str) -> str:
    # async mode allows sending more than 1 tx per block
    cmd = ['secretcli', 'tx', 'broadcast', signed_tx_path, '-b', 'async']
    return run_secret_cli(cmd)


def decrypt(data: str) -> str:
    cmd = ['secretcli', 'query', 'compute', 'decrypt', data]
    return run_secret_cli(cmd)


def query_scrt_swap(nonce: int, scrt_swap_address: str, token: str) -> str:
    query_str = swap_json(nonce, token)
    cmd = ['secretcli', 'query', 'compute', 'query', scrt_swap_address, f"{query_str}"]
    p = subprocess_run(cmd, stdout=PIPE, stderr=PIPE, check=True)
    return p.stdout.decode()


def query_tx(tx_hash: str):
    cmd = ['secretcli', 'query', 'tx', tx_hash]
    return run_secret_cli(cmd)


def account_info(account: str):
    cmd = ['secretcli', 'query', 'account', account]
    return json.loads(run_secret_cli(cmd))


def query_data_success(tx_hash: str) -> Dict:
    """ This command is used to test success of transactions. Raise if transaction failed, or return empty dict if
    transaction isn't on-chain yet

    :raises ValueError: On any bad response

    """
    cmd = ['secretcli', 'query', 'compute', 'tx', tx_hash]
    try:
        resp = run_secret_cli(cmd, log=False)
    except RuntimeError:
        return {}
    try:
        as_json = json.loads(resp)
        output_error = as_json["output_error"]
        if output_error:
            raise ValueError(f"Failed to execute transaction: {output_error}")
        return json.loads(json.loads(resp)["output_data_as_string"])
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to decode response as valid json: {e}, {resp}") from None
    except KeyError as e:
        raise ValueError(f"Failed to decode response {e}") from e


def get_uscrt_balance(address: str) -> int:
    info = account_info(address)
    amount = 0

    for coin in info['value']['coins']:
        if coin['denom'] == 'uscrt':
            amount += int(coin['amount'])

    return amount


def run_secret_cli(cmd: List[str], log: bool = True) -> str:
    """

    """
    try:
        logger.debug(f'Running command: {cmd}')
        p = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, check=True)
    except subprocess.CalledProcessError as e:
        if log:
            logger.error(f'Failed: stderr: {e.stderr.decode()}, stdout: {e.stdout.decode()}')
        raise RuntimeError(e.stdout.decode()) from None

    logger.debug('Success')
    return p.stdout.decode()


def configure_secretcli(config: Config):  # pylint: disable=too-many-statements, redefined-outer-name
    # check if cli is already set up:
    cmd = ['secretcli', 'keys', 'list']
    result = run_secret_cli(cmd)
    if result.strip() != '[]':  # sometimes \n is added to the result
        logger.info(f"{result}")
        logger.info("CLI already set up")
        return

    run_secret_cli(['secretcli', 'config', 'output', 'json'])
    run_secret_cli(['secretcli', 'config', 'indent', 'true'])
    run_secret_cli(['secretcli', 'config', 'trust-node', 'true'])
    run_secret_cli(['secretcli', 'config', 'node', config.secret_node])
    run_secret_cli(['secretcli', 'config', 'chain-id', config.chain_id])
    run_secret_cli(['secretcli', 'config', 'keyring-backend', 'test'])

    # set up multisig
    signers = []

    parsed_signers = config.secret_signers.replace(' ', '').split(',')

    for i, key in enumerate(parsed_signers):
        signers.append(f'ms_signer{i}')
        run_secret_cli(['secretcli', 'keys', 'add', f'ms_signer{i}', f'--pubkey={key}'])

    run_secret_cli([
        'secretcli', 'keys', 'add', f'{config.multisig_key_name}',
        f"--multisig={','.join(signers)}",
        '--multisig-threshold', f'{config.signatures_threshold}'
    ])

    logger.info(f'importing private key from {config.secret_key_file} with name {config.secret_key_name}')

    # import key
    key_path = os.path.join(f'{config.keys_base_path}', f'{config.secret_key_file}')
    process = subprocess.Popen(
        ['secretcli', 'keys', 'import', f'{config.secret_key_name}', f'{key_path}'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    inputdata = config.secret_key_password
    _, stderrdata = process.communicate(input=(inputdata+"\n").encode())

    if stderrdata:
        logger.error(f"Error importing secret key: {stderrdata}")
        raise EnvironmentError

    logger.debug("copying transaction key..")
    # copy transaction key from shared location
    src_key_path = os.path.join(f'{config.keys_base_path}', 'id_tx_io.json')
    dst_key_path = os.path.join(f'{config.secretcli_home}', 'id_tx_io.json')
    copyfile(src_key_path, dst_key_path)

    # test configuration
    run_secret_cli(['secretcli', 'query', 'account', config.multisig_acc_addr])

    run_secret_cli(['secretcli', 'query', 'register', 'secret-network-params'])
