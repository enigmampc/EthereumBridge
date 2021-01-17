import sys
from threading import Thread
from time import sleep
from typing import List

from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db import database
from src.leader.eth.leader import EtherLeader
from src.leader.secret20 import Secret20Leader
from src.signer.eth.signer import EtherSigner
from src.signer.secret20 import Secret20Signer
from src.signer.secret20.signer import SecretAccount
from src.util.common import Token, bytes_from_hex
from src.util.config import config
from src.util.crypto_store.local_crypto_store import LocalCryptoStore
from src.util.crypto_store.pkcs11_crypto_store import Pkcs11CryptoStore
from src.util.health_check import run
from src.util.logger import get_logger
from src.util.secretcli import configure_secretcli
from src.util.web3 import w3


def run_bridge():  # pylint: disable=too-many-statements
    runners = []
    logger = get_logger(logger_name='runner', loglevel=config.log_level)
    try:
        configure_secretcli(config)
    except RuntimeError:
        logger = get_logger(logger_name='runner', loglevel=config.log_level)
        logger.error('Failed to set up secretcli')
        sys.exit(1)

    if config.token:
        signer = Pkcs11CryptoStore(
            store=config.pkcs11_module, token=config.token, user_pin=config.user_pin, label=config.label
        )
    else:
        signer = LocalCryptoStore(private_key=bytes_from_hex(config.eth_private_key), account=config.eth_address)

    logger.info(f'Starting with ETH address {signer.address}')

    uri = config.db_uri
    if not uri:
        db = config.db_name or 'test_db'
        host = config.db_host or 'localhost'
        password = config.db_password
        username = config.db_username
        uri = f"mongodb+srv://{username}:{password}@{host}/{db}?retryWrites=true&w=majority"

    with database(uri):
        eth_wallet = MultisigWallet(w3, config.multisig_wallet_address)
        secret_account = SecretAccount(config.multisig_acc_addr, config.secret_key_name)

        eth_signer = EtherSigner(eth_wallet, signer, dst_network="Secret", config=config)
        s20_signer = Secret20Signer(secret_account, eth_wallet, config)

        runners.append(eth_signer)
        runners.append(s20_signer)

        if config.mode.lower() == 'leader':
            eth_leader = EtherLeader(eth_wallet, signer, dst_network="Secret", config=config)

            secret_leader = SecretAccount(config.multisig_acc_addr, config.multisig_key_name)
            s20_leader = Secret20Leader(secret_leader, eth_wallet, src_network="Ethereum", config=config)

            runners.append(eth_leader)
            runners.append(s20_leader)

        # run_all(runners)
        run(runners)


def run_all(runners: List[Thread]):
    for r in runners:
        r.start()

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for r in runners:
            if r.is_alive():
                r.stop()


if __name__ == '__main__':
    run_bridge()
