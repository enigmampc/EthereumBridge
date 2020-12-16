import sys
from time import sleep
from typing import List

from src.base import Entity
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db import database
from src.ethereum import EthEgressLeader, EthEgressSigner, EthIngressLeader, EthIngressSigner
from src.util.common import bytes_from_hex, SecretAccount
from src.util.config import config
from src.util.crypto_store.local_crypto_store import LocalCryptoStore
from src.util.crypto_store.pkcs11_crypto_store import Pkcs11CryptoStore
from src.util.logger import get_logger
from src.util.secretcli import configure_secretcli
from src.util.web3 import w3


def run_bridge():  # pylint: disable=too-many-statements
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
        runners = []
        eth_wallet = MultisigWallet(w3, config.multisig_wallet_address)
        secret_account = SecretAccount(config.multisig_acc_addr, config.secret_key_name)

        eth_signer = EthEgressSigner(eth_wallet, signer, config)
        s20_signer = EthIngressSigner(config, secret_account, eth_wallet)

        runners.append(eth_signer)
        runners.append(s20_signer)

        if config.mode.lower() == 'leader':
            eth_leader = EthEgressLeader(eth_wallet, signer, config)

            secret_leader = SecretAccount(config.multisig_acc_addr, config.multisig_key_name)
            s20_leader = EthIngressLeader(config, secret_leader, eth_wallet)

            runners.append(eth_leader)
            runners.append(s20_leader)

        run_all(runners)


def run_all(runners: List[Entity]):
    for r in runners:
        r.start_thread()

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
