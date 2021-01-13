import sys
from logging import Logger
from time import sleep
from typing import List

from src.base import Entity
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.cosmos_hub.gaia import GaiaCli
from src.db import database
from src.ethereum import EthEgressLeader, EthEgressSigner, EthIngressLeader, EthIngressSigner
from src.cosmos_hub import CosmosEgressLeader, CosmosEgressSigner, CosmosIngressLeader, CosmosIngressSigner
from src.util.common import bytes_from_hex, SecretAccount
from src.util.config import config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.crypto_store.local_crypto_store import LocalCryptoStore
from src.util.crypto_store.pkcs11_crypto_store import Pkcs11CryptoStore
from src.util.logger import get_logger
from src.util.secretcli import configure_secretcli
from src.util.web3 import w3


def get_database_uri() -> str:
    uri = config.db_uri
    if not uri:
        db = config.db_name or 'test_db'
        host = config.db_host or 'localhost'
        password = config.db_password
        username = config.db_username
        uri = f"mongodb+srv://{username}:{password}@{host}/{db}?retryWrites=true&w=majority"

    return uri


def get_sn_signer_account() -> SecretAccount:
    return SecretAccount(config.multisig_acc_addr, config.secret_key_name)


def get_sn_leader_account() -> SecretAccount:
    return SecretAccount(config.multisig_acc_addr, config.multisig_key_name)


def get_eth_crypto_store() -> CryptoManagerBase:
    if config.token:
        store = Pkcs11CryptoStore(
            store=config.pkcs11_module, token=config.token, user_pin=config.user_pin, label=config.label
        )
    else:
        store = LocalCryptoStore(private_key=bytes_from_hex(config.eth_private_key), account=config.eth_address)

    return store


def get_ethereum_entities(logger: Logger) -> List[Entity]:
    signer = get_eth_crypto_store()
    logger.info(f'Starting with ETH address {signer.address}')

    sn_signer_account = get_sn_signer_account()
    eth_wallet = MultisigWallet(w3, config.multisig_wallet_address)

    eth_signer = EthEgressSigner(config, signer, eth_wallet)
    sn_signer = EthIngressSigner(config, sn_signer_account, eth_wallet)

    if config.mode.lower() == 'leader':
        sn_leader_account = get_sn_leader_account()

        eth_leader = EthEgressLeader(config, signer, eth_wallet)
        sn_leader = EthIngressLeader(config, sn_leader_account, eth_wallet)

        entities = [eth_signer, sn_signer, eth_leader, sn_leader]
    else:
        entities = [eth_signer, sn_signer]

    return entities


def setup_gaiacli_keys(cli: GaiaCli, logger: Logger):
    logger.info("importing offline keys for all cosmos signers")
    parsed_signers = config.cosmos_signers.replace(' ', '').split(',')
    signers: List[str] = []
    for i, signer in parsed_signers:
        signer_name = f"cosmos-signer-{i}"
        signers.append(signer_name)
        cli.create_offline_key(signer_name, signer)

    logger.info("creating cosmos multisig address")
    output = cli.create_multisig_key(config.cosmos_multisig_key_name, config.signatures_threshold, signers)
    print(output)

    logger.info(f'importing private key from {config.cosmos_key_file} with name {config.cosmos_key_name}')
    cli.import_key(config.cosmos_key_name, config.cosmos_key_file, config.cosmos_key_password)


def get_cosmos_entities(logger: Logger) -> List[Entity]:
    cli = GaiaCli('secretcli', 'uscrt', 'holodeck-2')
    # cli = GaiaCli()
    cli.configure('http://bootstrap.secrettestnet.io:26657')
    setup_gaiacli_keys(cli, logger)

    sn_signer_account = get_sn_signer_account()
    cosmos_signer_account = cli.get_key_info(config.cosmos_key_name)['address']
    logger.info(f"starting with ATOM address {cosmos_signer_account}")

    eth_signer = CosmosEgressSigner(config, cosmos_signer_account, config.multisig_wallet_address, cli)
    sn_signer = CosmosIngressSigner(config, sn_signer_account, config.multisig_wallet_address, cli)

    if config.mode.lower() == 'leader':
        sn_leader_account = get_sn_leader_account()
        cosmos_multisig_addr = cli.get_key_info(config.cosmos_multisig_key_name)['address']
        cosmos_multisig_account = SecretAccount(config.cosmos_multisig_key_name, cosmos_multisig_addr)

        eth_leader = CosmosEgressLeader(config, cosmos_multisig_account, cli)
        sn_leader = CosmosIngressLeader(config, sn_leader_account, config.multisig_wallet_address, cli)

        entities = [eth_signer, sn_signer, eth_leader, sn_leader]
    else:
        entities = [eth_signer, sn_signer]

    return entities


def run_bridge():  # pylint: disable=too-many-statements
    logger = get_logger(logger_name='runner', loglevel=config.log_level)
    try:
        configure_secretcli(config)
    except RuntimeError:
        logger = get_logger(logger_name='runner', loglevel=config.log_level)
        logger.error('Failed to set up secretcli')
        sys.exit(1)

    uri = get_database_uri()

    with database(uri):
        entities = []
        entities += get_ethereum_entities(logger)
        entities += get_cosmos_entities(logger)

        run_all(entities)


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
