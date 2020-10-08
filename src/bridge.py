from os import _exit
from threading import Thread
from time import sleep
from typing import Union

from mongoengine import connect

from src.contracts.ethereum.erc20 import Erc20
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.db import database
from src.leader.erc20.leader import ERC20Leader
from src.leader.eth.leader import EtherLeader
from src.leader.secret20 import Secret20Leader
from src.signer.erc20.signer import ERC20Signer
from src.signer.eth.signer import EtherSigner
from src.signer.secret20 import Secret20Signer
from src.signer.secret20.signer import SecretAccount
from src.util.common import Token, bytes_from_hex
from src.util.config import Config
from src.util.logger import get_logger
from src.util.secretcli import configure_secretcli
from src.util.web3 import web3_provider


def chain_objects(signer, leader) -> dict:
    return {'signer': signer, 'leader': leader}


SUPPORTED_TYPES = ['erc20', 'eth', 's20', 'scrt']

SUPPORTED_COINS = [{'dai': 'sdai'}, {'eth': 'seth'}]


NETWORK_PARAMS = {
    'dai': {'type': 'erc20',
            'mainnet': {'address': '0x06526C574BA6e45069057733bB001520f08b59ff',
                        'decimals': 6},
            'ropsten': {'address': '0x06526C574BA6e45069057733bB001520f08b59ff',
                        'decimals': 6},
            'local': {'address': '0x06526C574BA6e45069057733bB001520f08b59ff',
                      'decimals': 6},
            },
    'sdai': {'type': 's20',
             'mainnet': {'address': 'secret1uwcjkghqlz030r989clzqs8zlaujwyphwkpq0n',
                         'decimals': 6},
             'holodeck': {'address': 'secret1uwcjkghqlz030r989clzqs8zlaujwyphwkpq0n',
                         'decimals': 6}},
    'eth': {'type': 'eth'},
    'seth': {'type': 's20',
             'mainnet': {'address': 'secret1uwcjkghqlz030r989clzqs8zlaujwyphwkpq0n',
                         'decimals': 6},
             'holodeck': {'address': 'secret1uwcjkghqlz030r989clzqs8zlaujwyphwkpq0n',
                         'decimals': 6}},
}
#
#
# chains = {
#     'dai': chain_objects(ERC20Signer, ERC20Leader),
#     'eth': chain_objects(EtherSigner, EtherLeader),
#     'sdai': chain_objects(Secret20Signer, Secret20Leader),
#     'seth': chain_objects(Secret20Signer, Secret20Leader)
# }


def get_token(token_name: str, network: str):
    return Token(NETWORK_PARAMS[token_name][network]['address'], token_name)


def get_leader(coin_name: str, eth_contract: Union[Erc20, MultisigWallet], private_key, account, cfg: Config) -> Thread:
    if NETWORK_PARAMS[coin_name]['type'] == 'erc20':
        token = get_token(coin_name, cfg['network'])
        return ERC20Leader(eth_contract, token, private_key, account, config=cfg)

    if NETWORK_PARAMS[coin_name]['type'] == 'eth':
        return EtherLeader(eth_contract, private_key, account, config=cfg)

    if NETWORK_PARAMS[coin_name]['type'] == 's20':
        s20token = get_token(coin_name, cfg['network'])
        account = SecretAccount(cfg['multisig_acc_addr'], cfg['multisig_key_name'])
        return Secret20Leader(account, s20token, eth_contract, config=cfg)


def run_bridge():

    runners = []
    required_configs = ['SRC_COIN', 'DST_COIN', 'MODE', 'private_key', 'account', 'secret_node', 'multisig_acc_addr',
                        'chain_id']
    cfg = Config(required=required_configs)
    try:
        configure_secretcli(cfg)
    except RuntimeError as e:
        logger = get_logger(logger_name='runner')
        logger.error(f'Failed to set up secretcli - {e}')
        _exit(1)

    with database(db=cfg['db_name'], host=cfg['db_host'], port=['db_port'],
                  password=cfg['db_password'], username=cfg['db_username']):

        provider = web3_provider(cfg['eth_node_address'])
        eth_wallet = MultisigWallet(provider, '0xef06222f18a008cd3635a8325208fc0ff934d830')

        private_key = bytes_from_hex(cfg['private_key'])
        account = cfg['account']

        scoin = cfg['SRC_COIN']
        dcoin = cfg['DST_COIN']
        erc20_contract = ''
        token = ''
        secret_account = SecretAccount(cfg['multisig_acc_addr'], cfg['secret_key_name'])
        if NETWORK_PARAMS[scoin]['type'] == 'erc20':
            token = get_token(scoin, cfg['network'])
            erc20_contract = Erc20(provider, token, eth_wallet.address)
            src_signer = ERC20Signer(eth_wallet, token, private_key, account, cfg)
            dst_signer = Secret20Signer(erc20_contract, secret_account, cfg)
        else:
            src_signer = EtherSigner(eth_wallet, private_key, account, cfg)
            dst_signer = Secret20Signer(eth_wallet, secret_account, cfg)

        runners.append(src_signer)
        runners.append(dst_signer)

        if cfg['MODE'].lower() == 'leader':
            src_leader = get_leader(scoin, eth_wallet, private_key, account, cfg)
            if erc20_contract:
                dst_leader = get_leader(dcoin, erc20_contract, private_key, account, cfg)
            else:
                dst_leader = get_leader(dcoin, eth_wallet, private_key, account, cfg)
            runners.append(src_leader)
            runners.append(dst_leader)

        map(lambda t: t.start(), runners)

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