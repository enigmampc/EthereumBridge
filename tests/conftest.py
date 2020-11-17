from os import path
from subprocess import run, PIPE
from typing import List

from mongoengine import connect
from pytest import fixture

import tests as tests_package
import tests.utils as utils_package
from src.signer.secret20.signer import SecretAccount
from src.util.common import module_dir

from src.util.config import Config, get_config
from tests.utils.keys import get_key_multisig_addr

utils_folder = module_dir(utils_package)
tests_folder = module_dir(tests_package)


@fixture(scope="module")
def configuration():
    # get address of account 'a' on docker
    config = get_config(config_file='config/test_config.json')
    a_address = run("docker exec secretdev secretcli keys show a | jq '.address'", shell=True, stdout=PIPE)
    config.a_address = a_address.stdout.decode().strip()[1:-1].encode()
    config.multisig_acc_addr = get_key_multisig_addr(f"ms{config.signatures_threshold}")
    # config.enclave_key = path.join(tests_folder, config["path_to_certs"], 'io-master-cert.der')

    return config


@fixture(scope="module")
def db(configuration: Config):
    # init connection to db
    connection = connect(db=configuration.db_name)

    # handle cleanup, fresh db
    db = connection.get_database(configuration.db_name)
    for collection in db.list_collection_names():
        db.drop_collection(collection)


@fixture(scope="module")
def multisig_account(configuration: Config):
    threshold = configuration.signatures_threshold
    multisig_addr = get_key_multisig_addr(f"ms{threshold}")
    return SecretAccount(multisig_addr, f"ms{configuration.signatures_threshold}")


@fixture(scope="module")
def scrt_accounts(configuration: Config) -> List[SecretAccount]:
    """multisig accounts for signers"""
    threshold = configuration.signatures_threshold
    multisig_acc_addr = get_key_multisig_addr(f"ms{threshold}")

    res = []
    for i in range(1, threshold + 1):
        res.append(SecretAccount(multisig_acc_addr, f"t{i}"))
    return res
