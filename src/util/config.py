import json
import os

from serde import Model, fields

from .logger import get_logger

logger = get_logger('config')

global_config_paths = {"LOCAL": "local_config.json",
                       "TESTNET": "testnet_config.json",
                       "MAINNET": "mainnet_config.json"}


env_defaults = {'LOCAL': './config/local_config.json',
                'TESTNET': './config/testnet_config.json',
                'MAINNET': './config/mainnet_config.json'}


__all__ = ['Config', 'config', 'get_config']


# The normalizers are pointed out explicitly here for robustness in case the field
# is written in the config file as a string, or is just fetched from the environment.
class Config(Model):
    # misc
    mode: fields.Str()
    log_level: fields.Str()
    logger_name: fields.Optional(fields.Str)
    sleep_interval: fields.Float(normalizers=[float])
    keys_base_path: fields.Str()
    path_to_keys: fields.Optional(fields.Str)  # Only used in tests

    # db stuff
    db_name: fields.Str()
    db_uri: fields.Optional(fields.Str)
    db_host: fields.Optional(fields.Str)
    db_password: fields.Optional(fields.Str)
    db_username: fields.Optional(fields.Str)

    # multisig stuff
    signatures_threshold: fields.Int(normalizers=[int])
    multisig_wallet_address: fields.Str()  # Ethereum address
    multisig_acc_addr: fields.Str()  # SN address
    multisig_key_name: fields.Str()
    secret_signers: fields.Str()

    # ethereum stuff
    eth_node: fields.Str()
    network: fields.Str()
    eth_start_block: fields.Int(normalizers=[int])
    eth_confirmations: fields.Int(normalizers=[int])

    # eth account stuff
    eth_address: fields.Optional(fields.Str)
    eth_private_key: fields.Optional(fields.Str)
    pkcs11_module: fields.Optional(fields.Str)
    token: fields.Optional(fields.Str)
    user_pin: fields.Optional(fields.Str)
    label: fields.Optional(fields.Str)

    # oracle stuff
    ethgastation_api_key: fields.Optional(fields.Str)

    # secret network stuff
    secretcli_home: fields.Str()
    secret_node: fields.Str()
    enclave_key: fields.Str()
    chain_id: fields.Str()
    scrt_swap_address: fields.Str()
    swap_code_hash: fields.Str()

    # scrt account stuff
    secret_key_file: fields.Str()
    secret_key_name: fields.Str()
    secret_key_password: fields.Optional(fields.Str)

    # warnings
    eth_funds_warning_threshold: fields.Float(normalizers=[float])
    scrt_funds_warning_threshold: fields.Float(normalizers=[float])


def get_config(config_file: str = None) -> Config:
    if not config_file:
        config_file = env_defaults[os.getenv('SWAP_ENV', 'LOCAL')]

    logger.info(f'Loading custom configuration: {config_file}')
    try:
        with open(config_file) as f:
            conf_file_data = json.load(f)
    except IOError:
        logger.critical("there was a problem opening the config file")
        raise
    except json.JSONDecodeError as e:
        logger.critical("config file isn't valid json")
        raise ValueError from e

    config_data = {}
    for field_name, field_type in Config.__fields__.items():  # pylint: disable=no-member
        for source in [os.environ, conf_file_data]:
            if field_name in source:
                config_data[field_name] = source[field_name]
                break

            upper_field_name = field_name.upper()
            if upper_field_name in source:
                config_data[field_name] = source[upper_field_name]
                break
        else:  # This will run if the field has not been found in the `for` loop (if `break` has not been executed)
            if not isinstance(field_type, fields.Optional):
                raise EnvironmentError(f'Missing key {field_name!r} in configuration file or environment variables')

    return Config.from_dict(config_data)


config: Config = get_config()
