from os import path, name

import main

signing_accounts = ["account1", "account2"]
multisig_account = "name"
signatures_threshold = 2
manager_sleep_time_seconds = 5.0
contract_address = "0xfc4589c481538f29ad738a13da49af79d93ecb21"
provider_address = "wss://ropsten.infura.io/ws/v3/e5314917699a499c8f3171828fac0b74"
blocks_confirmation_required = 12
default_sleep_time_interval = 5.0

project_base_path, _ = path.split(main.__file__)
enclave_key = path.join(project_base_path, "temp", "io-master-cert.der")
enclave_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
chain_id = 2
if name == 'nt':
    secret_cli = path.join(project_base_path, "temp", "secretcli.exe")
else:
    secret_cli = path.join(project_base_path, "temp", "secretcli")

secret_contract_address = "secret1h492k6dvfqcuraa935p7laaz203rz5546s0n8k"
