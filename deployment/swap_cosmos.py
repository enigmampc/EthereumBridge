import base64
import json
import subprocess


def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, check=True, text=True).stdout


def addr_of_key(key_name: str) -> str:
    return run_shell(f"secretcli keys show {key_name} | jq -r '.address'").strip()


def create_viewing_key(token: str, user: str) -> str:
    response = run_shell(f"secretcli tx secret20 create-viewing-key {token} --from {user} -y -b block")
    tx_hash = json.loads(response)['txhash']
    print(f"created viewing key in {tx_hash}")
    response = run_shell(f"secretcli query compute tx {tx_hash}")
    viewing_key = json.loads(json.loads(response)['output_data_as_string'])['create_viewing_key']['key']
    return viewing_key


def swap_atom_to_satom():
    sender_key = 'cosm-user'
    sender_addr = addr_of_key('cosm-user')
    recipient_addr = addr_of_key('scrt-user')
    cosmos_ms_addr = addr_of_key('kms-3-3')
    secret_atom = 'secret1m2332v066t7ll6z9cr4ceyrfzvufj29thqfqjg'

    # send 0.1 SCRT to the multisig from cosm-user
    response = run_shell(f"secretcli tx send -y {sender_addr} {cosmos_ms_addr} 100000uscrt --memo {recipient_addr}")
    tx_hash = json.loads(response)['txhash']
    print(f"sent atom to bridge in: {tx_hash}")

    viewing_key = create_viewing_key(secret_atom, sender_key)
    print(viewing_key)
    # viewing_key = 'api_key_3Q9hoyYSH4iPxyi++psV5uB2OLW50inSGY3F9Q8/OMc='
    response = run_shell(f"secretcli q secret20 balance {secret_atom} {recipient_addr} {viewing_key}")
    print(response)


def swap_satom_to_atom():
    sender_key = 'scrt-user'
    recipient_addr = addr_of_key('cosm-user')
    swap_contract = 'secret1j8n6qxtpd8mlwkjmmk8vel8pdsq8hs996j6atr'
    secret_atom = 'secret1m2332v066t7ll6z9cr4ceyrfzvufj29thqfqjg'

    swap = {"send": {
        "amount": '100000',
        "msg": base64.standard_b64encode(recipient_addr.encode()).decode(),
        "recipient": swap_contract,
    }}

    response = run_shell(
        f"secretcli tx compute execute {secret_atom} '{json.dumps(swap)}' --from {sender_key} --gas 300000 -y"
    )
    print(response)

    response = run_shell(f"secretcli q account {recipient_addr}")
    print(response)


if __name__ == '__main__':
    try:
        # swap_atom_to_satom()
        # swap_satom_to_atom()
        pass
    except subprocess.CalledProcessError as e:
        print(e.stdout)
        print(e.stderr)
        raise
