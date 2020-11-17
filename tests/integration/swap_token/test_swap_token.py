import base64
import json
from decimal import Decimal
from pathlib import Path
from subprocess import run, PIPE
from time import sleep

from web3 import Web3

from src.db.collections.eth_swap import Swap, Status
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.db.collections.signatures import Signatures
from src.db.collections.token_map import TokenPairing

from src.util.common import project_base_path
from src.util.config import Config
from src.util.secretcli import query_data_success
from src.util.web3 import event_log
# Note: The tests are ordered and named test_0...N and should be executed in that order as they demonstrate the flow
# Ethr -> Scrt and then Scrt -> Ethr
from tests.integration.conftest import PAYABLE_ADDRESS
from tests.utils.keys import get_key_signer

TRANSFER_AMOUNT_ETH = 1000000000000001
TRANSFER_AMOUNT_ERC = 100
zero_address = '0x000000000000000000000000000000000000dEaD'


def _test_header_log(func):
    import functools

    @functools.wraps(func)
    def test_header_log_wrapper(*args, **kwargs):
        print(f'-------------------------- Starting test {func.__name__}')
        ret = func(*args, **kwargs)
        print(f'-------------------------- Finished test {func.__name__}')
        return ret

    return test_header_log_wrapper


# Try to swap a token without the token being whitelisted -- should fail
@_test_header_log
def test_fail_swap_token_not_whitelisted(setup, scrt_leader, scrt_signers, web3_provider, configuration: Config,
                                         erc20_contract, multisig_wallet):

    t1_address = get_key_signer("t1", Path.joinpath(project_base_path(), configuration.path_to_keys))['address']

    tx_hash = erc20_contract.contract.functions.approve(multisig_wallet.address,
                                                                TRANSFER_AMOUNT_ERC). \
        transact({'from': web3_provider.eth.coinbase}).hex().lower()

    try:
        tx_hash = multisig_wallet.contract.functions.swapToken(t1_address.encode(),
                                                                       TRANSFER_AMOUNT_ERC,
                                                                       erc20_contract.address). \
                transact({'from': web3_provider.eth.coinbase}).hex().lower()
    except ValueError:
        pass
    # assert


@_test_header_log
def test_1_swap_eth_to_s20(setup, scrt_signers, scrt_leader, web3_provider, configuration: Config, multisig_wallet):

    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ETH").dst_address

    scrt_leader.start()
    for signer in scrt_signers:
        signer.start()

    fee_collector = multisig_wallet.contract.functions.getFeeCollector().call()

    print(f"{fee_collector=}")

    t1_address = get_key_signer("t1", Path.joinpath(project_base_path(), configuration.path_to_keys))['address']
    # swap ethr for secret20 token, deliver tokens to address of 'a'
    # (we will use 'a' later to check it received the money)
    print(f"Creating new swap transaction at {web3_provider.eth.getBlock('latest').number + 1}")
    tx_hash = multisig_wallet.contract.functions.swap(t1_address.encode()). \
        transact({'from': web3_provider.eth.coinbase, 'value': TRANSFER_AMOUNT_ETH}).hex().lower()
    # TODO: validate ethr increase of the smart contract
    # increase number of blocks to reach the confirmation threshold
    assert increase_block_number(web3_provider, configuration.eth_confirmations - 1)

    sleep(configuration.sleep_interval + 2)

    assert Swap.objects(src_tx_hash=tx_hash).count() == 0  # verify blocks confirmation threshold wasn't meet
    assert increase_block_number(web3_provider, 1)  # add the 'missing' confirmation block

    # give event listener and manager time to process tx
    sleep(configuration.sleep_interval + 5)
    assert Swap.objects(src_tx_hash=tx_hash).count() == 1  # verify swap event recorded

    sleep(1)
    # check signers were notified of the tx and signed it
    assert Signatures.objects().count() == len(scrt_signers)

    sleep(5)

    if Swap.objects().get().status == Status.SWAP_SUBMITTED:
        sleep(configuration.sleep_interval + 5)
    assert Swap.objects().get().status == Status.SWAP_CONFIRMED

    # get tx details
    tx_hash = Swap.objects().get().src_tx_hash
    _, log = event_log(tx_hash, ['Swap'], web3_provider, multisig_wallet.contract)
    transfer_amount = log.args.amount
    dest = log.args.recipient.decode()

    # validate swap tx on ethr delivers to the destination
    viewing_key_set = '{"set_viewing_key": {"key": "lol"}}'
    tx_hash = run(f"secretcli tx compute execute {secret_token_addr} "
                  f"'{viewing_key_set}' --from {dest} -b block -y | jq '.txhash'", shell=True, stdout=PIPE)
    sleep(6)

    balance = f'{{"balance": {{"key": "lol", "address": "{dest}"}} }}'
    res = run(f"secretcli q compute query {secret_token_addr} "
              f"'{balance}'", shell=True, stdout=PIPE)

    print(f"{res.stdout=}")

    amount = json.loads(res.stdout)["balance"]["amount"]

    print(f"swap amount: {transfer_amount}, dest balance amount: {amount}")

    assert int(amount) == log.args.amount


# covers EthrLeader tracking of swap events in secret20 and creating submission event in Ethereum
# ethr_signers are here to respond for leader's submission
@_test_header_log
def test_2_swap_s20_to_eth(setup, web3_provider, ethr_leader, configuration: Config, ethr_signers, scrt_signers):

    swap_contract_addr = configuration.scrt_swap_address
    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ETH").dst_address

    # start the eth signers
    for signer in ethr_signers[:-1]:
        signer.start()

    # Generate swap tx on secret network
    swap = {"send": {"amount": str(TRANSFER_AMOUNT_ETH),
                     "msg": base64.standard_b64encode(zero_address.encode()).decode(),
                     "recipient": swap_contract_addr}}

    sleep(configuration.sleep_interval)
    last_nonce = SwapTrackerObject.last_processed(secret_token_addr)
    print(f"last processed before: {last_nonce}")
    tx_hash = run(f"secretcli tx compute execute {secret_token_addr} "
                  f"'{json.dumps(swap)}' --from t1 --gas 300000 -y", shell=True, stdout=PIPE, stderr=PIPE)
    tx_hash = json.loads(tx_hash.stdout)['txhash']

    sleep(configuration.sleep_interval + 6)
    assert query_data_success(tx_hash) != {}

    last_nonce_after = SwapTrackerObject.last_processed(secret_token_addr)
    print(f"last processed before: {last_nonce_after}")
    assert last_nonce + 1 == last_nonce_after

    # Give ethr signers time to handle the secret20 swap tx
    increase_block_number(web3_provider, configuration.eth_confirmations)
    sleep(configuration.sleep_interval + 5)


# EthrSigner event response and multisig logic
# Components tested:
# 1. EthrSigner - confirmation and offline catchup
# 2. SmartContract multisig functionality
@_test_header_log
def test_3_confirm_and_finalize_eth_tx(web3_provider, ethr_signers, configuration: Config):
    # To allow the new EthrSigner to "catch up", we start it after the event submission event in Ethereum
    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ETH").dst_address
    prev_bal = web3_provider.eth.getBalance(zero_address, "latest")
    prev_bal_fee = web3_provider.eth.getBalance(PAYABLE_ADDRESS, "latest")
    ethr_signers[-1].start()
    sleep(1)
    assert increase_block_number(web3_provider, configuration.eth_confirmations)

    sleep(configuration.sleep_interval * 5)
    # Validate the tx is confirmed in the smart contract
    last_nonce = SwapTrackerObject.last_processed(secret_token_addr)
    # ethr_signers[-1].signer.multisig_contract.contract.functions.confirmations(last_nonce,
    #                                                                            ethr_signers[-1].account).call()

    assert last_nonce >= 0

    bal_fee = web3_provider.eth.getBalance(PAYABLE_ADDRESS, "latest")
    assert bal_fee > prev_bal_fee

    bal = web3_provider.eth.getBalance(zero_address, "latest")
    assert bal > prev_bal

    configuration.eth_start_block = web3_provider.eth.blockNumber


# TL;DR: Covers from swap tx to multisig in db(tx ready to be sent to secret20)
# Components tested:
# 1. Event listener registration recognize contract events
# 2. Manager status update and multisig creation.
# 3. SecretSigners validation and signing.
# 4. Smart Contract swap functionality.
@_test_header_log
def test_11_swap_erc_to_s20(scrt_leader, scrt_signers, web3_provider, configuration: Config,
                            erc20_contract, multisig_wallet, ethr_leader):

    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ERC").dst_address

    # scrt_leader.start()
    # for signer in scrt_signers:
    #     signer.start()

    t1_address = get_key_signer("t1", Path.joinpath(project_base_path(), configuration.path_to_keys))['address']
    # swap ethr for secret20 token, deliver tokens to address of 'a'.
    # (we will use 'a' later to check it received the money)

    # add usdt to the whitelisted token list
    account = web3_provider.eth.account.from_key(configuration.leader_key)
    nonce = web3_provider.eth.getTransactionCount(account.address, "pending")
    tx = multisig_wallet.contract.functions.addToken(erc20_contract.address, 1)
    raw_tx = tx.buildTransaction(transaction={'from': account.address, 'gas': 3000000, 'nonce': nonce})
    signed_tx = account.sign_transaction(raw_tx)
    tx_hash = web3_provider.eth.sendRawTransaction(signed_tx.rawTransaction)

    # Get transaction hash from deployed contract
    tx_receipt = web3_provider.eth.waitForTransactionReceipt(tx_hash)

    # this will likely fail since the test before also allocates the allowance - just ignore if it fails
    try:
        _ = erc20_contract.contract.functions.approve(multisig_wallet.address, TRANSFER_AMOUNT_ERC). \
            transact({'from': web3_provider.eth.coinbase})
    except ValueError:
        pass

    tx_hash = multisig_wallet\
        .contract\
        .functions\
        .swapToken(t1_address.encode(), TRANSFER_AMOUNT_ERC, erc20_contract.address)\
        .transact({'from': web3_provider.eth.coinbase}).hex().lower()

    assert TRANSFER_AMOUNT_ERC == erc20_contract.contract.functions.balanceOf(multisig_wallet.address).call()

    # increase number of blocks to reach the confirmation threshold
    assert increase_block_number(web3_provider, configuration.eth_confirmations - 1)

    sleep(configuration.sleep_interval + 2)

    assert Swap.objects(src_tx_hash=tx_hash).count() == 0  # verify blocks confirmation threshold wasn't meet
    assert increase_block_number(web3_provider, 1)  # add the 'missing' confirmation block

    # give event listener and manager time to process tx
    sleep(configuration.sleep_interval + 2)
    assert Swap.objects(src_tx_hash=tx_hash).count() == 1  # verify swap event recorded

    swap = Swap.objects(src_tx_hash=tx_hash).get()

    sleep(1)
    # check signers were notified of the tx and signed it
    assert Signatures.objects(tx_id=swap.id).count() == len(scrt_signers)

    # give time for manager to process the signatures
    sleep(configuration.sleep_interval + 2)
    assert Swap.objects().get(src_tx_hash=tx_hash).status in (Status.SWAP_SUBMITTED, Status.SWAP_CONFIRMED)

    _, log = event_log(tx_hash, ['SwapToken'], web3_provider, multisig_wallet.contract)
    transfer_amount = multisig_wallet.extract_amount(log)
    dest = multisig_wallet.extract_addr(log)

    # validate swap tx on ethr delivers to the destination
    viewing_key_set = '{"set_viewing_key": {"key": "lol"}}'
    _ = run(f"secretcli tx compute execute {secret_token_addr} "
            f"'{viewing_key_set}' --from {dest} -b block -y | jq '.txhash'", shell=True, stdout=PIPE)
    sleep(6)

    balance = f'{{"balance": {{"key": "lol", "address": "{dest}"}} }}'
    res = run(f"secretcli q compute query {secret_token_addr} "
              f"'{balance}'", shell=True, stdout=PIPE)

    print(f"{res.stdout=}")

    amount = json.loads(res.stdout)["balance"]["amount"]

    print(f"swap amount: {transfer_amount}, dest balance amount: {amount}")

    # give scrt_leader time to multi-sign already existing signatures
    sleep(configuration.sleep_interval + 5)
    assert Swap.objects().get(src_tx_hash=tx_hash).status == Status.SWAP_CONFIRMED


# covers EthrLeader tracking of swap events in secret20 and creating submission event in Ethereum
# ethr_signers are here to respond for leader's submission
@_test_header_log
def test_2_swap_s20_to_erc(web3_provider, ethr_leader, configuration: Config, ethr_signers, erc20_contract):

    swap_contract_addr = configuration.scrt_swap_address
    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ERC").dst_address

    # for signer in ethr_signers[:-1]:
    #     signer.start()

    # Generate swap tx on secret network
    swap = {"send": {"amount": str(TRANSFER_AMOUNT_ERC),
                     "msg": base64.b64encode(ethr_leader.signer.address.encode()).decode(),
                     "recipient": swap_contract_addr}}

    last_nonce = SwapTrackerObject.last_processed(src=secret_token_addr)
    tx_hash = run(f"secretcli tx compute execute {secret_token_addr} "
                  f"'{json.dumps(swap)}' --from t1 -b block -y --gas 300000", shell=True, stdout=PIPE, stderr=PIPE)
    tx_hash = json.loads(tx_hash.stdout)['txhash']
    print(f'{tx_hash=}')
    # Verify that leader recognized the burn tx
    assert increase_block_number(web3_provider, configuration.eth_confirmations)
    sleep(configuration.sleep_interval)

    assert last_nonce + 1 == SwapTrackerObject.last_processed(src=secret_token_addr)


# EthrSigner event response and multisig logic
# Components tested:
# 1. EthrSigner - confirmation and offline catchup
# 2. SmartContract multisig functionality
@_test_header_log
def test_3_confirm_tx(web3_provider, ethr_signers, configuration: Config, erc20_contract, ethr_leader):

    secret_token_addr = TokenPairing.objects().get(src_network="Ethereum", src_coin="ERC").dst_address

    assert increase_block_number(web3_provider, configuration.eth_confirmations)
    # To allow the new EthrSigner to "catch up", we start it after the event submission event in Ethereum
    # ethr_signers[-1].start()

    sleep(configuration.sleep_interval + 3)
    # Validate the tx is confirmed in the smart contract
    last_nonce = SwapTrackerObject.last_processed(src=secret_token_addr)
    assert last_nonce > -1
    # account for fee

    fee = erc20_contract.contract.functions.balanceOf(PAYABLE_ADDRESS).call()
    assert fee > 0
    assert TRANSFER_AMOUNT_ERC == erc20_contract.contract.functions.balanceOf(ethr_leader.signer.address).call() + fee


def increase_block_number(web3_provider: Web3, increment: int) -> True:
    # Creates arbitrary tx on the chain to increase the last block number
    for i in range(increment):
        web3_provider.eth.sendTransaction({
            'from': web3_provider.eth.coinbase,
            'to': web3_provider.eth.accounts[1],
            'value': 100
        })
    return True
