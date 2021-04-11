import subprocess
from json import JSONDecodeError
from random import randrange
from time import sleep
from typing import Dict

from mongoengine import DoesNotExist, MultipleObjectsReturned
from web3.datastructures import AttributeDict

import src.contracts.ethereum.message as message
from src.contracts.ethereum.ethr_contract import broadcast_transaction
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.secret.secret_contract import swap_query_res
from src.db.collections.eth_signatures import EthSignatures
from src.db.collections.scrt_retry import ScrtRetry
from src.db.collections.swaptrackerobject import SwapTrackerObject
from src.util.coins import CoinHandler
from src.util.common import swap_retry_address
from src.util.config import Config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.logger import get_logger
from src.util.oracle.oracle import BridgeOracle
from src.util.secretcli import query_scrt_swap
from src.util.web3 import erc20_contract, w3


def signer_id(account):
    return f'signer-{account}'


def extract_nonce_from_retry(data):
    data['nonce'] = int(ScrtRetry.objects().get(
        retry_id=f'{data["nonce"]}|{data["token"].lower()}'
    ).original_id.split('|')[0])


def _random_backoff():
    sleep(randrange(10))


class EthSignerImpl:  # pylint: disable=too-many-instance-attributes, too-many-arguments
    """
    Used to run through all the blocks starting from the number specified by the 'eth_start_block' config value, and up
    to the current block. After that is done the handle_submission method is used to sign individual transactions
    when triggered by an event listener

    Not 100% sure why we're doing this like this instead of just doing it in a single generic signer thread, but eh,
    it is what it is.

    Saves the last block in a file, which is used on the next execution to tell us where to start so we don't run
    through the same blocks multiple times

    Todo: Naming sucks. This is mostly caused by bad design, and by me not having enough coffee
    """
    # network = "Ethereum"

    def __init__(
        self,
        multisig_contract: MultisigWallet,
        signer: CryptoManagerBase,
        config: Config
    ):
        # todo: simplify this, pylint is right
        self.multisig_contract = multisig_contract
        self.account = signer.address
        self.signer = signer
        self.config = config
        self.logger = get_logger(
            db_name=config.db_name,
            loglevel=self.config.log_level,
            logger_name=config.logger_name or f"{self.__class__.__name__}-{self.account[0:5]}"
        )
        self.network = config.network
        self.erc20 = erc20_contract()
        self.catch_up_complete = False

        self.coins = CoinHandler()

    def _check_remaining_funds(self):
        remaining_funds = w3.eth.getBalance(self.account)
        self.logger.debug(f'ETH signer remaining funds: {w3.fromWei(remaining_funds, "ether")} ETH')
        fund_warning_threshold = self.config.eth_funds_warning_threshold
        if remaining_funds < w3.toWei(fund_warning_threshold, 'ether'):
            self.logger.warning(f'ETH signer {self.account} has less than {fund_warning_threshold} ETH left')

    # noinspection PyUnresolvedReferences
    def sign(self, submission_event: AttributeDict):
        """Tries to validate the transaction corresponding to submission id on the smart contract,
        confirms and signs if valid"""
        self._check_remaining_funds()

        transaction_id = submission_event.args.transactionId
        self.logger.info(f'Got submission event with transaction id: {transaction_id}, checking status')

        data = self.multisig_contract.submission_data(transaction_id)

        # this is here to avoid possible race-condition between different signers
        # since we don't want everyone to sign at the same time - each signer sleeps randomly between 1 and 10 seconds
        # slow down is probably insignificant
        _random_backoff()

        if self._is_confirmed(transaction_id, data):
            return

        self.logger.info(f'Transaction {transaction_id} is missing approvals. Checking validity..')

        # check if submitted tx is an ERC-20 transfer tx
        if data['amount'] == 0 and data['data']:
            _, params = self.erc20.decode_function_input(data['data'].hex())
            data['amount'] = params['amount']

            # if this is a retry swap we need to pull the original nonce to test
            if data['token'].lower() == swap_retry_address.lower():
                try:
                    extract_nonce_from_retry(data)
                except Exception as e:  # pylint: disable=broad-except
                    self.logger.error(f"Failed to get retry swap object for {data}. Error: {e}")
                    return

            data['token'] = data['dest']
            data['dest'] = params['recipient']

        else:
            if data['token'].lower() == swap_retry_address.lower():

                # if this is a retry swap we need to pull the original nonce to test
                try:
                    extract_nonce_from_retry(data)
                except Exception as e:  # pylint: disable=broad-except
                    self.logger.error(f"Failed to get retry swap object for {data}. Error: {e}")
                    return

                # and set the address to ETH
                data['token'] = '0x0000000000000000000000000000000000000000'

        self.validate_and_sign(data, submission_event, transaction_id)

        self.logger.info(f'Swap from secret network to ethereum signed successfully: {data}')

    def validate_and_sign(self, data, submission_event, transaction_id):
        try:
            if self._is_valid(data):
                self.logger.info(f'Transaction {transaction_id} is valid. Signing & approving..')
                self._approve_and_sign(transaction_id, data)

            else:
                self.logger.error(f'Failed to validate transaction: {data}')
        except ValueError as e:
            self.logger.error(f"Error parsing secret-20 swap event {data}. Error: {e}")
            return

        # either way we want to continue on
        finally:
            self.update_tracker_object(submission_event)

    def update_tracker_object(self, submission_event):
        obj = SwapTrackerObject.objects().get(src=signer_id(self.account))
        obj.update(nonce=submission_event["blockNumber"])

    def _eth_to_scrt(self, token: str) -> str:
        if token == '0x0000000000000000000000000000000000000000':
            return self.coins.scrt_address('native')
        return self.coins.scrt_address(token)

    def _is_valid(self, submission_data: Dict[str, any]) -> bool:
        # lookup the tx hash in secret20, and validate it.
        self.logger.info(f"Testing validity of {submission_data}")
        nonce = submission_data['nonce']
        token = submission_data['token']

        try:
            swap = query_scrt_swap(nonce, self.config.scrt_swap_address, self._eth_to_scrt(token))
        except subprocess.CalledProcessError as e:
            self.logger.error(f'Error querying transaction: {e}')
            raise RuntimeError from None

        try:
            swap_data = swap_query_res(swap)
            self.logger.debug(f'Parsing swap info: {swap_data}')
        except (AttributeError, JSONDecodeError) as e:
            raise ValueError from e
        if self._validate_tx_data(swap_data, submission_data):
            self.logger.info('Validated successfully')
            return True
        self.logger.info('Failed to validate')
        return False

    def _validate_tx_data(self, swap_data: dict, submission_data: dict) -> bool:
        """
        This used to verify secret-20 <-> ether tx data
        :param swap_data: the data from secret20 contract query
        :param submission_data: the data from the proposed tx on the smart contract
        """
        if int(swap_data['amount']) != int(submission_data['amount'] + submission_data['fee']):
            self.logger.error(f'Invalid transaction - {swap_data["amount"]} does not match '
                              f'{submission_data["amount"]} + {submission_data["fee"]}')
            return False

        # explicitly convert to checksum in case one side isn't checksum address
        dest = self.multisig_contract.provider.toChecksumAddress(swap_data['destination'])
        if dest != self.multisig_contract.provider.toChecksumAddress(submission_data['dest']):
            self.logger.error(f'Invalid transaction - {dest} does not match {submission_data["dest"]}')
            return False

        return True

    def _is_confirmed(self, transaction_id: int, submission_data: Dict[str, any]) -> bool:
        """Checks with the data on the contract if signer already added confirmation or if threshold already reached"""

        if EthSignatures.objects(tx_id=transaction_id).count() >= \
                (self.config.signatures_threshold_eth or self.config.signatures_threshold + 1):
            self.logger.debug(f'Transaction {transaction_id} has already been signed more than threshold')
            # todo: add a timer here
            return True

        # check if already executed
        if submission_data['executed']:
            return True

        # check if signer already signed the tx
        res = self.multisig_contract.contract.functions.confirmations(transaction_id, self.account).call()
        if res:
            return True

        return False

    def _save_lock_object(self, transaction_id: int):
        EthSignatures(swap_id='', tx_id=transaction_id, tx_hash='', signer=self.signer.address).save()

    def _approve_and_sign(self, submission_id: int, submission_data: dict):
        """
        Sign the transaction with the signer's private key and then broadcast
        Note: This operation costs gas

        submission_data is after the retry address changing - so the swap_id is just the nonce|token
        """
        if self.config.network == "mainnet":
            gas_prices = BridgeOracle.gas_price()
            self.logger.info(f'Current {gas_prices=}Gwei')
        else:
            gas_prices = None
        msg = message.Confirm(submission_id)

        data = self.multisig_contract.encode_data('confirmTransaction', *msg.args())
        tx = self.multisig_contract.raw_transaction(self.signer.address, 0, data, gas_prices,
                                                    gas_limit=self.multisig_contract.CONFIRM_GAS)
        tx = self.multisig_contract.sign_transaction(tx, self.signer)
        tx_hash = broadcast_transaction(tx)

        try:
            scrt_addr = self._eth_to_scrt(submission_data["token"])
            swap_id = f'{submission_data["nonce"]}|{scrt_addr}'
            self._save_sig_to_db(swap_id, submission_id, tx_hash.hex())
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Failed to get save signature object {submission_id=} {tx_hash}. Error: {e}")

        # tx_hash = self.multisig_contract.confirm_transaction(self.account, self.private_key, gas_prices, msg)
        self.logger.info(msg=f"Signed transaction - signer: {self.account}, signed msg: {msg}, "
                             f"tx hash: {tx_hash.hex()}")

    def _save_sig_to_db(self, swap_id, submission_id, tx_hash):
        try:
            old_sig = EthSignatures.objects().get(swap_id=swap_id, signer=self.signer.address)
            old_sig.update(swap_id=swap_id, tx_hash=tx_hash)
        except DoesNotExist:
            EthSignatures(swap_id=swap_id, tx_id=submission_id, tx_hash=tx_hash, signer=self.signer.address).save()
        except MultipleObjectsReturned:
            self.logger.error(f'Too many signatures for transaction in DB: {swap_id=}, {submission_id=}, {tx_hash=}')
