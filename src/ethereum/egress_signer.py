from typing import Iterable, Any, Dict, Tuple

from src.base import EgressSigner, SwapEvent
from src.contracts.ethereum import message
from src.contracts.ethereum.ethr_contract import broadcast_transaction
from src.contracts.ethereum.multisig_wallet import MultisigWallet
from src.contracts.ethereum.event_listener import EventTracker
from src.db import SwapTrackerObject
from src.signer.eth.impl import signer_id
from src.util.config import Config
from src.util.crypto_store.crypto_manager import CryptoManagerBase
from src.util.oracle.oracle import BridgeOracle
from src.util.web3 import erc20_contract, w3


SUBMISSION = 'Submission'


class EthEgressSigner(EgressSigner):
    def __init__(
        self,
        multisig_contract: MultisigWallet,
        signer: CryptoManagerBase,
        config: Config,
    ):
        super().__init__(config)

        self._account = signer.address
        self._signer = signer
        self._multisig_contract = multisig_contract
        self._event_tracker = EventTracker(multisig_contract, confirmations=config.eth_confirmations)
        self._erc20_interface = erc20_contract()

        # This is just used to skip Ethereum blocks that we have already seen
        swap_tracker = SwapTrackerObject.get_or_create(src=signer_id(self._account))
        if swap_tracker.nonce == -1:
            swap_tracker.update(nonce=self.config.eth_start_block)

        self._event_tracker.register_event(SUBMISSION, swap_tracker.nonce)

    def get_new_submissions(self) -> Iterable[Any]:
        for submission_event in self._event_tracker.get_new_events(SUBMISSION):
            transaction_id = submission_event.args.transactionId
            self.logger.info(f'Got submission event with transaction id: {transaction_id}, checking status')
            submission_data = self._multisig_contract.submission_data(transaction_id)
            submission_data['blockNumber'] = submission_event.blockNumber

            if self._is_confirmed(transaction_id, submission_data):
                self.logger.info(f"skipping transaction {transaction_id} because it was already confirmed")
                continue

            # check if submitted tx is an ERC-20 transfer tx
            if submission_data['amount'] == 0 and submission_data['data']:
                _, params = self._erc20_interface.decode_function_input(submission_data['data'].hex())
                submission_data['amount'] = params['amount']
                submission_data['dest'] = params['recipient']

            if submission_data['token'] == '0x0000000000000000000000000000000000000000':
                submission_data['token'] = 'native'

            yield submission_data

    def _is_confirmed(self, transaction_id: int, submission_data: Dict[str, any]) -> bool:
        """Checks with the data on the contract if signer already added confirmation or if threshold already reached"""
        # check if already executed
        if submission_data['executed']:
            return True

        # check if signer already signed the tx
        res = self._multisig_contract.contract.functions.confirmations(transaction_id, self._account).call()
        # This conversion is probably unnecessary but let's keep it just in case.
        return bool(res)

    def get_token_and_nonce(self, submission: Any) -> Tuple[str, int]:
        return submission['token'], submission['nonce']

    def verify_submission(self, submission_data: Any, swap_event: SwapEvent) -> bool:
        self.logger.info(f"Testing validity of {submission_data}")

        # TODO validate fee

        if int(swap_event.amount) != int(submission_data['amount'] + submission_data['fee']):
            self.logger.error(
                f'Invalid transaction - {swap_event.amount} does not match '
                f'{submission_data["amount"]} + {submission_data["fee"]}'
            )
            return False

        # explicitly convert to checksum in case one side isn't checksum address
        swap_dest = w3.toChecksumAddress(swap_event.recipient)
        submission_dest = w3.toChecksumAddress(submission_data['dest'])
        if swap_dest != submission_dest:
            self.logger.error(f'Invalid transaction - {swap_dest} does not match {submission_dest}')
            return False

        self.logger.info('Validated successfully')
        return True

    def approve(self, submission: Any):
        """
        Sign the transaction with the signer's private key and then broadcast
        Note: This operation costs gas
        """
        self._check_remaining_funds()
        if self.config.network == "mainnet":
            gas_prices = BridgeOracle.gas_price()
        else:
            gas_prices = None
        msg = message.Confirm(submission['ethr_tx_hash'])

        data = self._multisig_contract.encode_data('confirmTransaction', *msg.args())
        tx = self._multisig_contract.raw_transaction(
            self._account, 0, data, gas_prices, gas_limit=self._multisig_contract.CONFIRM_GAS
        )
        tx = self._multisig_contract.sign_transaction(tx, self._signer)
        tx_hash = broadcast_transaction(tx)

        self.logger.info(msg=f"Signed transaction - signer: {self._account}, signed msg: {msg}, "
                             f"tx hash: {tx_hash.hex()}")

        swap = SwapTrackerObject.objects().get(src=signer_id(self._account))
        swap.update(nonce=submission['blockNumber'])

    def _check_remaining_funds(self):
        remaining_funds = w3.eth.getBalance(self._account)
        self.logger.debug(f'ETH signer remaining funds: {w3.fromWei(remaining_funds, "ether")} ETH')
        fund_warning_threshold = self.config.eth_funds_warning_threshold
        if remaining_funds < w3.toWei(fund_warning_threshold, 'ether'):
            self.logger.warning(f'ETH signer {self._account} has less than {fund_warning_threshold} ETH left')
