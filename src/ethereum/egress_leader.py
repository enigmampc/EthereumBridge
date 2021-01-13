from typing import List

from web3.exceptions import TransactionNotFound
from web3.contract import LogReceipt

from ..base import EgressLeader, SwapEvent, SwapFailed, Network, get_tx_hash, NATIVE_COIN_ADDRESS
from ..contracts.ethereum import message
from ..contracts.ethereum.ethr_contract import broadcast_transaction
from ..contracts.ethereum.event_listener import EventTracker
from ..contracts.ethereum.multisig_wallet import MultisigWallet
from ..util.oracle.coins import Coin
from ..util.config import Config
from ..util.crypto_store.crypto_manager import CryptoManagerBase
from ..util.oracle.oracle import BridgeOracle
from ..util.web3 import erc20_contract, w3

WITHDRAW = 'Withdraw'
WITHDRAW_FAILURE = 'WithdrawFailure'


class EthEgressLeader(EgressLeader):
    def __init__(
        self,
        config: Config,
        signer: CryptoManagerBase,
        multisig_contract: MultisigWallet,
    ):  # pylint: disable=duplicate-code
        super().__init__(config)
        self._multisig_contract = multisig_contract
        self._erc20_interface = erc20_contract()
        self._signer = signer
        self._event_tracker = EventTracker(multisig_contract, [WITHDRAW, WITHDRAW_FAILURE], config.eth_confirmations)

    @classmethod
    def native_network(cls) -> Network:
        return Network.Ethereum

    def update_sequence(self):
        # No action needed for ethereum
        pass

    def handle_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a native coin, back to the native coin"""
        if self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
            fee = int(gas_price * 1e9 * self._multisig_contract.SUBMIT_GAS)
            self.logger.debug(f'calculated fee: {fee}')
        else:
            fee = 1

        # use address(0) for native ethereum swaps
        token_addr = '0x0000000000000000000000000000000000000000'
        native_amount = int(swap_event.amount - fee)
        data = ''

        return self._send_currency(swap_event, token_addr, swap_event.recipient, native_amount, fee, data)

    def handle_non_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a non-native coin, back to the non-native coin

        An example of a non-native coin would be an ERC-20 coin.
        """
        self._erc20_interface.address = swap_event.dst_coin_address

        if self.config.network == "mainnet":
            decimals = self._token_map[swap_event.src_coin_address].decimals
            x_rate = BridgeOracle.x_rate(Coin.Ethereum, Coin(swap_event.dst_coin_name))
            self.logger.info(f'Calculated exchange rate: {x_rate=}')
            gas_price = BridgeOracle.gas_price()
            fee = BridgeOracle.calculate_fee(
                self._multisig_contract.SUBMIT_GAS, gas_price, decimals, x_rate, swap_event.amount
            )
            self.logger.info(f'Fee taken: {fee}')
        # for testing mostly
        else:
            fee = 1

        checksum_addr = w3.toChecksumAddress(swap_event.recipient)
        data = self._erc20_interface.encodeABI(fn_name='transfer', args=[checksum_addr, swap_event.amount - fee])
        native_amount = 0  # no native funds

        return self._send_currency(
            swap_event, swap_event.dst_coin_address, swap_event.dst_coin_address, native_amount, fee, data
        )

    def _send_currency(
        self, swap_event: SwapEvent, token: str, recipient: str, native_amount: int, fee: int, data: str
    ) -> str:
        self.logger.info(f"sending currency to {recipient}, amount: {swap_event.amount}, token: {token}, fee: {fee}")
        if swap_event.amount <= fee:
            raise SwapFailed(swap_event, data)

        # if we are swapping token, no ether should be rewarded
        msg = message.Submit(recipient, native_amount, int(swap_event.nonce), token, fee, data)

        try:
            tx_hash = self._submit_swap(msg)
        except (ValueError, TransactionNotFound) as e:
            self.logger.critical(f"Failed to broadcast transaction for msg {repr(msg)}: {e}")
            raise SwapFailed(swap_event, data) from e

        return tx_hash

    def _submit_swap(self, msg: message.Submit):
        if self.config.network == "mainnet":
            gas_price = BridgeOracle.gas_price()
            self.logger.info(f'Current {gas_price=}Gwei')
        else:
            gas_price = None

        self._chcek_remaining_funds()

        data = self._multisig_contract.encode_data('submitTransaction', *msg.args())
        tx = self._multisig_contract.raw_transaction(
            self._signer.address, 0, data, gas_price,
            gas_limit=self._multisig_contract.SUBMIT_GAS
        )
        tx = self._multisig_contract.sign_transaction(tx, self._signer)

        tx_hash = broadcast_transaction(tx)

        self.logger.info(f"Submitted swap: hash: {tx_hash.hex()}")
        self.logger.debug(f"Submitted swap: hash: {tx_hash.hex()}, msg: {msg}")
        return tx_hash.hex()

    def _chcek_remaining_funds(self):
        remaining_funds = w3.eth.getBalance(self._signer.address)
        self.logger.info(f'ETH leader remaining funds: {w3.fromWei(remaining_funds, "ether")} ETH')
        fund_warning_threshold = self.config.eth_funds_warning_threshold
        if remaining_funds < w3.toWei(fund_warning_threshold, 'ether'):
            self.logger.warning(f'ETH leader {self._signer.address} has less than {fund_warning_threshold} ETH left - '
                                f'{remaining_funds}')

    def get_completed_swap_ids(self) -> List[str]:
        new_events = self._event_tracker.get_new_events(WITHDRAW)
        return list(map(self._event_to_swap_id, new_events))

    def get_failed_swap_ids(self) -> List[str]:
        new_events = self._event_tracker.get_new_events(WITHDRAW_FAILURE)
        return list(map(self._event_to_swap_id, new_events))

    def _event_to_swap_id(self, event: LogReceipt) -> str:
        # The `args` attribute is added to the `LogReceipt` instance by the `LogFilter` type.
        transaction_id = event.args.transactionId
        data = self._multisig_contract.submission_data(transaction_id)
        nonce = data['nonce']
        token = data['token']

        if token == '0x0000000000000000000000000000000000000000':
            token = NATIVE_COIN_ADDRESS

        scrt_token = self._secret_token_map[token].address

        tx_hash = get_tx_hash(nonce, scrt_token)
        return tx_hash
