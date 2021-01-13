from typing import List

from .gaia import GaiaCli, GaiaCliError
from ..base import EgressLeader, Network, SwapEvent, SwapFailed
from ..db import Signatures, Swap, Status
from ..util.common import SecretAccount, temp_file, temp_files
from ..util.config import Config
from ..util.crypto_store.crypto_manager import CryptoManagerBase


class CosmosEgressLeader(EgressLeader):
    def __init__(self, config: Config, multisig: SecretAccount, cli: GaiaCli):
        super().__init__(config)
        self._multisig = multisig
        self._cli = cli
        self._multisig_account_num = self._cli.get_account_details(multisig.address)['value']['account_number']
        self._pending_tx_hashes = []
        self._failed_tx_hashes = []

    @classmethod
    def native_network(cls) -> Network:
        return Network.CosmosHub

    def update_sequence(self):
        details = self._cli.get_account_details(self._multisig.address)
        self.sequence = details['value']['sequence']

    def handle_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a native coin, back to the native coin"""
        # TODO add extra fee to this, above the operational cost
        fee = self._cli.SEND_FEE if self.config.network == "mainnet" else 1
        if fee <= swap_event.amount:
            raise SwapFailed(swap_event, '')

        amount = swap_event.amount - fee  # Charge the fee
        swap_event.data = self._cli.generate_send_tx(self._multisig.address, swap_event.recipient, amount)
        # We don't know the dest tx yet, but we use the tx nonce as the identifier so we can use it later
        return swap_event.nonce

    def handle_non_native_swap(self, swap_event: SwapEvent) -> str:
        """This should handle swaps from the secret version of a non-native coin, back to the non-native coin

        An example of a non-native coin would be an ERC-20 coin.
        """
        raise NotImplementedError('Cosmos Hub does not support non-native coins')

    def get_completed_swap_ids(self) -> List[str]:
        #  "raw_log": "insufficient funds: insufficient account funds; 16800000uscrt \u003c 100000000uscrt:
        #  failed to execute message; message index: 0",
        for swap in Swap.objects(status=Status.SWAP_SIGNED, dst_network=self.native_network().value):
            signatures = Signatures.objects(tx_id=swap.src_tx_hash)
            if len(signatures) < self.config.signatures_threshold:
                self.logger.warning(
                    f"Swap {swap.src_tx_hash} has been marked as signed before enough signatures have been collected"
                )
                continue

            signatures = [signature.signed_tx for signature in signatures]
            tx_hash = self._sign_and_send_tx(swap.unsigned_tx, signatures, swap.sequence)
            self._pending_tx_hashes.append(tx_hash)

        pending_tx_hashes = []
        failed_tx_hashes = []
        completed_tx_hashes = []
        for tx_hash in self._pending_tx_hashes:
            try:
                tx = self._cli.query_tx(tx_hash)
            except GaiaCliError as e:
                if 'not found' not in e.inner.stderr:
                    self.logger.warning(f"unexpected error while querying tx {tx_hash}: {e.inner.stderr!r}")
                pending_tx_hashes.append(tx_hash)
                continue

            if 'logs' in tx:
                completed_tx_hashes.append(tx_hash)
            else:
                failed_tx_hashes.append(tx_hash)

        self._pending_tx_hashes = pending_tx_hashes
        self._failed_tx_hashes = failed_tx_hashes

        return completed_tx_hashes

    def _sign_and_send_tx(self, unsigned_tx: str, signatures: List[str], sequence: int):
        with temp_file(unsigned_tx) as tx_path:
            with temp_files(signatures, self.logger) as signature_paths:
                ms_tx = self._cli.create_multisig_tx(
                    tx_path, self._multisig.name, self._multisig_account_num, sequence, signature_paths
                )

        with temp_file(ms_tx) as tx_path:
            tx_hash = self._cli.broadcast_tx(tx_path)

        return tx_hash

    def get_failed_swap_ids(self) -> List[str]:
        # You should call `get_completed_swap_ids` first for this to give a useful value
        failed_txs = self._failed_tx_hashes
        self._failed_tx_hashes = []
        return failed_txs
