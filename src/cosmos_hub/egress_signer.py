from typing import Iterable, Any, Tuple

from ..base import EgressSigner, Network, SwapEvent
from ..db import Swap, Status, Signatures
from ..util.common import temp_file
from ..util.config import Config
from ..util.gaia import GaiaCli


class CosmosEgressSigner(EgressSigner):
    def __init__(self, config: Config, signer_addr: str, multisig_addr: str, cli: GaiaCli):
        self._signer = signer_addr
        super().__init__(config)
        self._multisig = multisig_addr
        self._cli = cli
        self._multisig_account_num = self._cli.get_account_details(multisig_addr)['value']['account_number']

    def log_identifier(self) -> str:
        return '-' + self._signer[-4:]

    @classmethod
    def native_network(cls) -> Network:
        return Network.CosmosHub

    def get_new_submissions(self) -> Iterable[Any]:
        return Swap.objects(status=Status.SWAP_UNSIGNED, dst_network=self.native_network().value)

    def get_token_and_nonce(self, submission: Swap) -> Tuple[str, int]:
        """return the address of the token on the foreign network, and the swap nonce"""
        # The nonce was saved in dst_tx_hash because `CosmosEgressLeader.handle_native_swap` returned the swap nonce
        return submission.src_coin, submission.dst_tx_hash

    def verify_submission(self, submission_data: Swap, swap_event: SwapEvent) -> bool:
        # No validation needs to be done here
        return True

    def approve_submission(self, submission: Swap):
        with temp_file(submission.unsigned_tx) as tx_path:
            signed_tx = self._cli.create_multisig_signature(
                tx_path, self._signer, self._multisig, self._multisig_account_num, submission.sequence
            )
            signature = Signatures(tx_id=submission.src_tx_hash, signed_tx=signed_tx, signer=self._multisig)
            signature.save()
            signature_count = Signatures.objects.count()
            if signature_count >= self.config.signatures_threshold:
                submission.status = Status.SWAP_SIGNED  # Should probably be done by the leader to avoid races...
