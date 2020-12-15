from ..base import IngressSigner, Network
from ..contracts.ethereum.multisig_wallet import MultisigWallet
from ..util.common import SecretAccount
from ..util.config import Config


class EthIngressSigner(IngressSigner):
    def __init__(self, config: Config, multisig: SecretAccount, contract: MultisigWallet):
        super(EthIngressSigner, self).__init__(config, multisig)
        self._contract = contract

    @classmethod
    def native_network(cls) -> Network:
        return Network.Ethereum

    def verify_transaction(self, tx_hash: str, recipient: str, amount: int, token: str):
        log = self._contract.get_events_by_tx(tx_hash)
        if not log:  # because for some reason event_log can return None???
            return False

        # extract amount from on-chain swap tx
        try:
            log_amount = self._contract.extract_amount(log)
            log_recipient = self._contract.extract_addr(log)
            if (token_address := self._contract.extract_token(log)) is None:
                raise AttributeError
        except AttributeError:
            self.logger.error(f"Failed to validate tx data: {tx_hash}, {log}, "
                              f"failed to get amount or address from on-chain eth tx")
            return False

        # check that amounts on-chain and in the db match the amount we're minting
        if amount != log_amount:
            self.logger.error(
                f"Failed to validate tx data: {tx_hash} ({amount}, {log_amount} amounts do not match")
            return False

        # check that the address we're minting to matches the target from the TX
        if recipient != log_recipient:
            self.logger.error(f"Failed to validate tx data: {tx_hash}, ({recipient}, {log_recipient}),"
                              f" addresses do not match")
            return False

        if token != token_address:
            self.logger.error(f"Failed to validate tx data: {tx_hash}, ({token}, {token_address}),"
                              f" token addresses do not match")
            return False

        return True
