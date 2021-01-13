from ..base import IngressSigner, Network
from ..util.common import SecretAccount
from ..util.config import Config
from ..util.gaia import GaiaCli


class CosmosIngressSigner(IngressSigner):
    def __init__(self, config: Config, s20_multisig: SecretAccount, cosmos_multisig: str, cli: GaiaCli):
        super().__init__(config, s20_multisig)
        self._cosmos_multisig = cosmos_multisig
        self._cli = cli

    @classmethod
    def native_network(cls) -> Network:
        return Network.CosmosHub

    def verify_transaction(self, tx_hash: str, recipient: str, amount: int, token: str) -> bool:
        """Check if the tx at the `tx_hash` was sent to the `recipient` with `amount` funds.

        `tx_hash` is the identifier of the tx in the network we're integrating with.
        `recipient` is a Secret Network address
        `amount` refers to the amount of coin passed
        `token` is the address of the token on the non-secret network, or "native".
        """
        self.logger.info(f"Verifying tx {tx_hash}")

        tx = self._cli.query_tx(tx_hash)

        # This means the tx failed
        if 'logs' not in tx:
            self.logger.info(f"tx {tx_hash} was a failed tx")
            return False

        tx_value = tx['tx']['value']
        if recipient != tx_value['memo']:
            self.logger.info(f"tx {tx_hash} was sent to the wrong recipient")
            return False

        details = tx_value['msg'][0]['value']
        if self._cosmos_multisig != details['to_address']:
            self.logger.info(f"tx {tx_hash} was not sent to the multisig account")
            return False

        sent_currency = details['amount'][0]
        if amount != sent_currency['amount']:
            self.logger.info(f"tx {tx_hash} sent the wrong amount")
            return False

        if token != sent_currency['denom']:
            self.logger.info(f"tx {tx_hash} sent the wrong currency")
            return False

        return True
