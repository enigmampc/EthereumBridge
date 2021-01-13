import json
import subprocess
from typing import List, Dict


class GaiaCliError(Exception):
    def __init__(self, inner: subprocess.CalledProcessError):
        super().__init__(inner.stderr)
        self.inner = inner


class GaiaCli:
    SEND_FEE = 50000  # in scrt. == 200000 * 0.25

    DEFAULT_QUERY_LIMIT = 30

    def __init__(self, cli_name='gaiacli', denom='uatom', chain_id='cosmoshub-3'):
        self.cli_name = cli_name
        self.denom = denom
        self.chain_id = chain_id
        self._flags = ['--output', 'json', '--chain-id', self.chain_id]

    def _run(self, command: List[str], *, input: str = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self.cli_name, *self._flags, *command],
                input=input, capture_output=True, check=True, text=True
            )
        except subprocess.CalledProcessError as e:
            raise GaiaCliError(e)

    def _json_run(self, command: List[str], *, input: str = None):
        process = self._run(command, input=input)
        return json.loads(process.stdout)

    def configure(self, node: str = 'https://rpc.cosmos.network/status:26657'):
        self._run(['config', 'node', node])
        self._run(['config', 'trust-node', 'true'])
        self._run(['config', 'indent', 'false'])

    def import_key(self, name: str, path: str, password: str = ''):
        self._run(['keys', 'import', name, path], input=password+'\n')

    def create_offline_key(self, name: str, pubkey: str) -> Dict:
        return self._json_run(['keys', 'add', name, f'--pubkey', pubkey])

    def create_multisig_key(self, name: str, threshold: int, signers: List[str]) -> Dict:
        return self._json_run([
            'keys', 'add', name, '--signers', ','.join(signers), '--multisig-threshold', str(threshold)
        ])

    def query_tx(self, tx_hash) -> Dict:
        return self._json_run(['query', 'tx', tx_hash])

    def query_txs(self, events: str, page: int = 1, limit: int = DEFAULT_QUERY_LIMIT) -> List[Dict]:
        command = ['query', 'txs', '--events', events, '--limit', str(limit)]
        if page is not None:
            command += ['--page', str(page)]
        response = self._json_run(command)
        return response['txs']

    def query_txs_from(self, sender: str, page: int = 1, limit: int = DEFAULT_QUERY_LIMIT) -> List[Dict]:
        return self.query_txs(f'message.action=send&message.sender={sender}', page, limit)

    def query_txs_to(self, recipient: str, page: int = 1, limit: int = DEFAULT_QUERY_LIMIT) -> List[Dict]:
        return self.query_txs(f'transfer.recipient={recipient}', page, limit)

    def generate_send_tx(self, sender: str, recipient: str, amount: int) -> str:
        process = self._run(['tx', 'send', sender, recipient, f'{amount}{self.denom}', '--generate-only'])
        return process.stdout.strip()

    def get_key_info(self, key_name: str):
        return self._json_run(['keys', 'show', key_name])

    def get_account_details(self, address: str) -> Dict:
        return self._json_run(['query', 'account', address])

    def get_balance_of(self, address: str) -> List[Dict]:
        return self.get_account_details(address)['value']['coins']

    def create_multisig_signature(
        self, tx_path: str, signer: str, multisig_addr: str, account_num: int, sequence: int
    ) -> str:
        """Create a signature for one of the multisig participants.

        account_num and sequence should be of the multisig account
        """
        process = self._run([
            'tx', 'sign', tx_path,
            '--from', signer,
            '--multisig', multisig_addr,
            '--offline',
            '--account-number', str(account_num),
            '--sequence', str(sequence)
        ])
        return process.stdout

    def create_multisig_tx(
        self, tx_path: str, multisig_key_name: str, account_num: int, sequence: int, signature_paths: List[str]
    ) -> str:
        """Collect multisig signatures to a singe multisig transaction"""
        process = self._run([
            'tx', 'multisign', tx_path, multisig_key_name, *signature_paths,
            '--offline',
            '--account-number', str(account_num),
            '--sequence', str(sequence)
        ])
        return process.stdout

    def broadcast_tx(self, signed_tx_path: str) -> str:
        # async broadcast mode allows sending more than 1 tx per block
        return self._json_run(['tx', 'broadcast', signed_tx_path, '--broadcast-mode', 'async'])['txhash']


def _main():
    """Examples"""
    from pprint import pprint

    from src.util.common import temp_file, temp_files

    cli = GaiaCli('secretcli', 'uscrt')

    # Create, sign, and send multisig tx:
    signer1 = 'secret12q5e0ppulztmd03kyhmpxtutxga6guujh5tzry'
    signer2 = 'secret1q9l6rs89kf820re4jccklgvnfqnst5qc4stc0f'
    ms = 'secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm'
    recipient = 'secret1xp0peuxa9mjnf9pplmxkxfgy9ks8nvavds78z0'

    ms_details = cli.get_account_details(ms)
    ms_account_num = ms_details['value']['account_number']
    ms_sequence = ms_details['value']['sequence']

    tx = cli.generate_send_tx(ms, recipient, 1000000)
    with temp_file(tx) as tx_path:
        signature1 = cli.create_multisig_signature(tx_path, signer1, ms, ms_account_num, ms_sequence)
        signature2 = cli.create_multisig_signature(tx_path, signer2, ms, ms_account_num, ms_sequence)
        with temp_files([signature1, signature2], None) as signature_paths:
            ms_tx = cli.create_multisig_tx(tx_path, 'kms2', ms_account_num, ms_sequence, signature_paths)

    with temp_file(ms_tx) as tx_path:
        tx_hash = cli.broadcast_tx(tx_path)
        print(tx_hash)

    # tx = cli.query_tx('D6D758496B2C5C11CD580D98AD8D03F511F51B7074B793A9EC8AFCF11AD670F9')
    # pprint(tx)

    # print(cli.get_account_details('secret1et6rzussnvwkvy4dentr4x7mv936y2s099us2d'))
    # print(cli.get_balance_of('secret1et6rzussnvwkvy4dentr4x7mv936y2s099us2d'))

    # tx = cli.generate_send_tx(
    #     'cosmos1ag66c0pkzyzz9gkhz7wdmgq5s75x9rr5hksgmc',
    #     'cosmos1et6rzussnvwkvy4dentr4x7mv936y2s08qgeh3',
    #     1000000,
    # )
    # print(f'the tx is: {tx!r}')

    # txs = cli.query_txs_to('secret1et6rzussnvwkvy4dentr4x7mv936y2s099us2d')
    #
    # events = txs[0]['events']
    # event = next(filter(lambda event: event['type'] == 'transfer', events))
    # attributes = event['attributes']
    # attribute = next(filter(lambda attribute: attribute['key'] == 'recipient', attributes))
    # recipient = attribute['value']
    #
    # print(repr(recipient))
    #
    # txs = cli.query_txs_from('secret1ag66c0pkzyzz9gkhz7wdmgq5s75x9rr54nypxy')
    # pprint(txs[0]['events'])

    # # Collect txs from oldest to newest
    # txs = cli.query_txs_from('secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm', 1)
    # txs += cli.query_txs_from('secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm', 2)
    # txs += cli.query_txs_from('secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm', 3)
    # # Internal error: page should be within
    # # txs += cli.query_txs_from('secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm', 4)
    # pprint([tx['txhash'] for tx in txs])


# If run with `python -m src.cosmos_hub.gaia`
if __name__ == '__main__':
    _main()
