import json
import subprocess
from typing import List, Dict


class CliError(Exception):
    def __init__(self, inner: subprocess.CalledProcessError = None):
        args = (inner.stderr,) if inner is not None else ()
        super().__init__(*args)
        self.inner = inner


class NotFoundError(CliError):
    pass


class TxNotFoundError(NotFoundError):
    def __init__(self, tx_hash):
        super().__init__()
        self.tx_hash = tx_hash

    def __str__(self):
        return self.tx_hash


class GaiaCli:
    def __init__(self, cli_name='gaiacli', denom='uatom'):
        self.cli_name = cli_name
        self.denom = denom

    def _run(self, command: List[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.cli_name, *command], capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError as e:
            raise CliError(e)

    def _json_run(self, *args, **kwargs):
        process = self._run(*args, **kwargs)
        return json.loads(process.stdout)

    def configure(self, chain_id: str, node: str):
        self._run(['config', 'chain-id', chain_id])
        self._run(['config', 'node', node])
        self._run(['config', 'trust-node', 'true'])
        self._run(['config', 'output', 'json'])
        self._run(['config', 'indent', 'false'])

    def query_tx(self, tx_hash) -> Dict:
        return self._json_run(['query', 'tx', tx_hash])

    def _query_txs_raw(self, events: str, page: int = None) -> Dict:
        command = ['query', 'txs', '--events', events]
        if page is not None:
            command += ['--page', str(page)]
        return self._json_run(command)

    def query_txs(self, events: str, page: int = None) -> List[Dict]:
        return self._query_txs_raw(events, page)['txs']

    def query_txs_until(self, events: str, until_tx: str) -> List[Dict]:
        page = 1
        limit = 0
        prev_total_count = 0
        all_txs = []
        target_found = False

        while not target_found:
            try:
                response = self._query_txs_raw(events, page)
            except CliError as e:
                if 'page should be within' in e.inner.stderr:
                    raise TxNotFoundError(until_tx)
                raise

            txs = response['txs']
            if len(txs) == 0:
                raise TxNotFoundError(until_tx)

            total_count = int(response['total_count'])
            if prev_total_count == 0:
                prev_total_count = total_count
            if limit == 0:
                limit = int(response['limit'])

            # If there were a lot of new txs, try to jump to the txs after the previous ones we observed
            new_tx_count = total_count - prev_total_count
            if limit <= new_tx_count:  # If more than a whole page has been added
                page += new_tx_count // limit
                prev_total_count = total_count
                continue

            # If the target transaction is in this batch, remove the ones after it
            tx_hashes = [tx['txhash'] for tx in txs]
            target_index = len(txs)
            try:
                target_index = tx_hashes.index(until_tx)
                target_found = True
            except ValueError:
                pass

            # Skip txs that we already observed
            if new_tx_count != 0 or target_index != len(txs):
                txs = txs[new_tx_count:target_index+1]

            all_txs += txs
            prev_total_count = total_count
            page += 1

        return all_txs

    def query_txs_from(self, sender: str) -> List[Dict]:
        return self.query_txs(f'message.action=send&message.sender={sender}')

    def query_txs_to(self, recipient: str) -> List[Dict]:
        return self.query_txs(f'transfer.recipient={recipient}')

    def query_txs_from_until(self, sender: str, until_tx: str = None) -> List[Dict]:
        return self.query_txs_until(f'message.action=send&message.sender={sender}', until_tx)

    def query_txs_to_until(self, recipient: str, until_tx: str = None) -> List[Dict]:
        return self.query_txs_until(f'transfer.recipient={recipient}', until_tx)

    def generate_send_tx(self, sender: str, recipient: str, amount: int) -> str:
        process = self._run(['tx', 'send', sender, recipient, f'{amount}{self.denom}', '--generate-only'])
        return process.stdout.strip()

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

    def broadcast_tx(self, signed_tx_path: str):
        # async broadcast mode allows sending more than 1 tx per block
        return self._json_run(['tx', 'broadcast', signed_tx_path, '--broadcast-mode', 'async'])


def _main():
    pass
    # from pprint import pprint
    #
    # from src.util.common import temp_file, temp_files
    #
    # cli = GaiaCli('secretcli', 'uscrt')

    # # Create, sign, and send multisig tx:
    # signer1 = 'secret12q5e0ppulztmd03kyhmpxtutxga6guujh5tzry'
    # signer2 = 'secret1q9l6rs89kf820re4jccklgvnfqnst5qc4stc0f'
    # ms = 'secret1j8rt5jwjlsc5hcgnwv5hqfe46e3ma6xjd8fvhm'
    # recipient = 'secret1xp0peuxa9mjnf9pplmxkxfgy9ks8nvavds78z0'
    #
    # ms_details = cli.get_account_details(ms)
    # ms_account_num = ms_details['value']['account_number']
    # ms_sequence = ms_details['value']['sequence']
    #
    # tx = cli.generate_send_tx(ms, recipient, 1000000)
    # with temp_file(tx) as tx_path:
    #     signature1 = cli.create_multisig_signature(tx_path, signer1, ms, ms_account_num, ms_sequence)
    #     signature2 = cli.create_multisig_signature(tx_path, signer2, ms, ms_account_num, ms_sequence)
    #     with temp_files([signature1, signature2], None) as signature_paths:
    #         ms_tx = cli.create_multisig_tx(tx_path, 'kms2', ms_account_num, ms_sequence, signature_paths)
    #
    # with temp_file(ms_tx) as tx_path:
    #     cli.broadcast_tx(tx_path)

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

    # txs = cli.query_txs_to_until(
    #     'secret1et6rzussnvwkvy4dentr4x7mv936y2s099us2d',
    #     # 'D6D758496B2C5C11CD580D98AD8D03F511F51B7074B793A9EC8AFCF11AD670F9',
    #     '8632E427EBAC694F0B352D532161D430AD92FC09FE6C6E183167862039D679E7',
    # )
    # pprint([tx['txhash'] for tx in txs])


# If run with `python -m src.cosmos_hub.gaia`
if __name__ == '__main__':
    _main()
