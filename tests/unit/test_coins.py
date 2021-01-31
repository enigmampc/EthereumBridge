from src.util.coins import CoinHandler
from src.db import database


def test_coins():
    import os
    uri = os.environ.get("db_uri")
    with database(uri):
        coins = CoinHandler()
        print(f'coins in handler: {list(coins.keys())}')
        for addr in ['0xb7792dfef59e58219a63fd3d328220cc8a5bc420', '0xB7792dfeF59E58219A63fD3D328220cc8A5Bc420', 'bob']:
            print(f'Getting coin for address: {addr}')
            try:
                c = coins[addr]
                print(f'{c.scrt_address=}, {c.symbol=}, {c.decimals=}')
            except KeyError:
                assert(addr == 'bob')
