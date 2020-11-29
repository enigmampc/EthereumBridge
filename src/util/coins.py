from enum import Enum, auto


class Currency(Enum):
    USD = auto()


# TODO these types should probably be moved to the oracle module
class Coin(Enum):
    # todo: Determine what we want to start with
    Secret = auto()
    Ethereum = auto()
    Tether = auto()
    Dai = auto()
    Zrx = auto()
    Compound = auto()


# TODO move this to the db?
erc20_db = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": {
        "symbol": "USDT",
        "decimal": 6,
        "coin": Coin.Tether
    },
    "0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359": {
        "symbol": "DAI",
        "decimal": 18,
        "coin": Coin.Dai
    }
}


class Erc20Info:
    @staticmethod
    def decimals(token: str) -> int:
        return erc20_db[token]["decimal"]

    @staticmethod
    def coin(token: str) -> Coin:
        return erc20_db[token]["coin"]
