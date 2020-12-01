from enum import Enum, auto


class Currency(Enum):
    USD = auto()


class Coin(Enum):
    Secret = 'SCRT'
    Ethereum = 'ETH'
    Tether = 'USDT'
    Dai = 'DAI'
    Zrx = 'ZRX'
    Compound = 'COMP'
