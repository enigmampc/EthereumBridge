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
    Uniswap = 'UNI'
    YearnFinance = 'YFI'
    TrueUSD = 'TUSD'
    Ocean = 'OCEAN'
    Link = 'LINK'
    Maker = 'MKR'
    Synthetix = 'SNX'
    Aave = 'AAVE'
    Band = 'BAND'
    Kyber = 'KNC'
