from enum import Enum, auto


class Currency(Enum):
    USD = auto()


class Coin(Enum):
    # todo: Determine what we want to start with
    Secret = auto()
    Ethereum = auto()
    Tether = auto()
    Dai = auto()
    Zrx = auto()
    Compound = auto()
    Uniswap = auto()
    YearnFinance = auto()
    TrueUSD = auto()
    Ocean = auto()
    Link = auto()
    Maker = auto()
    Synthetix = auto()
    Aave = auto()
    Band = auto()
    Kyber = auto()
    WrappedBTC = auto()
    BAC = auto()


erc20_db = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": {
        "symbol": "USDT",
        "decimal": 6,
        "coin": Coin.Tether
    },
    "0x6b175474e89094c44da98b954eedeac495271d0f": {
        "symbol": "DAI",
        "decimal": 18,
        "coin": Coin.Dai
    },
    "0xc00e94cb662c3520282e6f5717214004a7f26888": {
        "symbol": "COMP",
        "decimal": 18,
        "coin": Coin.Compound
    },
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {
        "symbol": "UNI",
        "decimal": 18,
        "coin": Coin.Uniswap
    },
    "0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e": {
        "symbol": "YFI",
        "decimal": 18,
        "coin": Coin.YearnFinance
    },
    "0x0000000000085d4780B73119b644AE5ecd22b376": {
        "symbol": "TUSD",
        "decimal": 18,
        "coin": Coin.TrueUSD
    },
    "0x967da4048cD07aB37855c090aAF366e4ce1b9F48": {
        "symbol": "OCEAN",
        "decimal": 18,
        "coin": Coin.Ocean
    },
    "0x514910771af9ca656af840dff83e8264ecf986ca": {
        "symbol": "LINK",
        "decimal": 18,
        "coin": Coin.Link
    },
    "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2": {
        "symbol": "MKR",
        "decimal": 18,
        "coin": Coin.Maker
    },
    "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f": {
        "symbol": "SNX",
        "decimal": 18,
        "coin": Coin.Synthetix
    },
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": {
        "symbol": "AAVE",
        "decimal": 18,
        "coin": Coin.Aave
    },
    "0xba11d00c5f74255f56a5e366f4f77f5a186d7f55": {
        "symbol": "BAND",
        "decimal": 18,
        "coin": Coin.Band
    },
    "0xdd974d5c2e2928dea5f71b9825b8b646686bd200": {
        "symbol": "KNC",
        "decimal": 18,
        "coin": Coin.Kyber
    },
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": {
        "symbol": "WBTC",
        "decimal": 8,
        "coin": Coin.WrappedBTC
    },
    "0x3449fc1cd036255ba1eb19d65ff4ba2b8903a69a": {
        "symbol": "BAC",
        "decimal": 18,
        "coin": Coin.BAC
    }
}


class Erc20Info:
    @staticmethod
    def decimals(token: str) -> int:
        return erc20_db[token]["decimal"]

    @staticmethod
    def coin(token: str) -> Coin:
        return erc20_db[token]["coin"]
