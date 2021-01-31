from collections import UserDict
from dataclasses import dataclass
from enum import Enum, auto

from src.db.collections.token_map import TokenPairing


class Currency(Enum):
    USD = auto()


@dataclass
class Coin:
    symbol: str
    decimals: int
    name: str
    erc20_address: str
    scrt_address: str

    @classmethod
    def from_db(cls, src: TokenPairing):
        return Coin(symbol=src.display_props.get('symbol', '').upper(),
                    decimals=src.decimals,
                    name=src.name,
                    erc20_address=src.src_address,
                    scrt_address=src.dst_address)


# class Erc20Info:
#     @staticmethod
#     def decimals(token: str) -> int:
#         return erc20_db[token]["decimal"]
#
#     @staticmethod
#     def coin(token: str) -> Coin:
#         return erc20_db[token]["coin"]


class CoinHandler(UserDict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for coin in TokenPairing.objects():
            self.update(
                {self._key(coin): Coin.from_db(coin)}
            )

    @staticmethod
    def _key(coin: TokenPairing):
        return coin.src_address.lower()

    def decimals(self, token: str):
        return self[token.lower()].decimals

    def coin(self, token: str) -> str:
        return self[token.lower()].symbol

    def scrt_address(self, token: str):
        return self[token.lower()].scrt_address

    def __getattr__(self, item):
        _key = item.lower()
        return self[_key]

    def __getitem__(self, key: str):
        _key = key.lower()
        if _key not in self:
            for coin in TokenPairing.objects():
                if self._key(coin) not in self:
                    self.update(
                        {self._key(coin): Coin.from_db(coin)}
                    )
            if _key in self:
                return self.data[_key]
            raise KeyError(f"Coin not found for key: {key}")
        return self.data[_key]
