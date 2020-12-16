from typing import Dict

from src.util.oracle.coins import Coin, Currency


class PriceSourceBase:

    API_URL = ""

    coin_map: Dict[Coin, str]
    currency_map: Dict[Currency, str]

    def __init__(self, api_base_url=API_URL):
        self.api_url = api_base_url

    def _base_url(self):
        return self.API_URL

    async def price(self, coin: Coin, currency: Currency) -> float:
        raise NotImplementedError

    def supported_tokens(self):
        return self.coin_map.keys()

    def _coin_to_str(self, coin: Coin) -> str:
        return self.coin_map[coin]

    def _currency_to_str(self, currency: Currency) -> str:
        return self.currency_map[currency]
