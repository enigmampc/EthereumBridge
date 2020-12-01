import json

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.oracle.coins import Currency, Coin
from src.util.oracle.price_source_base import PriceSourceBase


class CoinGecko(PriceSourceBase):

    API_URL = "https://api.coingecko.com/api/v3/simple/"

    coin_map = {
        Coin.Secret: "secret",
        Coin.Ethereum: "ethereum",
        Coin.Tether: "usdt",
    }

    currency_map = {Currency.USD: "usd"}

    def _base_url(self):
        return f'{self.API_URL}price'

    @staticmethod
    def _price_params(coin: str, currency: str):
        return {'ids': coin, 'vs_currencies': currency}

    async def _price_request(self, coin: str, currency: str) -> dict:

        url = self._base_url()
        # this opens a new connection each time. It's possible to restructure with sessions, but then the session needs
        # to live inside an async context, and I don't think it's necessary right now
        async with aiohttp.ClientSession().get(url, params=self._price_params(coin, currency), raise_for_status=True) as resp:
            return await resp.json()

    async def price(self, coin: Coin, currency: Currency) -> float:
        try:
            coin_str = self._coin_to_str(coin)
            currency_str = self._currency_to_str(currency)
        except IndexError as e:
            # log not found
            raise ValueError from e

        try:
            result = await self._price_request(coin_str, currency_str)
            return result[coin_str][currency_str]
        except (ConnectionError, ClientConnectionError, HTTPError, json.JSONDecodeError):
            pass
