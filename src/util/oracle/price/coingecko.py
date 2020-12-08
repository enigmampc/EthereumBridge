import json

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.coins import Currency, Coin
from src.util.oracle.price_source_base import PriceSourceBase


class CoinGecko(PriceSourceBase):

    API_URL = "https://api.coingecko.com/api/v3/simple/"

    coin_map = {Coin.Secret: "secret",
                Coin.Ethereum: "ethereum",
                Coin.Tether: "0xdac17f958d2ee523a2206206994597c13d831ec7",
                }

    currency_map = {Currency.USD: "usd"}

    def _base_url(self):
        return f'{self.API_URL}price'

    def _base_token_url(self):
        return f'{self.API_URL}token_price/ethereum'

    @staticmethod
    def _price_params(coin: str, currency: str):
        """ The API is slightly different for native coins vs tokens """
        return {'ids': coin, 'vs_currencies': currency}

    @staticmethod
    def _token_price_params(coin: str, currency: str):
        """ The API is slightly different for native coins vs tokens """
        return {'contract_addresses': coin, 'vs_currencies': currency}

    async def _price_request(self, coin: str, currency: str) -> dict:

        if coin in [self.coin_map[Coin.Ethereum], self.coin_map[Coin.Secret]]:
            url = self._base_url()
            params = self._price_params(coin, currency)
        else:
            url = self._base_token_url()
            params = self._token_price_params(coin, currency)

        # this opens a new connection each time. It's possible to restructure with sessions, but then the session needs
        # to live inside an async context, and I don't think it's necessary right now
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url, params=params, raise_for_status=True)
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
