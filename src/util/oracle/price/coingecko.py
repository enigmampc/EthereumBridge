import json
from typing import List

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.coins import Currency
from src.util.oracle.price_source_base import PriceSourceBase


class CoinGecko(PriceSourceBase):

    API_URL = "https://api.coingecko.com/api/v3/simple/"

    coin_map = {
        "BTC": "bitcoin",
        "SCRT": "secret",
        "SSCRT": "secret-erc20",
        "ETH": "ethereum",
        "OCEAN": "ocean-protocol",
        "USDT": "tether",
        "YFI": "yearn-finance",
        "LINK": "chainlink",
        "DAI": "dai",
        "WBTC": "wrapped-bitcoin",
        "UNI": "uniswap",
        "AAVE": "aave",
        "COMP": "compound-governance-token",
        "SNX": "havven",
        "TUSD": "true-usd",
        "BAND": "band-protocol",
        "BAC": "basis-cash",
        "MKR": "maker",
        "KNC": "kyber-network",
        "DPI": "defipulse-index",
        "RSR": "reserve-rights-token",
        "REN": "republic-protocol",
        "RENBTC": "renbtc",
        "USDC": "usd-coin",
        "SUSHI": "sushi",
    }

    currency_map = {Currency.USD: "usd"}

    def __init__(self, api_base_url=None):
        self._raw_coin_list: List[object] = []
        with open('src/util/oracle/price/coingecko.json') as f:
            self._raw_coin_list = json.load(f)

        super().__init__(api_base_url)

    def _base_url(self):
        return f'{self.API_URL}price'

    def _find_symbol(self, symbol: str):
        for coin in self._raw_coin_list:
            if coin['symbol'] == symbol.lower():
                self.coin_map.update({coin['symbol'].upper(): coin['id']})  # pylint: disable=no-member
                return coin['id']
        raise KeyError(f"Cannot find id for {symbol=}")

    @staticmethod
    def _price_params(coin: str, currency: str):
        """ The API is slightly different for native coins vs tokens """
        return {'ids': coin, 'vs_currencies': currency}

    @staticmethod
    def _token_price_params(coin: str, currency: str):
        """ The API is slightly different for native coins vs tokens """
        return {'contract_addresses': coin, 'vs_currencies': currency}

    async def _price_request(self, coin: str, currency: str) -> dict:
        url = self._base_url()
        params = self._price_params(coin, currency)

        # this opens a new connection each time. It's possible to restructure with sessions, but then the session needs
        # to live inside an async context, and I don't think it's necessary right now
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url, params=params, raise_for_status=True)
            return await resp.json()

    async def price(self, coin: str, currency: Currency) -> float:
        try:
            currency_str = self._currency_to_str(currency)
            coin_str = self._coin_to_str(coin)
        except IndexError as e:
            raise ValueError from e
        except KeyError:
            try:
                currency_str = self._currency_to_str(currency)
                coin_str = self._find_symbol(coin)
            except KeyError as e:
                raise ValueError from e

        try:
            result = await self._price_request(coin_str, currency_str)
            return result[coin_str][currency_str]
        except (ConnectionError, ClientConnectionError, HTTPError, json.JSONDecodeError):
            pass
