import json
import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.coins import Coin, Currency
from src.util.oracle.price_source_base import PriceSourceBase


class CompoundPriceOracle(PriceSourceBase):

    API_URL = "https://prices.compound.finance/"

    coin_map = {Coin.Zrx: "ZRX",
                Coin.Compound: "COMP",
                Coin.Ethereum: "ETH",
                Coin.Dai: "DAI"}

    currency_map = {Currency.USD: "usd"}

    async def price(self, coin: Coin, currency: Currency) -> float:
        url = self._base_url()
        try:
            coin_str = self._coin_to_str(coin)
            if currency != Currency.USD:
                raise IndexError
        except IndexError as e:
            # log not found
            raise ValueError(f"Coin or currently not supported: {e}") from IndexError

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(url, raise_for_status=True)
                resp_json = await resp.json()
                cbase_price = resp_json["coinbase"]["prices"][coin_str]
                okex_price = resp_json["okex"]["prices"][coin_str]

                return (float(cbase_price) + float(okex_price)) / 2
        except (ConnectionError, ClientConnectionError, HTTPError, json.JSONDecodeError):
            pass
