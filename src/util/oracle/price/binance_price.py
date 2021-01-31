import json

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.coins import Currency
from src.util.oracle.price_source_base import PriceSourceBase


class BinancePriceOracle(PriceSourceBase):

    API_URL = "https://api.binance.com/api/v3/ticker/price"

    coin_map = {
        # Coin.Dai: "DAI",
        # Coin.Compound: "COMP",
        # Coin.Uniswap: "UNI",
        # Coin.YearnFinance: "YFI",
        # Coin.TrueUSD: "TUSD",
        # Coin.Ocean: "OCEAN",
        # Coin.Link: "LINK",
        # Coin.Maker: "MKR",
        # Coin.Synthetix: "SNX",
        # Coin.Aave: "AAVE",
        # Coin.Kyber: "KNC",
        # Coin.RENBTC: "BTC",  # just use BTC for this, should be fine
        # Coin.REN: "REN",
        # Coin.ReserveRights: "RSR",
        # Coin.Sushi: "SUSHI",
        # Coin.USDC: "USDC"
    }

    currency_map = {Currency.USD: "USDT"}

    async def price(self, coin: str, currency: Currency) -> float:
        url = self._base_url()
        if currency != Currency.USD:
            raise IndexError

        if coin.upper() == 'USDT':
            return 1.0

        # except IndexError as e:
        #     # log not found
        #     if coin == Coin.Tether and currency == Currency.USD:
        #         return 1.0  # I mean, if USDT crashes we'll have some bigger problems to solve:)
        #
        #     raise ValueError(f"Coin or currently not supported: {e}") from IndexError

        # Just query the pair with Tether.. it's close enough

        params = {'symbol': f'{coin.upper()}USDT'}

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(url, params=params, raise_for_status=True)
                resp_json = await resp.json()
                price = float(resp_json['price'])
                return price

        except (ConnectionError, ClientConnectionError, HTTPError, json.JSONDecodeError, ValueError):
            return 0.0
