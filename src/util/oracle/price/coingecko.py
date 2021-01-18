import json

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web_exceptions import HTTPError

from src.util.coins import Currency, Coin
from src.util.oracle.price_source_base import PriceSourceBase


class CoinGecko(PriceSourceBase):

    API_URL = "https://api.coingecko.com/api/v3/simple/"

    coin_map = {
        Coin.Secret: "secret",
        Coin.Ethereum: "ethereum",
        Coin.Tether: "0xdac17f958d2ee523a2206206994597c13d831ec7",
        Coin.Dai: "0x6b175474e89094c44da98b954eedeac495271d0f",
        Coin.Compound: "0xc00e94cb662c3520282e6f5717214004a7f26888",
        Coin.Uniswap: "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
        Coin.YearnFinance: "0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e",
        Coin.TrueUSD: "0x0000000000085d4780B73119b644AE5ecd22b376",
        Coin.Ocean: "0x967da4048cD07aB37855c090aAF366e4ce1b9F48",
        Coin.Link: "0x514910771af9ca656af840dff83e8264ecf986ca",
        Coin.Maker: "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2",
        Coin.Synthetix: "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f",
        Coin.Aave: "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9",
        Coin.Kyber: "0xdd974d5c2e2928dea5f71b9825b8b646686bd200",
        Coin.BAC: "0x3449fc1cd036255ba1eb19d65ff4ba2b8903a69a",
        Coin.WrappedBTC: "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
        Coin.ReserveRights: "0x8762db106b2c2a0bccb3a80d1ed41273552616e8",
        Coin.Sushi: "0x6b3595068778dd592e39a122f4f5a5cf09c90fe2",
        Coin.RENBTC: "0xeb4c2781e4eba804ce9a9803c67d0893436bb27d",
        Coin.USDC: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        Coin.REN: "0x408e41876cccdc0f92210600ef50372656052a38",
        Coin.DefiPulseIndex: "0x1494ca1f11d487c2bbe4543e90080aeba4ba3c2b"
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
