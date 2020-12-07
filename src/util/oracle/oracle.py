import asyncio
from typing import List

from src.util.oracle.gas.etherchain_gas_oracle import EtherchainGasOracle
from src.util.oracle.gas.ethgasstation import EthGasStation
from src.util.oracle.gas.poa_gas_oracle import POAGasOracle
from src.util.oracle.gas.zoltu_gas_oracle import ZoltuGasOracle
from src.util.oracle.price.coingecko import CoinGecko
from .gas_source_base import GasSourceBase
from .price.compound_price import CompoundPriceOracle
from .price_source_base import PriceSourceBase
from ..coins import Currency, Coin


class Oracle:
    price_sources: List[PriceSourceBase] = [CoinGecko(), CompoundPriceOracle()]
    gas_sources: List[GasSourceBase] = [EtherchainGasOracle(), EthGasStation(), ZoltuGasOracle(), POAGasOracle()]

    @staticmethod
    async def _get_price_from_source(source: PriceSourceBase, coin: Coin, currency: Currency) -> float:
        return await source.price(coin, currency)

    @staticmethod
    async def _get_gas_price_from_source(source: GasSourceBase) -> int:
        return await source.gas_price()

    async def _price(self, coin: Coin, currency: Currency) -> float:
        prices = await asyncio.gather(*(self._get_price_from_source(source, coin, currency)
                                        for source in self.price_sources if coin in source.supported_tokens()))

        average = sum(prices) / len(prices)
        return average

    async def _gas_price(self) -> int:
        prices = await asyncio.gather(*(self._get_gas_price_from_source(source) for source in self.gas_sources))

        average = sum(prices) / len(prices)
        return int(average)

    def price(self, coin: Coin, currency: Currency) -> float:
        # aiohttp displays an error on windows, but we can ignore it, or switch to
        # asyncio.get_event_loop().run_until_complete(
        # https://github.com/aio-libs/aiohttp/issues/4324
        task = asyncio.run(self._price(coin, currency))
        return task

    def gas_price(self) -> int:
        # aiohttp displays an error on windows, but we can ignore it, or switch to
        # asyncio.get_event_loop().run_until_complete(
        # https://github.com/aio-libs/aiohttp/issues/4324
        task = asyncio.run(self._gas_price())
        return task

    def x_rate(self, coin_primary: Coin, coin_secondary: Coin) -> float:
        try:
            return self.price(coin_primary, Currency.USD) / self.price(coin_secondary, Currency.USD)
        except ZeroDivisionError:
            raise ValueError("Cannot get price for secondary") from None

    @staticmethod
    def calculate_fee(gas: int, gas_price: int, token_decimals: int, xrate: float, amount_sent: int) -> int:

        # flat fee:
        #              Gwei         -> ETH -> Token -> Token Decimals
        flat_fee = (float(gas_price) / 1e9) / xrate * pow(10, token_decimals) * gas

        # variable fee tbd
        _ = amount_sent

        return int(flat_fee)


BridgeOracle = Oracle()
