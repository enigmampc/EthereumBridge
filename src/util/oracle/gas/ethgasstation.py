import aiohttp

from src.util.oracle.gas_source_base import GasSourceBase
from src.util.config import config


class EthGasStation(GasSourceBase):
    API_URL = "https://ethgasstation.info/api/ethgasAPI.json"

    @staticmethod
    def _api_key():
        return {'api-key': config.ethgastation_api_key}

    def _params(self):
        return self._api_key()

    async def gas_price(self) -> int:
        url = self._base_url()
        # this opens a new connection each time. It's possible to restructure with sessions, but then the session needs
        # to live inside an async context, and I don't think it's necessary right now
        async with aiohttp.ClientSession().get(url, params=self._params(), raise_for_status=True) as resp:
            resp = await resp.json()
            # To convert the provided values to gwei, divide by 10
            # https://docs.ethgasstation.info/gas-price
            return int(resp['average'] / 10)
