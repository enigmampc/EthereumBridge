from src.util.oracle.gas_source_base import GasSourceBase


class ZoltuGasOracle(GasSourceBase):
    API_URL = "https://gas-oracle.zoltu.io/"

    async def gas_price(self) -> int:
        resp = await self._base_request()
        # To convert the provided values to gwei, divide by 10
        # https://docs.ethgasstation.info/gas-price
        value = float(resp["percentile_90"].split(' ')[0])
        return int(value)
