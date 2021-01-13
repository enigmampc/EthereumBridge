from src.util.oracle.gas_source_base import GasSourceBase


class POAGasOracle(GasSourceBase):
    API_URL = "https://gasprice.poa.network/"

    async def gas_price(self) -> int:
        resp = await self._base_request()
        # To convert the provided values to gwei, divide by 10
        # https://docs.ethgasstation.info/gas-price
        gas_price = resp["fast"]
        return int(gas_price)
