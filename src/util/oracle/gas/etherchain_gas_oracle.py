from src.util.oracle.gas_source_base import GasSourceBase


class EtherchainGasOracle(GasSourceBase):
    API_URL = "https://www.etherchain.org/api/gasPriceOracle"

    # pylint: disable=duplicate-code
    async def gas_price(self) -> int:
        resp = await self._base_request()
        # To convert the provided values to gwei, divide by 10
        # https://docs.ethgasstation.info/gas-price
        value = resp["fastest"]
        return int(value)
