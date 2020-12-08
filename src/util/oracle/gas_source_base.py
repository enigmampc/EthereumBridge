import aiohttp


class GasSourceBase:
    API_URL = ""

    def _base_url(self):
        return self.API_URL

    async def _base_request(self) -> dict:
        url = self._base_url()
        # this opens a new connection each time. It's possible to restructure with sessions, but then the session needs
        # to live inside an async context, and I don't think it's necessary right now
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url, raise_for_status=True)
            return await resp.json()

    async def gas_price(self) -> int:
        raise NotImplementedError
