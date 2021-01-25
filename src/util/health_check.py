from collections import ChainMap
from functools import reduce
from threading import Thread
from typing import List, Optional, Awaitable

import tornado.ioloop
import tornado.web
import tornado.options

from src.leader.eth.leader import EtherLeader
from src.leader.secret20 import Secret20Leader
from src.signer.eth.signer import EtherSigner
from src.signer.secret20 import Secret20Signer

from src.util.web3 import w3


class MainHandler(tornado.web.RequestHandler):
    def initialize(self, threads):
        self.threads: List[EtherSigner, Secret20Signer, Optional[EtherLeader], Optional[Secret20Leader]] = threads

    def data_received(self, chunk: bytes) -> Optional[Awaitable[None]]:
        pass

    def get(self):
        health = dict(ChainMap(*list(map(lambda t: {t.getName(): {True: "pass", False: "fail"}[t.running()]}, self.threads))))

        overall = reduce(lambda x, y: x and y, map(lambda v: v[1] == "pass", health.items()))

        health.update({"overall": {True: "pass", False: "fail"}[overall]})

        try:
            config = self.threads[0].config
            balance = w3.eth.getBalance(config.eth_address, "latest")
            health.update({"eth-balance": balance})
        except Exception as e:
            health.update({"eth-balance": "failed to update"})

        if health:
            self.finish(health)


def make_app(threads):

    for t in threads:
        t.start()

    return tornado.web.Application([
        (r"/health", MainHandler, dict(threads=threads)),
    ])


def run(threads: List[Thread]):

    app = make_app(threads)
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
