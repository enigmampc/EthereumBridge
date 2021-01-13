from functools import reduce
from threading import Thread
from typing import List, Optional, Awaitable

import tornado.ioloop
import tornado.web


class MainHandler(tornado.web.RequestHandler):
    def initialize(self, threads):
        self.threads = threads

    def data_received(self, chunk: bytes) -> Optional[Awaitable[None]]:
        pass

    def get(self):
        health = reduce(lambda x, y: x and y, map(lambda t: t.running(), self.threads))

        if health:
            self.write("Hello, world")
        else:
            self.write("Goodbye, world")


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
