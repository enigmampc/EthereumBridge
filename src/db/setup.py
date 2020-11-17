from contextlib import contextmanager

import mongoengine


@contextmanager
def database(uri):
    # alias = f"{db}-{host}-{username}"

    yield mongoengine.connect(
        host=uri
    )

    mongoengine.disconnect()


def connect_default():
    mongoengine.connect(db="tempdb")
