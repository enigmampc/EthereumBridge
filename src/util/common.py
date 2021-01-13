import sys
from collections import namedtuple
from contextlib import contextmanager
from dataclasses import dataclass
from os import remove
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import List, Generator

import src


# TODO why do we set `delete=False` here??
@contextmanager
def temp_file(data: str):
    f = NamedTemporaryFile(mode="w+", delete=False)
    f.write(data)
    f.close()
    yield f.name
    remove(f.name)


@contextmanager
def temp_files(data: List[str], logger) -> Generator:
    temp = [temp_file(d) for d in data]

    yield [manager.__enter__() for manager in temp]
    for manager in temp:
        try:
            manager.__exit__(*sys.exc_info())
        except OSError as e:
            logger.debug(e)


# noinspection PyTypeChecker
def project_base_path():
    res = module_dir(src)
    return Path(res).parent


def module_dir(module) -> Path:
    return Path(module.__file__).parent


@dataclass
class Token:
    """Name and address of a native token, on some network"""
    address: str = None
    name: str = None
    decimals: int = 0


SecretAccount = namedtuple('SecretAccount', ['address', 'name'])


def bytes_from_hex(s: str):
    if s[:2] == '0x':
        return bytes.fromhex(s[2:])
    return bytes.fromhex(s)
