import sys
from collections import namedtuple
from contextlib import contextmanager
from dataclasses import dataclass
from os import remove
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import List, Generator

import src

swap_retry_address = '0x00000000000000000000000000000000deadbeef'


@contextmanager
def temp_file(data: str):
    f = NamedTemporaryFile(mode="w+", delete=False)
    f.write(data)
    f.close()
    yield f.name
    remove(f.name)


# todo: I don't think this actually works
@contextmanager
def temp_files(data: List[str], logger) -> Generator:
    temp = []
    for d in data:
        temp.append(temp_file(d))

    yield list(manager.__enter__() for manager in temp)
    for manager in temp:
        try:
            manager.__exit__(*sys.exc_info())
        except OSError as e:
            logger.debug(msg=e)


# noinspection PyTypeChecker
def project_base_path():
    res = module_dir(src)
    return Path(res).parent


def module_dir(module) -> Path:
    return Path(module.__file__).parent


# Token = namedtuple('Token', ['address', 'name', 'code_hash'], defaults=(None,) * 3)
@dataclass
class Token:
    address: str = None
    name: str = None
    code_hash: str = None
    token_contract: str = None


SecretAccount = namedtuple('SecretAccount', ['address', 'name'])


def bytes_from_hex(s: str):
    if s[0:1] == '0x':
        return bytes.fromhex(s[2:])
    return bytes.fromhex(s)
