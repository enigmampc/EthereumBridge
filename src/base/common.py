from dataclasses import dataclass
from enum import Enum
import enum


NATIVE_COIN_ADDRESS = "native"


# Supported networks are networks that have full support.
# Coins deployed on the networks will be named by a string.
# The native coin must be named appropriately, by its main denomination ('ETH', 'BTC', etc.)
class Network(Enum):
    Ethereum = "Ethereum"
    CosmosHub = "CosmosHub"
    Terra = "Terra"


class SwapDirection(Enum):
    ToSecretNetwork = enum.auto()
    FromSecretNetwork = enum.auto()


@dataclass
class SwapEvent:
    # routing
    id: str  # arbitrary ID determined by the underlying implementation
    nonce: str
    dst_coin_name: str
    dst_coin_address: str
    src_coin_address: str
    direction: SwapDirection
    # details
    amount: int  # in smallest denomination (e.g. wei)
    sender: str  # address in source network
    recipient: str  # address in destination network
    data: str = ""
