import os

import rlp
from eth_utils import to_checksum_address

from src.util.crypto_store.pkcs11_crypto_store import Pkcs11CryptoStore


# test only works if you have a pkcs11 signer installed
from src.util.eth.transaction import Transaction
from src.util.web3 import w3

zero_address = '0x000000000000000000000000000000000000dEaD'


def test_pkcs11_sign():
    # os.environ.update({"pkcs11_module": "/usr/local/lib/softhsm/libsofthsm2.so"})
    # if we don't have a pkcs11 module just return, to not break tests for now
    if not os.environ.get("pkcs11_module", ''):
        return

    bal = w3.eth.getBalance(to_checksum_address(zero_address))

    signer = Pkcs11CryptoStore(store=os.getenv("pkcs11_module"), token="token", user_pin="1234", label="bobob")

    label = signer.generate()
    print(f"{label=}, {signer.address=}")

    w3.eth.sendTransaction({
        'from': w3.eth.coinbase,
        'to': to_checksum_address(signer.address),
        'value': int(1e16)  # 0.01eth
    })

    tx = Transaction(nonce=0, gasprice=w3.eth.gasPrice, startgas=21000, to=zero_address, value=100,
                     sender=signer.address, network=w3.eth.chainId, data=b'')

    tx_signed = tx.sign(signer, w3.eth.chainId)
    print(f"{signer.address=}, {tx_signed.sender.hex()}")
    w3.eth.sendRawTransaction(rlp.encode(tx_signed))

    assert w3.eth.getBalance(to_checksum_address(zero_address)) == bal + 100
