from time import sleep

from db.collections.eth_swap import ETHSwap, Status
from db.collections.signatures import Signatures


def test_catch_up(signer, offline_data):
    for swap in offline_data:
        assert Signatures.objects(tx_id=swap.id, signed_tx=signer.enc_key).count() == 1


def test_db_notifications(signer):
    # Check notification processed
    d = ETHSwap(tx_hash="test hash", status=Status.SWAP_STATUS_UNSIGNED.value,
                unsigned_tx="{test_key: test_value}").save()

    sleep(0.5)  # give signer time to process notification from DB
    assert Signatures.objects(tx_id=d.id, signed_tx=signer.enc_key).count() == 1

    # Check notification process only Status.SWAP_STATUS_UNSIGNED
    d = ETHSwap(tx_hash="test hash", status=Status.SWAP_STATUS_SIGNED.value,
                unsigned_tx="{test_key: test_value}").save()

    sleep(0.5)
    assert Signatures.objects(tx_id=d.id, signed_tx=signer.enc_key).count() == 0
