from datetime import datetime
from enum import Enum, auto

from mongoengine import Document, StringField, DateTimeField, signals, IntField

from .common import EnumField


class Status(Enum):
    SWAP_UNSIGNED = auto()
    SWAP_SIGNED = auto()
    SWAP_SUBMITTED = auto()  # Submitted to Secret
    SWAP_CONFIRMED = auto()
    SWAP_FAILED = auto()
    SWAP_RETRY = auto()


class Swap(Document):
    src_tx_hash = StringField(required=True, unique=True)
    src_network = StringField(required=True)
    src_coin = StringField(required=True, default='')
    amount = StringField(required=True)
    status = EnumField(Status, required=True)
    unsigned_tx = StringField(required=True)
    dst_tx_hash = StringField(required=True, default='')
    dst_network = StringField(required=True)
    dst_coin = StringField(default='seth')
    dst_address = StringField()
    created_on = DateTimeField(default=datetime.utcnow)
    updated_on = DateTimeField(default=datetime.utcnow)
    sequence = IntField()

    @classmethod
    def pre_save(cls, _, document, **kwargs):  # pylint: disable=unused-argument
        document.updated_on = datetime.now()

    def __repr__(self):
        return f"<Swap hash {self.src_tx_hash} from {self.src_network} for {self.amount} {self.src_coin} " \
               f"to {self.dst_network} for {self.dst_coin}>"


signals.pre_save.connect(Swap.pre_save, sender=Swap)
