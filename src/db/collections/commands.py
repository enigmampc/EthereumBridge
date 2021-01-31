from datetime import datetime

from mongoengine import Document, StringField, DateTimeField, IntField

from src.db.collections.common import EnumField
from src.db.collections.eth_swap import Status


class Commands(Document):
    status = EnumField(Status, required=True)
    unsigned_tx = StringField(required=True)
    dst_address = StringField(required=False)
    created_on = DateTimeField(default=datetime.utcnow)
    updated_on = DateTimeField(default=datetime.utcnow)
    sequence = IntField(required=False)
    dst_tx_hash = StringField(required=False)
