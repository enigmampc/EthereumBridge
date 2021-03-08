from datetime import datetime

from mongoengine import Document, StringField, DateTimeField, IntField


class EthSignatures(Document):
    tx_id = IntField(required=True)
    tx_hash = StringField(required=True, unique=True)
    signer = StringField(required=True)
    swap_id = StringField(required=True)
    creation = DateTimeField(default=datetime.now, required=True)
