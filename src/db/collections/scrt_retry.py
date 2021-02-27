from datetime import datetime

from mongoengine import Document, StringField, DateTimeField, IntField, ObjectIdField

from src.db.collections.common import EnumField
from src.db.collections.eth_swap import Status


class ScrtRetry(Document):
    swap = ObjectIdField(required=True)
    # original_nonce = IntField(required=True)
    original_contract = StringField(required=False)
