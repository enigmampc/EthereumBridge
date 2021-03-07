from datetime import datetime

from mongoengine import Document, StringField, DateTimeField, BooleanField


class SignerHealth(Document):
    signer = StringField(required=True, unique=True)
    health = BooleanField(required=True)
    updated_on = DateTimeField(default=datetime.utcnow)

    @classmethod
    def pre_save(cls, _, document, **kwargs):  # pylint: disable=unused-argument
        document.updated_on = datetime.now()
