from mongoengine import Document, StringField


class ScrtRetry(Document):
    original_id = StringField(required=True, unique=True)
    retry_id = StringField(required=True, unique=True)
