from mongoengine import Document, StringField, IntField


class TokenPairing(Document):
    # Foreign network
    src_network = StringField(required=True)  # Blockchain name
    src_coin = StringField(required=True)  # Token name
    src_address = StringField(required=True, unique=True)  # Smart contract address

    # Secret network
    dst_network = StringField(required=True)  # Always "Secret", redundant
    dst_coin = StringField(required=True)
    dst_address = StringField(required=True, unique=True)

    decimals = IntField(required=True)
