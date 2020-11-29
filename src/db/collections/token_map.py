from mongoengine import Document, StringField, IntField, MapField, EmbeddedDocumentField


class TokenRecord(Document):
    name = StringField(required=True)
    swap_address: StringField(required=True)
    swap_code_hash: StringField(required=True)
    token_address: StringField(required=True)


class TokenMapRecord(Document):
    src = StringField(required=True)
    src_network = StringField(required=True)
    swap_token = TokenRecord


class TokenPairingDisplayProps(Document):
    image = StringField(required=True)
    label = StringField(required=True)
    symbol = StringField(required=True)

class TokenPairing(Document):
    # Blockchain name
    src_network = StringField(required=True)
    # Token name
    src_coin = StringField(required=True)
    # Smart contract address
    src_address = StringField(required=True, unique=True)
    dst_network = StringField(required=True)
    dst_address = StringField(required=True, unique=True)
    dst_coin = StringField(required=True)
    decimals = IntField(required=True)
    name = StringField(required=True)
    display_props = MapField(EmbeddedDocumentField(TokenPairingDisplayProps), required=False)
