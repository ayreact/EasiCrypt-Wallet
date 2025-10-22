from mongoengine import Document, StringField, BinaryField, connect
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
if MONGO_URI is None:
    raise ValueError("MONGO_URI not set in .env file")
connect(host=MONGO_URI)

class User(Document):
    phone_number = StringField(required=True, unique=True)
    wallet_address = StringField(required=True)
    encrypted_private_key = BinaryField(required=True)
    pin_hash = StringField(required=True) 

    meta = {'collection': 'users'}

    def to_dict(self):
        return {
            "phone_number": self.phone_number,
            "wallet_address": self.wallet_address,
        }