import base64
import os

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_utils import decode_hex

keys = KeyAPI(NativeECCBackend)

def generate_private_key():
    randomBytes = os.urandom(32)
    private_key = keys.PrivateKey(randomBytes)
    return private_key.to_hex()

def generate_public_key(private_key_hex):
    private_key = keys.PrivateKey(decode_hex(private_key_hex))
    public_key = private_key.public_key
    assert public_key.to_checksum_address() == private_key.public_key.to_checksum_address()
    return public_key.to_hex()

def create_signing_challenge():
    message = os.urandom(32)
    return message.hex()

def sign_challenge(private_key_hex, challenge):
    private_key = keys.PrivateKey(decode_hex(private_key_hex))
    message_bytes = decode_hex(challenge)
    signature = private_key.sign_msg(message_bytes)
    return base64.b64encode(signature.to_bytes()).decode()

def create_signing_challenge():
    message = os.urandom(32)
    return message.hex()

def verify_signing_challenge(public_key_hex, message, signature):
    public_key = keys.PublicKey(decode_hex(public_key_hex))
    message_bytes = decode_hex(message)
    signature_bytes = base64.b64decode(signature)
    try:
        public_key.verify_msg(message_bytes, keys.Signature(signature_bytes))
        return True
    except Exception as e:
        print(f"Error verifying signature: {str(e)}")
        return False
