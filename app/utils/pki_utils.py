import base64
import os

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_utils import decode_hex

# Initialize the KeyAPI with the NativeECCBackend
keys = KeyAPI(NativeECCBackend)

def generate_private_key():
    """
    Generate a new private key.
    
    Returns:
        str: The private key in hexadecimal format.
    """
    random_bytes = os.urandom(32)
    private_key = keys.PrivateKey(random_bytes)
    return private_key.to_hex()

def generate_public_key(private_key_hex):
    """
    Generate the public key corresponding to a given private key.
    
    Args:
        private_key_hex (str): The private key in hexadecimal format.
    
    Returns:
        str: The public key in hexadecimal format.
    """
    private_key = keys.PrivateKey(decode_hex(private_key_hex))
    public_key = private_key.public_key
    # Ensure the public key is correctly derived from the private key
    assert public_key.to_checksum_address() == private_key.public_key.to_checksum_address()
    return public_key.to_hex()

def create_signing_challenge():
    """
    Create a random signing challenge.
    
    Returns:
        str: The challenge message in hexadecimal format.
    """
    message = os.urandom(32)
    return message.hex()

def sign_challenge(private_key_hex, challenge):
    """
    Sign a challenge message with a given private key.
    
    Args:
        private_key_hex (str): The private key in hexadecimal format.
        challenge (str): The challenge message in hexadecimal format.
    
    Returns:
        str: The signature in base64 encoded format.
    """
    private_key = keys.PrivateKey(decode_hex(private_key_hex))
    message_bytes = decode_hex(challenge)
    signature = private_key.sign_msg(message_bytes)
    return base64.b64encode(signature.to_bytes()).decode()

def verify_signing_challenge(public_key_hex, message, signature):
    """
    Verify a signed challenge message with a given public key.
    
    Args:
        public_key_hex (str): The public key in hexadecimal format.
        message (str): The challenge message in hexadecimal format.
        signature (str): The signature in base64 encoded format.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    public_key = keys.PublicKey(decode_hex(public_key_hex))
    message_bytes = decode_hex(message)
    signature_bytes = base64.b64decode(signature)
    try:
        public_key.verify_msg(message_bytes, keys.Signature(signature_bytes))
        return True
    except Exception as e:
        print(f"Error verifying signature: {str(e)}")
        return False
