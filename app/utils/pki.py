import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_keys import keys
from eth_utils import decode_hex
from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError  # Add ecdsa import

def generate_private_key():
    """
    Generate an Ethereum private key using ECDSA secp256k1.
    """
    private_key = SigningKey.generate(curve=SECP256k1)
    return private_key.to_string().hex()

def generate_public_key(private_key_hex: str):
    """
    Generate an Ethereum public key from the given private key using ECDSA secp256k1.
    """
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return public_key.to_string().hex()

def generate_ethereum_address(public_key_hex: str):
    """
    Generate an Ethereum address from the given public key.
    """
    public_key_bytes = bytes.fromhex(public_key_hex[2:])  # Remove '0x' prefix
    public_key = keys.PublicKey(public_key_bytes)
    return public_key.to_checksum_address()

def create_signing_challenge():
    """
    Create a random signing challenge.
    """
    challenge = os.urandom(32)
    return challenge.hex()

def verify_signing_challenge(public_key_hex: str, challenge: str, signature: str):
    """
    Verify the signing challenge using the public key and signature.
    """
    public_key_bytes = bytes.fromhex(public_key_hex)
    public_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    challenge_bytes = bytes.fromhex(challenge)
    signature_bytes = bytes.fromhex(signature)
    try:
        return public_key.verify(signature_bytes, challenge_bytes)
    except BadSignatureError:
        return False
