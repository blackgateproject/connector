import json
import uuid
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_keys import keys
from eth_utils import decode_hex
from fastapi import Depends
from fastapi.responses import JSONResponse
from gotrue import AuthResponse
from gotrue.types import AuthResponse
from supabase import Client, create_client
from supabase.client import AuthApiError
from supabase.lib.client_options import ClientOptions
from typing_extensions import Annotated
from web3 import Web3

from .utils import get_settings_dependency

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(get_settings_dependency().HARDHAT_URL))


def revoke_did(address: str):
    """
    Revoke a DID on the blockchain with the given address.
    """
    contract = initialize_contract()
    tx = contract.functions.revokeDID(address).transact({"from": address})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    return receipt


def register_did(address: str, did: str):
    """
    Register a DID on the blockchain with the given address and public key.
    """
    contract = initialize_contract()
    tx = contract.functions.registerDID(address, did).transact({"from": address})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    return receipt


def get_did(address: str):
    """
    Get the DID for a given address from the contract.
    """
    contract = initialize_contract()  # Ensure your contract is initialized
    print(f"[GET_DID] Address: {address}")

    # Directly call the `getDID` function, no need for tx receipt
    did = contract.functions.getDID(address).call()

    # Print or log the DID for debugging
    print(f"[GET_DID] Retrieved DID from blockchain: {did}")

    # Return the DID string (it should already be in the correct format)
    return did


def issue_vc(issuer: str, holder: str, credential_hash: str):
    """
    Issue a Verifiable Credential (VC) on the blockchain.
    """
    contract = initialize_contract()
    tx = contract.functions.issueVC(holder, credential_hash).transact({"from": issuer})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    return receipt


def verify_signature(message: str, signature: str, address: str, w3: Web3) -> bool:
    """
    Verifies the signature of a message using the Ethereum address.
    """
    try:
        # Convert the signature from hex to bytes
        signature_bytes = bytes.fromhex(signature)

        # Recover the address that signed the message
        recovered_address = w3.eth.account.recover_message(
            message.encode("utf-8"), signature=signature_bytes
        )

        # Compare recovered address with the given address
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(f"Error in verifying signature: {e}")
        return False


def generate_challenge():
    # Generate a random challenge (nonce)
    challenge = os.urandom(32)  # 32 bytes random
    return challenge.hex()  # Return as a hexadecimal string


def verify_challenge(user_address, challenge, signed_challenge):
    # Recompute the challenge hash
    challenge_hash = w3.solidityKeccak(["string"], [challenge])

    # Recover the address from the signed challenge
    recovered_address = w3.eth.account.recoverHash(
        challenge_hash, signature=signed_challenge
    )

    # Verify that the recovered address matches the user's address (DID owner)
    if recovered_address.lower() == user_address.lower():
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed!")
        return False


def sign_challenge(challenge, private_key):
    # Hash the challenge
    challenge_hash = w3.solidityKeccak(["string"], [challenge])

    # Sign the challenge hash with the user's private key
    signed_message = w3.eth.account.signHash(challenge_hash, private_key)
    return signed_message.signature.hex()  # Return signed message (hex format)


def sign_message(message: str, private_key: str):
    """
    Signs a message with the provided private key.
    """
    try:
        private_key_bytes = base64.b64decode(
            private_key
        )  # Decode private key from base64
        private_key_obj = serialization.load_pem_private_key(
            private_key_bytes, password=None
        )

        signature = private_key_obj.sign(
            message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )

        # Return the signature as hex
        return signature.hex()
    except Exception as e:
        print(f"Error in signing message: {e}")
        return None


def generate_private_key():
    """
    Generate a private key using RSA algorithm (for testing purposes).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key = base64.b64encode(private_pem).decode("utf-8")

    return private_pem


def generate_public_key(private_key_pem: bytes, isPEM: bool, isBase64: bool):
    """
    Generate a public key from the given private key (in PEM, Base64, or Hex format).
    Also verify the public key by signing a message with the private key and verifying it with the public key.
    use eth_keys to generate a new public key from the private key.
    """
    try:
        # Load the private key
        if isPEM:
            print(f"I am in PEM")
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
            print(f"PEM'ed private key: {private_key}")
        elif isBase64:
            print(f"I am in B64")
            private_key = serialization.load_pem_private_key(
                base64.b64decode(private_key_pem), password=None
            )
            print(f"Base64'ed private key: {private_key}")
        else:
            print(f"I am in HEX")
            private_key = private_key_pem

        privateKeyBytes = decode_hex(private_key)
        privateKey = keys.PrivateKey(privateKeyBytes)
        public_key = privateKey.public_key
        print(f"Public key: {public_key}")

        print(f"CONFRIM Address: {public_key.to_checksum_address()}")

        return str(public_key)
    except Exception as e:
        print(f"Error in generating public key: {e}")
        return None


# Utility Functions
def verify_signature(message: str, signature: str, address: str, w3Prov: Web3) -> bool:
    """
    Verifies that a given signature is valid for a given message and address.

    Args:
        message (str): The original message that was signed.
        signature (str): The signature to verify.
        address (str): The Ethereum address of the signer.

    Returns:
        bool: True if the signature is valid and matches the address, False otherwise.
    """
    message_hash = web3.solidityKeccak(["string"], [message])
    signer = web3.eth.account.recoverHash(message_hash, signature=signature)
    return signer.lower() == address.lower()


# Load the deployment information
def getContract():
    debug = False
    # Define the base directory (prefix path)
    base_dir = r"..\blockchain\ignition\deployments\chain-31337"

    # Construct the paths to the ABI and address JSON files by prefixing the base directory
    abi_json_path = os.path.join(
        base_dir, "artifacts", "DIDRegistryModule#DIDRegistry.json"
    )
    address_json_path = os.path.join(base_dir, "deployed_addresses.json")

    print(f"Loading contract details...")
    print(f"  ABI Path: {abi_json_path}")
    print(f"  Address Path: {address_json_path}")

    # Load the ABI and contract address in one go
    with open(abi_json_path, "r") as abi_file:
        contract_data = json.load(abi_file)

    with open(address_json_path, "r") as address_file:
        deployed_addresses = json.load(address_file)

    # Extract contract ABI and address
    contract_abi = contract_data["abi"]
    contract_address = deployed_addresses.get("DIDRegistryModule#DIDRegistry", "")

    # Print contract address
    print(f"  Contract Address: {contract_address}\n")

    # Loop through the ABI and print details for each function
    if debug:
        for item in contract_abi:
            # Only print function details, skip events
            if item["type"] == "function":
                print(f"Function Name: {item['name']}")

                # Print function inputs
                if item["inputs"]:
                    print("  Inputs:")
                    for input_param in item["inputs"]:
                        print(
                            f"    - Name: {input_param['name']}({input_param['type']})"
                        )
                else:
                    print("  Inputs: None")

                # Print function outputs
                if item["outputs"]:
                    print("  Outputs:")
                    for output_param in item["outputs"]:
                        print(
                            f"    - Name: {output_param['name']}({output_param['type']})"
                        )
                else:
                    print("  Outputs: None")

                print("-" * 50)

    # Return both the contract address and ABI for further use
    return contract_address, contract_abi


# Initialize Web3 and the contract
def initialize_contract():
    w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
    # contract_address, contract_abi = spawnContract()
    contract_address, contract_abi = getContract()

    return w3.eth.contract(address=contract_address, abi=contract_abi)


# Get all accounts from hardhat testnet
def get_loaded_accounts():
    return w3.eth.accounts


# Parse accounts.json and return a list of w3 accounts
def get_accounts():
    with open("accounts.json", "r") as file:
        accounts = json.load(file)
    return accounts
