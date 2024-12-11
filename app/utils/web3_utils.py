import hashlib
import json
import os
from datetime import datetime, timezone
from functools import lru_cache

import didkit
from fastapi import Depends
from typing_extensions import Annotated
from web3 import Web3

from ..core.config import Settings
from ..utils.ipfs_utils import (
    add_file_to_ipfs,
    get_file_from_ipfs,
    list_all_files_from_ipfs,
)
from .accumulator_utils import *
from .helpfunctions import hash_to_prime


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().HARDHAT_URL))

# Secrets dict for the RSA Accumulator
# accMod, accInit, accState = setup(
#     modulus=settings_dependency().BACKEND_MODULUS, A0=settings_dependency().BACKEND_ACC
# )
accMod = settings_dependency().BACKEND_MODULUS
accInit = settings_dependency().BACKEND_ACC
accState = dict()


async def issue_did(storeIPFS: bool = False):
    """
    Issue a DID
    """
    # Generate a new Ed25519 keypair
    jwk = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", jwk)

    print(f"JWK: {jwk}")
    print(f"DID: {did}")

    # print(
    #     f"\n\n\nDIDKIT DID RESOLVE:\n{await didkit.resolve_did(did, input_metadata=json.dumps({}))}\n\n\n"
    # )
    # if storeIPFS:
    #     # Store DID on IPFS
    #     ipfs_did_hash = add_file_to_ipfs(did)
    #     print(f"IPFS DID Hash: {ipfs_did_hash}")
    #     return jwk, did, ipfs_did_hash

    return jwk, did


async def issue_vc(did: str, jwk: str, user_uuid: str, storeIPFS: bool = False):
    """
    Issue a VC and sign it based on the received DID
    """
    server_did = settings_dependency().BACKEND_DID
    server_jwk = settings_dependency().BACKEND_JWK

    print(f"DID-Recv: \n{did}")
    print(f"JWK-Recv: \n{jwk}")
    print(f"UUID-Recv: \n{user_uuid}")

    print(f"Server DID: \n{server_did}")
    print(f"Server JWK: \n{server_jwk}")

    if not did:
        return {"Error": "DID not provided"}

    user_did = didkit.key_to_did("key", didkit.generate_ed25519_key())

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": f"urn:uuid:{user_uuid}",
        "type": ["VerifiableCredential"],
        "issuer": server_did,
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "id": user_did,
        },
    }

    print(f"VC: \n{credential}")

    signed_vc = await didkit.issue_credential(json.dumps(credential), "{}", server_jwk)

    if storeIPFS:
        # Store VC on IPFS
        ipfs_vc_hash = add_file_to_ipfs(signed_vc)
        print(f"IPFS VC Hash: {ipfs_vc_hash}")
        return {"VC": json.loads(signed_vc), "IPFS": ipfs_vc_hash}

    return {"VC": json.loads(signed_vc)}


# Load the deployment information
def getContract(contract_name: str, debug: bool = False):
    if not contract_name:
        raise ValueError("Contract name cannot be empty!")
    # Define the base directory (prefix path)
    base_dir = r"..\..\blockchain\ignition\deployments\chain-31337"

    # Construct the paths to the ABI and address JSON files by prefixing the base directory
    base_prefix = "Blackgate#"
    abi_json_path = os.path.join(
        base_dir, "artifacts", f"{base_prefix}{contract_name}.json"
    )
    address_json_path = os.path.join(base_dir, "deployed_addresses.json")

    if debug:
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
    if debug:
        print(f"Loaded Addresses\n{deployed_addresses}")
    contract_address = deployed_addresses.get(f"{base_prefix}{contract_name}", "")

    # Print contract address
    if debug:
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


def setAccumulator(accumulator: str):
    """
    Set the accumulator on the blockchain
    """
    # Create Contract Instance & Call the setAccumulator function from the contract
    tx_hash = get_rsa_accumulator().functions.setAccumulator(accumulator).transact()

    # Print the transaction hash for debugging purposes
    print(f"Transaction Hash: \n{tx_hash.hex()}")

    return tx_hash.hex()


def getCurrentAccumulator():
    """
    Get the current accumulator from the blockchain
    """
    # Create Contract Instance and Call the getAccumulator function from the contract
    current_accumulator = get_rsa_accumulator().functions.getAccumulator().call()
    current_accumulator = f"0x{current_accumulator.hex()}"
    print(f"Current Accumulator: \n{current_accumulator}")

    return current_accumulator


async def recalcAccumulator():
    """
    Recalculate the Accumulator at this current point in time by using IPFS ls
    """

    # Recalculate the accumulator
    # Get current accumulator value
    current_accumulator = int(getCurrentAccumulator(), 16)

    # convert modulus to int
    print(f"Modulus({len(str(accMod))}): {accMod}")
    accModulus = int(accMod, 16)

    # List all CIDs currently in IPFS
    ipfs_cids = list_all_files_from_ipfs()
    concat_ipfs = "".join(ipfs_cids)
    concat_bytes = concat_ipfs.encode()
    hashed_cids = int(hashlib.sha256(concat_bytes).hexdigest(), 16)

    print(f"Hash of CIDs({len(str(hashed_cids))}): {hashed_cids}")
    
    x = hashed_cids
    A1 = add(current_accumulator, accState, x, accModulus)
    nonce = accState[x]
    proof = prove_membership(current_accumulator, accState, x, accModulus)
    prime, nonce = hash_to_prime(x, nonce)

    new_accumulator = A1
    

    # # Run the list through hash_to_prime to get element1
    # element1, nonce1 = hash_to_prime(hashed_cids, 3072)

    # # Generate new accumulator value
    # # ADD(Accumulator, State, Element, Modulus)
    # new_accumulator = add(current_accumulator, accState, element1, accModulus)

    # # Store the nonce after calculating the new accumulator
    # nonce1 = accState[element1]

    # print(f"Element1({len(str(element1))}): {element1}")
    # print(f"Nonce1({len(str(nonce1))}): {nonce1}")

    # # Generate Proof
    # # proof, prime = generate_proof(element1, current_accumulator, accState, accModulus)
    # prime, nonce = hash_to_prime(element1, nonce1)
    # print(f"Prime({len(str(prime))}): {prime}")

    # # Set the new accumulator on the blockchain
    # print(f"New Accumulator({len(str(new_accumulator))}): {hex(new_accumulator)}")
    # print(f"\nState: {accState}")
    return {
        "isAccTheSame?": "Yes" if new_accumulator == current_accumulator else "No",
        "NewAccumulator": to_padded_num_str(new_accumulator, 384),
        "Prime": to_padded_num_str(prime, 32),
    }


# Create a new prime from hash
async def storeDIDonBlockchain(did: str, publicKey: str):
    """
    Store DID on IPFS and then on the blockchain
    """
    # Get currentAccumulator value
    current_accumulator = getCurrentAccumulator()

    # Store DID on IPFS
    ipfs_did_hash = add_file_to_ipfs(did)
    print(f"IPFS DID Hash: {ipfs_did_hash}")

    # Create a contract instance and Call the registerDID function from the contract
    tx_hash = (
        get_did_registry()
        .functions.registerDID(
            did,
            ipfs_did_hash,
            current_accumulator,
            publicKey,
        )
        .transact()
    )

    # Print the transaction hash for debugging purposes
    print(f"Transaction Hash: \n{tx_hash.hex()}")

    # Return the CID and the transaction hash as JSON
    return {"CID": ipfs_did_hash, "TX": tx_hash.hex()}


async def storeVCOnBlockchain(did: str, vc: str):
    """
    Store VC on IPFS and then on the blockchain
    """
    # json dump the vc
    vc = json.dumps(vc)

    # Store VC on IPFS
    ifps_VC_CID = add_file_to_ipfs(vc)
    print(f"IPFS VC CID: {ifps_VC_CID}")

    # Create a keccak256 hash of the VC
    vc_hash = w3.solidity_keccak(["string"], [vc]).hex()
    print(f"VC Hash: {vc_hash}")

    # Call the storeCredential function from the contract
    tx_hash = get_vc_manager().functions.issueVC(did, vc_hash, ifps_VC_CID).transact()

    # Print the transaction hash for debugging purposes
    print(f"Transaction Hash: \n{tx_hash.hex()}")

    return {"CID": ifps_VC_CID, "TX": tx_hash.hex()}


async def udpateAccumulatorOnBlockchain():
    """
    Update the accumulator on the blockchain, by recalculating the accumulator from the IPFS files
    """

    # Recalculate the accumulator
    # Create a RSAAcc contract instance
    # Update the ACC
    pass


# Get all accounts from hardhat testnet
def get_loaded_accounts():
    return w3.eth.accounts


# Parse accounts.json and return a list of w3 accounts
def get_accounts():
    with open("accounts.json", "r") as file:
        accounts = json.load(file)
    return accounts


"""
Contract init functions
"""


# Return a DIDRegistry instance
def get_did_registry():
    contract_address, contract_abi = getContract("DIDRegistry")
    return w3.eth.contract(address=contract_address, abi=contract_abi)


# Return a VerifiableCredentialManager instance
def get_vc_manager():
    contract_address, contract_abi = getContract("VerifiableCredentialManager")
    return w3.eth.contract(address=contract_address, abi=contract_abi)


# Return a RSAAccumulator instance
def get_rsa_accumulator():
    contract_address, contract_abi = getContract("RSAAccumulator")
    return w3.eth.contract(address=contract_address, abi=contract_abi)
