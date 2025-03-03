import hashlib
import json
import os
from datetime import datetime, timezone
from functools import lru_cache

import didkit
from eth_account import Account
from fastapi import Depends
from typing_extensions import Annotated
from web3 import Web3
from zksync2.module.module_builder import ZkSyncBuilder
from zksync2.signer.eth_signer import PrivateKeyEthSigner

from ..core.config import Settings
from ..core.merkle import merkleCore


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().HARDHAT_URL))

debug = settings_dependency().DEBUG

wallet_prv_key = ""
wallet_addr = ""
if settings_dependency().BLOCKCHAIN_WALLET_ADDR:
    wallet_prv_key = settings_dependency().BLOCKCHAIN_WALLET_PRVT_KEY
    wallet_addr = settings_dependency().BLOCKCHAIN_WALLET_ADDR

    derived_addr = Account.from_key(wallet_prv_key).address
    if derived_addr != wallet_addr:
        print(
            f"Derived Address({derived_addr}) does not match the provided address({wallet_addr})"
        )

    if debug >= 2:
        print("Using Wallet Address from .env")

else:
    print(
        f"BLOCKCHAIN_WALLET_ADDR not set in .env, please use a valid private key and address"
    )


def getContractZKsync(contract_name: str):
    """
    Loads the contract details from the deployment files in the hardhat project (w/zksync)
    Will merge to getContract once the pull request is completed for zksync
    """
    # Basic error checks
    if not contract_name:
        raise ValueError("Contract name cannot be empty!")
    elif contract_name not in [
        "EthereumDIDRegistry",
        "VerifiableCredentialManager",
    ]:
        raise ValueError("Invalid contract name provided!")

    # Define the base directory (prefix path)
    base_dir = r"..\..\blockchain"

    # zksyncNodeType[dockerizedNode, anvilZKsync, zkSyncSepoliaTestnet, zkSyncSepoliaMainet]
    zksyncNodeType = "anvilZKsync"
    deployments_json_path = os.path.join(
        base_dir,
        "deployments-zk",
        zksyncNodeType,
        f"contracts/{contract_name}.sol",
        f"{contract_name}.json",
    )

    if debug >= 3:
        print(f"Loading {contract_name} contract details...")
        print(f"  Deployments Path: {deployments_json_path}")

    # Load contract deployment json
    with open(deployments_json_path, "r") as contract_file:
        contract_data = json.load(contract_file)
        # if debug >= 2:
        # print(f"Contract Data: {json.dumps(contract_data)}")

    # Extract contract ABI
    contract_abi = contract_data.get("abi")

    # Extract contract address, txHash, constructorArgs
    for entry in contract_data.get("entries", []):
        contract_address = entry.get("address")
        txHash = entry.get("txHash")
        constructorArgs = entry.get("constructorArgs")

        if debug >= 4:

            print(f"Contract Address: {contract_address}")
            print(f"Contract ABI: {contract_abi}")
            print(f"Transaction Hash: {txHash}")
            print(f"Constructor Args: {constructorArgs}")
            print("\n")

    # # Return both the contract address and ABI for further use

    if not contract_address:
        raise ValueError("Contract address not found in the deployment file!")
    elif not contract_abi:
        raise ValueError("Contract ABI not found in the deployment file!")

    return contract_address, contract_abi


# Create a new prime from hash
async def storeDIDonBlockchain(did: str, publicKey: str):
    """
    Store DID on IPFS and then on the blockchain
    """

    # try:
    #     # Store DID on IPFS
    #     # ipfs_did_hash = add_file_to_ipfs(did)
    #     # if debug >= 2:
    #         # print(f"[storeDIDonBlockchain()] IPFS DID Hash: {ipfs_did_hash}")
    # except Exception as e:
    #     print(f"[storeDIDonBlockchain()] Failed to store DID on IPFS: {e}")
    #     return {"Error": "[storeDIDonBlockchain()] Failed to store DID on IPFS"}

    # Create a contract instance and Call the registerDID function from the contract
    tx_hash = (
        get_did_registry()
        .functions.registerDID(
            did,
            # ipfs_did_hash,
            publicKey,
        )
        .transact()
    )

    # Print the transaction hash for debugging purposes
    if debug >= 1:
        print(f"[storeDIDonBlockchain()] Transaction Hash: {tx_hash.hex()}")

    # Return the CID and the transaction hash
    return tx_hash.hex()


async def storeVCOnBlockchain(did: str, vc: str):
    """
    Store VC on IPFS and then on the blockchain
    """
    # json dump the vc
    vc = json.dumps(vc)

    # Store VC on IPFS
    # ifps_VC_CID = add_file_to_ipfs(vc)
    # if debug >= 2:
    #     print(f"[storeVCOnBlockchain()] IPFS VC CID: {ifps_VC_CID}")

    # Create a keccak256 hash of the VC
    vc_hash = w3.solidity_keccak(["string"], [vc]).hex()
    if debug >= 2:
        print(f"[storeVCOnBlockchain()] VC Hash: {vc_hash}")

    # Call the storeCredential function from the contract
    # tx_hash = get_vc_manager().functions.issueVC(did, vc_hash, ifps_VC_CID).transact()
    tx_hash = get_vc_manager().functions.issueVC(did, vc_hash).transact()

    # Print the transaction hash for debugging purposes
    if debug >= 1:
        print(f"[storeVCOnBlockchain()] Transaction Hash: \n{tx_hash.hex()}")

    # Return the CID and the transaction hash
    return tx_hash.hex()


def addUserToMerkle(user: str, pw: str):
    """
    Add a user to the Merkle Tree
    """
    # Add the user to the Merkle Tree
    dataEntries = merkleCore.add_user(user, pw)
    return dataEntries


def verifyUserOnMerkle(user: str, pw: str):
    """
    Verify a user on the Merkle Tree
    """
    # Verify the user on the Merkle Tree
    valid = merkleCore.verify_proof(user, pw)
    return valid


async def issue_did():
    """
    Issue a DID
    """
    # Generate a new Ed25519 keypair
    jwk = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", jwk)

    if debug >= 2:
        print(f"[issue_did()] JWK: {jwk}")
        print(f"[issue_did()] DID: {did}")

    # print(
    #     f"\n\n\nDIDKIT DID RESOLVE:\n{await didkit.resolve_did(did, input_metadata=json.dumps({}))}\n\n\n"
    # )
    # if storeIPFS:
    #     # Store DID on IPFS
    #     ipfs_did_hash = add_file_to_ipfs(did)
    #     print(f"IPFS DID Hash: {ipfs_did_hash}")
    #     return jwk, did, ipfs_did_hash

    return jwk, did


async def issue_vc(did: str, jwk: str, user_uuid: str):
    """
    Issue a VC and sign it based on the received DID
    """
    server_did = settings_dependency().BACKEND_DID
    server_jwk = settings_dependency().BACKEND_JWK

    if debug >= 1:
        print(f"[issue_vc()] DID-Recv: {did}")
        print(f"[issue_vc()] JWK-Recv: \n{jwk}")
        print(f"[issue_vc()] UUID-Recv: {user_uuid}")
    if debug >= 2:
        print(f"[issue_vc()] Server-DID(env): {server_did}")
        print(f"[issue_vc()] Server-JWK(env): \n{server_jwk}")

    missing_params = [
        param
        for param, name in [(did, "DID"), (jwk, "JWK"), (user_uuid, "User-UUID")]
        if not param
    ]
    if missing_params:
        raise ValueError(
            f"[issue_vc()] Error: {', '.join(name for _, name in missing_params)} not provided"
        )

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

    if debug >= 1:
        print(f"[issue_vc()] Generated VC: \n{credential}")

    signed_vc = await didkit.issue_credential(json.dumps(credential), "{}", server_jwk)

    # if storeIPFS:
    #     # Store VC on IPFS
    #     ipfs_vc_hash = add_file_to_ipfs(signed_vc)

    #     if debug >= 1:
    #         print(f"[issue_vc()] IPFS VC Hash: {ipfs_vc_hash}")
    #     return {"VC": json.loads(signed_vc), "IPFS": ipfs_vc_hash}
    # if debug >=2:
    # print(f"[issue_vc()] Signed VC: \n{json.loads(signed_vc)}")
    return json.loads(signed_vc)


"""
Contract init functions
"""


# Return a DIDRegistry instance
def get_did_registry():
    contract_address, contract_abi = getContractZKsync("EthereumDIDRegistry")
    return w3.eth.contract(address=contract_address, abi=contract_abi)


# Return a VerifiableCredentialManager instance
def get_vc_manager():
    contract_address, contract_abi = getContractZKsync("VerifiableCredentialManager")
    return w3.eth.contract(address=contract_address, abi=contract_abi)
