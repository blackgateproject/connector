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
from . import (
    add_file_to_ipfs,
    get_file_from_ipfs,
    list_all_files_from_ipfs,
)


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


# NOTE:: Changed for zksync
# Load the deployment information
def getContract(contract_name: str, debug: bool = False):
    """
    Loads the contract details from the deployment files in the hardhat project (w/o zksync)
    """
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

    if debug >= 2:
        print(f"Loading contract details...")
        print(f"  ABI Path: {abi_json_path}")
        print(f"  Address Path: {address_json_path}")

    # Load the ABI and contract address in one go
    with open(abi_json_path, "r") as abi_file:
        contract_data = json.load(abi_file)

    with open(address_json_path, "r") as address_file:
        deployed_addresses = json.load(address_file)
    if debug >= 2:
        print(f"Loaded Addresses\n{deployed_addresses}")

    # Extract contract ABI and address
    contract_abi = contract_data["abi"]
    contract_address = deployed_addresses.get(f"{base_prefix}{contract_name}", "")

    # Print contract address
    if debug >= 2:
        print(f"  Contract Address: {contract_address}\n")

    # Loop through the ABI and print details for each function
    if debug >= 2:
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

    try:
        # Store DID on IPFS
        ipfs_did_hash = add_file_to_ipfs(did)
        if debug >= 2:
            print(f"[storeDIDonBlockchain()] IPFS DID Hash: {ipfs_did_hash}")
    except Exception as e:
        print(f"[storeDIDonBlockchain()] Failed to store DID on IPFS: {e}")
        return {"Error": "[storeDIDonBlockchain()] Failed to store DID on IPFS"}

    # Create a contract instance and Call the registerDID function from the contract
    tx_hash = (
        get_did_registry()
        .functions.registerDID(
            did,
            ipfs_did_hash,
            publicKey,
        )
        .transact()
    )

    # Print the transaction hash for debugging purposes
    if debug >= 1:
        print(f"[storeDIDonBlockchain()] Transaction Hash: {tx_hash.hex()}")

    # Return the CID and the transaction hash
    return ipfs_did_hash, tx_hash.hex()


async def storeVCOnBlockchain(did: str, vc: str):
    """
    Store VC on IPFS and then on the blockchain
    """
    # json dump the vc
    vc = json.dumps(vc)

    # Store VC on IPFS
    ifps_VC_CID = add_file_to_ipfs(vc)
    if debug >= 2:
        print(f"[storeVCOnBlockchain()] IPFS VC CID: {ifps_VC_CID}")

    # Create a keccak256 hash of the VC
    vc_hash = w3.solidity_keccak(["string"], [vc]).hex()
    if debug >= 2:
        print(f"[storeVCOnBlockchain()] VC Hash: {vc_hash}")

    # Call the storeCredential function from the contract
    tx_hash = get_vc_manager().functions.issueVC(did, vc_hash, ifps_VC_CID).transact()

    # Print the transaction hash for debugging purposes
    if debug >= 1:
        print(f"[storeVCOnBlockchain()] Transaction Hash: \n{tx_hash.hex()}")

    # Return the CID and the transaction hash
    return ifps_VC_CID, tx_hash.hex()


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
