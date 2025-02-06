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

from ..core.accumulator import accumulatorCore
from ..core.merkle import merkleCore
from ..core.config import Settings
from ..utils.ipfs_utils import (
    add_file_to_ipfs,
    get_file_from_ipfs,
    list_all_files_from_ipfs,
)

# from .accumulator_utils import *
# from .accumulator_utils import hash_to_prime


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().HARDHAT_URL))
w3_zk = Web3(Web3.HTTPProvider(settings_dependency().ZK_HARDHAT_URL))

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
        wallet_addr = derived_addr

    if debug >= 2:
        print("Using Wallet Address from .env")

else:
    print(
        f"BLOCKCHAIN_WALLET_ADDR not set in .env, please use a valid private key and address"
    )

def addUserToMerkle(user:str, pw:str):
    """
    Add a user to the Merkle Tree
    """
    # Add the user to the Merkle Tree
    dataEntries = merkleCore.add_user(user, pw)
    return dataEntries

def verifyUserOnMerkle(user:str, pw:str):
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

    if debug >= 6:
        print(f"Loading contract details...")
        print(f"  ABI Path: {abi_json_path}")
        print(f"  Address Path: {address_json_path}")

    # Load the ABI and contract address in one go
    with open(abi_json_path, "r") as abi_file:
        contract_data = json.load(abi_file)

    with open(address_json_path, "r") as address_file:
        deployed_addresses = json.load(address_file)
    if debug >= 6:
        print(f"Loaded Addresses\n{deployed_addresses}")

    # Extract contract ABI and address
    contract_abi = contract_data["abi"]
    contract_address = deployed_addresses.get(f"{base_prefix}{contract_name}", "")

    # Print contract address
    if debug >= 6:
        print(f"  Contract Address: {contract_address}\n")

    # Loop through the ABI and print details for each function
    if debug >= 6:
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
        "DIDRegistry",
        "RSAAccumulatorVerifier",
        "VerifiableCredentialManager",
    ]:
        raise ValueError("Invalid contract name provided!")

    # Define the base directory (prefix path)
    base_dir = r"..\..\blockchain-1"

    # zksyncNodeType[dockerizedNode, anvilZKsync, zkSyncSepoliaTestnet, zkSyncSepoliaMainet]
    zksyncNodeType = "dockerizedNode"
    deployments_json_path = os.path.join(
        base_dir,
        "deployments-zk",
        zksyncNodeType,
        f"contracts/{contract_name}.sol",
        f"{contract_name}.json",
    )

    if debug >= 6:
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

        if debug >= 6:

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


# Function to get the current accumulator (view function)
def getCurrentAccumulatorMod():
    """
    Get the current accumulator modulus from the blockchain (view function).
    """
    # Create Contract Instance
    contract = get_rsa_accumulator()

    # Call the getAccumulator function (view function, no gas required)
    try:
        current_accumulator = contract.functions.getModulus().call(
            {"from": wallet_addr}
        )

        # Since it's returned as bytes, we can format it into hex
        current_accumulator = f"0x{current_accumulator.hex()}"

        if debug >= 2:
            print(
                f"[getCurrentAccumulatorMod()] Current Accumulator: {current_accumulator}"
            )
        return current_accumulator

    except Exception as e:
        print(f"Error while calling getAccumulator: {e}")
        return None


def addUserToAccmulator(did: str, vc: str):
    # Combine the did and vc into json
    userW3creds = json.dumps({"did": did, "vc": vc})
    print(f"[addUserToAccmulator()] UserW3Creds: {userW3creds}")
    # keccak hash the combined json
    userW3credsHash = w3.solidity_keccak(["string"], [userW3creds]).hex()
    # call the add function in the accumulator object (NOTE:: the returned values are padded_str)
    accVal, proof, prime = accumulatorCore.add(userW3credsHash)
    # return the accVal, prime and calculated proof
    return accVal, proof, prime


# Function to verify the accumulator
def verifyUserOnAccumulator(accVal: str, proof: str, prime: str):
    """
    Verify the user on the RSA accumulator
    """
    # Call the verify function from the contract
    try:
        result = (
            get_rsa_accumulator()
            .functions.verify(proof, prime, accVal)
            .call({"from": wallet_addr})
        )

        if debug >= 2:
            print(f"[verifyUserOnAccumulator()] Verification Result: {result}")

        return result

    except Exception as e:
        print(f"Error while calling verify: {e}")


# Create a new prime from hash
def storeDIDonBlockchain(did: str, publicKey: str):
    """
    Store DID on IPFS and then on the blockchain
    """
    # Get currentAccumulator value
    # current_accumulator = getCurrentAccumulatorMod()

    try:
        # Store DID on IPFS
        ipfs_did_hash = add_file_to_ipfs(did)
        if debug >= 2:
            print(f"[storeDIDonBlockchain()] IPFS DID Hash: {ipfs_did_hash}")
    except Exception as e:
        print(f"[storeDIDonBlockchain()] Failed to store DID on IPFS: {e}")
        return {"Error": "[storeDIDonBlockchain()] Failed to store DID on IPFS"}

    # Create a contract instance and Call the registerDID function from the contract
    # NOTE:: TX is state changing,this func does not sign the transaction
    tx_hash = (
        get_did_registry()
        .functions.registerDID(
            did,
            ipfs_did_hash,
            # current_accumulator,
            publicKey,
        )
        .build_transaction(
            {
                "from": wallet_addr,
                # "to": get_did_registry().address,
                # "value": 1000000000000000000,
                "chainId": 270,
                "gas": 2000000,
                "gasPrice": w3_zk.to_wei("1", "gwei"),
                "nonce": w3_zk.eth.get_transaction_count(wallet_addr),
            }
        )
    )

    # tx_log = w3_zk.eth.get_transaction_receipt(tx_hash)

    # print(f"[storeDIDonBlockchain()] Transaction Hash AFTERTX: {tx_hash}")

    signed_tx = w3_zk.eth.account.sign_transaction(tx_hash, private_key=wallet_prv_key)
    signed_tx_hash = w3_zk.eth.send_raw_transaction(signed_tx.raw_transaction)
    logs = (
        get_did_registry()
        .events.DIDRegistered()
        .get_logs(from_block=w3_zk.eth.block_number - 1)
    )
    # for log in logs:
    #     print(
    #         f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {log.args.did}\n\tIPFS_CID{log.args.ipfsCID}\n\tTX_HASH: {log.transactionHash.hex()}"
    #     )
    print(
        f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {logs[0].args.did}\n\tIPFS_CID{logs[0].args.ipfsCID}\n\tTX_HASH: {logs[0].transactionHash.hex()}"
    )

    # # Get contract instance
    # contract = get_did_registry()

    # # Build a tx
    # tx = contract.functions.registerDID(
    #     did, ipfs_did_hash, publicKey
    # ).build_transaction(
    #     {
    #         "chainId": 260,
    #         "gas": 2000000,
    #         "gasPrice": w3_zk.to_wei("20", "gwei"),
    #         "nonce": w3_zk.eth.get_transaction_count(wallet_addr),
    #         "from": wallet_addr,
    #         "to": get_did_registry().address,
    #         "data": get_did_registry().encode_abi(
    #             "registerDID", args=[did, ipfs_did_hash, publicKey]
    #         ),
    #     }
    # )

    # # Sign the tx
    # signed_tx = w3_zk.eth.account.sign_transaction(tx, private_key=wallet_prv_key)

    # # Send the tx
    # tx_hash = w3_zk.eth.send_raw_transaction(signed_tx.rawTransaction)

    # # Get the receipt
    # receipt = w3_zk.eth.get_transaction(tx_hash)

    # # Print the transaction hash for debugging purposes
    # if debug >= 1:
    #     print(f"[storeDIDonBlockchain()] Transaction Hash: {tx_hash.hex()}")
    #     print(f"[storeDIDonBlockchain()] Receipt: {receipt}")

    # Return the CID and the transaction hash
    return logs[0].args.did, logs[0].args.ipfsCID, logs[0].transactionHash.hex()


def storeVCOnBlockchain(did: str, vc: str):
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
    # NOTE:: TX is state changing,this func does not sign the transaction
    print(f"[storeVCOnBlockchain()] START:: Blockchain EXE")
    tx_hash = (
        get_vc_manager()
        .functions.issueVC(
            did,
            vc_hash,
            ifps_VC_CID,
        )
        .build_transaction(
            {
                "from": wallet_addr,
                # "to": get_did_registry().address,
                # "value": 1000000000000000000,
                "chainId": 270,
                "gas": 20000000,
                "gasPrice": w3_zk.to_wei("1", "gwei"),
                "nonce": w3_zk.eth.get_transaction_count(wallet_addr),
            }
        )
    )

    signed_tx = w3_zk.eth.account.sign_transaction(tx_hash, private_key=wallet_prv_key)
    signed_tx_hash = w3_zk.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"[storeDIDonBlockchain()] Transaction Hash AFTERTX: {tx_hash}")

    print(f"[storeVCOnBlockchain()] END:: Blockchain EXE")
    print(f"[storeVCOnBlockchain()] START:: Blockchain LOGFETCH")
    logs = (
        get_vc_manager()
        .events.VCIssued()
        .get_logs(from_block=w3_zk.eth.block_number - 1)
    )
    # for log in logs:
    #     print(
    #         f"[storeVConBlockchain()] Transaction Successful: \n\tDID: {log.args.did}\n\VC_HASH{log.args.vcHash}\n\tIPFS_CID: {log.args.ipfsCID}\n\tTX_HASH: {logs[0].transactionHash.hex()}"
    #     )
    if debug >= 1:
        if logs:
            print(
                f"[storeVConBlockchain()] Transaction Successful: \n\tDID: {logs[0].args.did}\n\tVC_HASH{logs[0].args.vcHash}\n\tIPFS_CID: {logs[0].args.ipfsCID}\n\tTX_HASH: {logs[0].transactionHash.hex()}"
            )
        else:
            print(f"[storeVConBlockchain()] Transaction LOGFETCH Failed: No logs found")
    print(f"[storeVCOnBlockchain()] END:: Blockchain LOGFETCH")

    # Return the CID and the transaction hash
    return (
        # logs[0].args.did,
        # logs[0].args.vcHash,
        # logs[0].args.ipfsCID,
        # logs[0].transactionHash.hex(),
        did,
        vc_hash,
        ifps_VC_CID,
        signed_tx_hash.hex()
    )


"""
Contract init functions
"""


# Return a DIDRegistry instance
def get_did_registry():
    contract_address, contract_abi = getContractZKsync("DIDRegistry")
    return w3_zk.eth.contract(address=contract_address, abi=contract_abi)


# Return a VerifiableCredentialManager instance
def get_vc_manager():
    contract_address, contract_abi = getContractZKsync("VerifiableCredentialManager")
    return w3_zk.eth.contract(address=contract_address, abi=contract_abi)


# Return a RSAAccumulator instance
def get_rsa_accumulator():
    contract_address, contract_abi = getContract("RSAAccumulatorVerifier")
    return w3.eth.contract(address=contract_address, abi=contract_abi)
