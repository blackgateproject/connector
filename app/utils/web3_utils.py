import hashlib
import json
import os
import time
from datetime import datetime, timezone
from functools import lru_cache

from eth_abi import decode as decode_abi
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi import Depends
from regex import F
from typing_extensions import Annotated
from web3 import Web3
from zksync2.account.wallet import Wallet
from zksync2.module.module_builder import ZkSyncBuilder
from zksync2.module.zksync_provider import ZkSyncProvider
from zksync2.signer.eth_signer import BaseAccount, PrivateKeyEthSigner

from ..core.accumulator import accumulatorCore
from ..core.config import Settings
from ..core.merkle import merkleCore
from ..core.sparseMerkleTree import smtCore


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().BLOCKCHAIN_RPC_URL))

debug = settings_dependency().DEBUG
zksyncNodeType = settings_dependency().ZKSYNC_NODE_TYPE
chain_id = settings_dependency().BLOCKCHAIN_CHAIN_ID
wallet_prv_key = ""
wallet_addr = ""
signer = None
wallet = None
if settings_dependency().BLOCKCHAIN_WALLET_ADDR:
    wallet_prv_key = settings_dependency().BLOCKCHAIN_WALLET_PRVT_KEY
    wallet_addr = settings_dependency().BLOCKCHAIN_WALLET_ADDR

    derived_addr = Account.from_key(wallet_prv_key).address

    # # Setup a zkSync wallet
    account: LocalAccount = Account.from_key(wallet_prv_key)
    # wallet = Wallet(account)

    if derived_addr != wallet_addr:
        print(
            f"Derived Address({derived_addr}) does not match the provided address({wallet_addr})"
        )

    if debug >= 0:
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
    elif contract_name not in ["Merkle", "RSAAccumulator"]:
        raise ValueError("Invalid contract name provided!")

    # Define the base directory (prefix path)
    # print(f"Current Directory: {os.getcwd()}")
    # print(f"Directory List: {os.listdir('./')}")
    # base_dir = "utils"

    # zksyncNodeType[dockerizedNode, anvilZKsync, zkSyncSepoliaTestnet, zkSyncSepoliaMainet]
    deployments_json_path = os.path.join(
        "app",
        "utils",
        "deployments-zk",
        zksyncNodeType,
        "contracts",
        f"{contract_name}.sol",
        f"{contract_name}.json",
    )

    if debug >= 0:
        print(f"Loading {contract_name} contract details...")
        print(f"  Deployments Path: {deployments_json_path}")

    # Load contract deployment json
    with open(deployments_json_path, "r") as contract_file:
        contract_data = json.load(contract_file)
        # if debug >= 0:
        # print(f"Contract Data: {json.dumps(contract_data)}")

    # Extract contract ABI
    contract_abi = contract_data.get("abi")

    # Extract contract address, txHash, constructorArgs
    for entry in contract_data.get("entries", []):
        contract_address = entry.get("address")
        txHash = entry.get("txHash")
        constructorArgs = entry.get("constructorArgs")

        # if debug >= 0:

        #     print(f"Contract Address: {contract_address}")
        #     print(f"Contract ABI: {contract_abi}")
        #     print(f"Transaction Hash: {txHash}")
        #     print(f"Constructor Args: {constructorArgs}")
        #     print("\n")

    # # Return both the contract address and ABI for further use

    if not contract_address:
        raise ValueError("Contract address not found in the deployment file!")
    elif not contract_abi:
        raise ValueError("Contract ABI not found in the deployment file!")

    return contract_address, contract_abi


# Read the merkle root from the merkle_verifier contract
async def getZKSyncMerkleRoot():
    """
    Get the merkle root from the contract
    """
    # Get the contract instance
    contract = get_merkle_verifier()

    # Call the getRoot function from the contract
    merkle_root = contract.functions.getMerkleRoot().call()

    if debug >= 0:
        print(f"[get_zkSync_merkle_root()] Merkle Root: {merkle_root}")

    return merkle_root


# Add user to the Merkle Tree Offchain and update the state Onchain
def addUserToMerkle(user: str, pw: str):
    """
    Add a user to the Merkle Tree
    """
    # Add the user to the Merkle Tree
    # print(f"[addUserToMerkle()] Old merkle root: {merkleCore.get_root()}")
    # print(f"[addUserToMerkle()] Adding to local merkle tree")
    userHashAndProof = merkleCore.add_user(user, pw)
    # print(f"[addUserToMerkle()] User Added to local merkle tree")
    # print(f"[addUserToMerkle()] Data Entries: {userHashAndProof}")
    # print(f"[addUserToMerkle()] New merkle root: {merkleCore.get_root()}")

    # Update the merkle root state onchain
    print(f"[addUserToMerkle()] Updating root onchain")
    root = str(merkleCore.get_root())
    built_tx = (
        get_merkle_verifier()
        .functions.storeMerkleRoot(root)
        .build_transaction(
            {
                "from": wallet_addr,
                "chainId": chain_id,
                "gas": 2000000,
                "gasPrice": w3.to_wei("1", "gwei"),
                "nonce": w3.eth.get_transaction_count(wallet_addr, "pending"),
            }
        )
    )
    print(f"[addUserToMerkle()] Built transaction: {built_tx}")
    signed_tx = w3.eth.account.sign_transaction(built_tx, private_key=wallet_prv_key)
    signed_tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"[addUserToMerkle()] Updated root onchain")
    # logs = (
    #     get_did_registry()
    #     .events.DIDRegistered()
    #     .get_logs(from_block=w3.eth.block_number - 1)
    # )
    # # for log in logs:
    # #     print(
    # #         f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {log.args.did}\n\tIPFS_CID{log.args.ipfsCID}\n\tTX_HASH: {log.transactionHash.hex()}"
    # #     )
    # print(
    #     f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {logs[0].args.did}\n\tIPFS_CID{logs[0].args.ipfsCID}\n\tTX_HASH: {logs[0].transactionHash.hex()}"
    # )

    # Print the transaction hash for debugging purposes
    if debug >= 0:
        # print(f"[addUserToMerkle()] Transaction Hash: {signed_tx}")
        print(f"[addUserToMerkle()] Transaction Hash: 0x{signed_tx_hash.hex()}")

    # Prepare return values
    data = {
        "userHash": userHashAndProof["hash"],
        "userProof": userHashAndProof["proof"],
        "merkleRoot": merkleCore.get_root(),
        "txHash": signed_tx_hash.hex(),
    }

    return data


# def verifyUserOnMerkle(hash: str, proof: list[str]):
def verifyUserOnMerkle(hash: str):
    """
    Verify a user on the Merkle Tree
    """
    # Verify the user on the Merkle Tree
    before_local_verify = time.time()
    proof = merkleCore.merkle_tree.get_proof(hash)
    validOffchain = merkleCore.verify_proof(hash, proof)
    local_verify_duration = time.time() - before_local_verify
    print(
        f"[verifyUserOnMerkle()] Local verification duration: {local_verify_duration:.4f} seconds"
    )
    # validOffchain = merkleCore.verify_proof(hash, proof)

    # [TEST] Verify the user on the blockchain by computing the proof
    # This should be moved to the frontend
    contract = get_merkle_verifier()
    before_onchain_verify = time.time()
    # Call the verifyProof function from the contract
    validOnchain = contract.functions.verifyProof(hash, proof).call()
    onchain_verify_duration = time.time() - before_onchain_verify
    print(
        f"[verifyUserOnMerkle()] Onchain verification duration: {onchain_verify_duration:.4f} seconds"
    )

    results = {
        "valid_Offchain": validOffchain,
        "valid_Onchain": validOnchain,
        "auth_Offchain_duration": local_verify_duration,
        "auth_Onchain_duration": onchain_verify_duration,
    }

    return results


"""
SMT Merkle functions
"""


# Add user to the Merkle Tree Offchain and update the state Onchain
def addUserToSMT(user: str, pw: str):
    """
    Add a user to the SMT Tree
    """
    # Add the user to the SMT Tree
    # print(f"[addUserToSMT()] Old SMT root: {SMTCore.get_root()}")
    # print(f"[addUserToSMT()] Adding to local SMT tree")
    userHashAndProof = smtCore.add_user(user, pw)
    # print(f"[addUserToSMT()] User Added to local SMT tree")
    # print(f"[addUserToSMT()] Data Entries: {userHashAndProof}")
    # print(f"[addUserToSMT()] New SMT root: {SMTCore.get_root()}")

    # Update the SMT root state onchain
    print(f"[addUserToSMT()] Updating root onchain disabled for now, need to uncomment")
    # root = str(smtCore.get_root())
    # built_tx = (
    #     get_merkle_verifier()
    #     .functions.storeMerkleRoot(root)
    #     .build_transaction(
    #         {
    #             "from": wallet_addr,
    #             "chainId": chain_id,
    #             "gas": 2000000,
    #             "gasPrice": w3.to_wei("1", "gwei"),
    #             "nonce": w3.eth.get_transaction_count(wallet_addr),
    #         }
    #     )
    # )
    # print(f"[addUserToSMT()] Built transaction: {built_tx}")
    # signed_tx = w3.eth.account.sign_transaction(built_tx, private_key=wallet_prv_key)
    # signed_tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    # print(f"[addUserToSMT()] Updated root onchain")
    # logs = (
    #     get_did_registry()
    #     .events.DIDRegistered()
    #     .get_logs(from_block=w3.eth.block_number - 1)
    # )
    # # for log in logs:
    # #     print(
    # #         f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {log.args.did}\n\tIPFS_CID{log.args.ipfsCID}\n\tTX_HASH: {log.transactionHash.hex()}"
    # #     )
    # print(
    #     f"[storeDIDonBlockchain()] Transaction Successful: \n\tDID: {logs[0].args.did}\n\tIPFS_CID{logs[0].args.ipfsCID}\n\tTX_HASH: {logs[0].transactionHash.hex()}"
    # )

    # Print the transaction hash for debugging purposes
    # if debug >= 0:
    #     # print(f"[addUserToMerkle()] Transaction Hash: {signed_tx}")
    #     print(f"[addUserToMerkle()] Transaction Hash: 0x{signed_tx_hash.hex()}")

    # Prepare return values
    # data = {
    #     "user_id": user,
    #     "merkleRoot": smtCore.get_root(),
    #     "stored_data": userHashAndProof,
    # }

    return userHashAndProof


# def verifyUserOnMerkle(hash: str, proof: list[str]):
def verifyUserOnSMT(user_id, key, credentials):
    """
    Verify a user on the SMT Tree
    """
    # Verify the user on the SMT Tree
    before_local_verify = time.time()
    # Commented this out, neeed a way to get proof
    validOffchain = smtCore.verify_user(user_id, key, credentials)
    local_verify_duration = time.time() - before_local_verify
    print(
        f"[verifyUserOnMerkle()] Local verification duration: {local_verify_duration:.4f} seconds"
    )
    # validOffchain = merkleCore.verify_proof(hash, proof)

    # [TEST] Verify the user on the blockchain by computing the proof
    # This should be moved to the frontend
    # contract = get_merkle_verifier()
    # before_onchain_verify = time.time()
    # # Call the verifyProof function from the contract
    # validOnchain = contract.functions.verifyProof(hash, proof).call()
    # onchain_verify_duration = time.time() - before_onchain_verify
    # print(
    #     f"[verifyUserOnMerkle()] Onchain verification duration: {onchain_verify_duration:.4f} seconds"
    # )

    # Remove this once the onchain verification is implemented
    validOnchain = True
    onchain_verify_duration = 99.0

    results = {
        "valid_Offchain": validOffchain,
        "valid_Onchain": validOnchain,
        "auth_Offchain_duration": local_verify_duration,
        "auth_Onchain_duration": onchain_verify_duration,
    }

    return results


def addUserToAccmulator(did: str, vc: str):
    # Combine the did and vc into json
    userW3creds = json.dumps({"did": did, "vc": vc})
    print(f"[addUserToAccmulator()] UserW3Creds: {userW3creds}")

    # convert the json to bytes
    userW3creds = userW3creds.encode("utf-8").hex()
    print(f"[addUserToAccmulator()] UserW3Creds: {type(userW3creds)}\t{userW3creds}")

    # Convert HexBytes to hex string before passing to accumulatorCore.add
    data = accumulatorCore.add(userW3creds)

    return data


# Function to verify the accumulator
def verifyUserOnAccumulator(dataHash: str, accVal: str, proof: str, prime: str):
    """
    Verify the user on the RSA accumulator
    """
    try:
        # Verify the user on the RSA accumulator

        print(f"[verifyUserOnAccumulator()] accVal: {accVal}")
        print(f"[verifyUserOnAccumulator()] proof: {proof}")
        print(f"[verifyUserOnAccumulator()] prime: {prime}")

        result = accumulatorCore.verify_membership(
            accVal=accVal, proof=proof, prime=prime
        )

        results = {
            "valid_Offchain": result,
            "valid_Onchain": True,
            "auth_Offchain_duration": 0,
            "auth_Onchain_duration": 0,
        }

    except Exception as e:
        print(f"[verifyUserOnAccumulator()] Error while verifying membership: {str(e)}")
        results = {
            "valid_Offchain": False,
            "valid_Onchain": False,
            "auth_Offchain_duration": 0,
            "auth_Onchain_duration": 0,
        }
    return results

    # try:
    #     contract = get_rsa_accumulator()

    #     # Ensure prime is 32 bytes long
    #     primeBytes = bytes.fromhex(prime[2:])
    #     if len(primeBytes) != 32:
    #         raise ValueError("Prime must be 32 bytes long")

    #     result = contract.functions.verify(proof, prime, accVal).transact({"from": wallet_addr})

    #     if debug >= 0:
    #         print(f"[verifyUserOnAccumulator()] Verification Result: {result}")

    #     return result

    # except Exception as e:
    #     print(f"Error while calling verify: {e}")
    #     return {"error": str(e)}


def getBlockchainModulus():
    """
    Get the modulus from the RSA accumulator contract
    """
    try:
        contract = get_rsa_accumulator()
        modulus = contract.functions.getModulus().call({"from": wallet_addr})

        # Convert the bytes modulus to a hex string
        modulus = f"0x{modulus.hex()}"

        if debug >= 0:
            print(f"[getBlockchainModulus()] Modulus: {modulus}")

        return modulus

    except Exception as e:
        print(f"Error while calling getModulus: {e}")
        return {"error": str(e)}


"""
Contract init functions
"""


# Returns the contract instance for the Merkle contract, used for verifying proofs
def get_merkle_verifier():
    contract_address, contract_abi = getContractZKsync("Merkle")
    return w3.eth.contract(address=contract_address, abi=contract_abi)


# Return a RSAAccumulator instance
def get_rsa_accumulator():
    contract_address, contract_abi = getContractZKsync("RSAAccumulator")
    return w3.eth.contract(address=contract_address, abi=contract_abi)
