import hashlib
import json
import os
from datetime import datetime, timezone
from functools import lru_cache

import didkit
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi import Depends
from typing_extensions import Annotated
from web3 import Web3
from zksync2.module.module_builder import ZkSyncBuilder
from zksync2.signer.eth_signer import PrivateKeyEthSigner,BaseAccount
from zksync2.account.wallet import Wallet
from zksync2.module.zksync_provider import ZkSyncProvider
from ..core.config import Settings
from ..core.merkle import merkleCore


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().BLOCKCHAIN_RPC_URL))

debug = settings_dependency().DEBUG

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
    elif contract_name not in ["Merkle"]:
        raise ValueError("Invalid contract name provided!")

    # Define the base directory (prefix path)
    base_dir = r"..\..\blockchain"

    # zksyncNodeType[dockerizedNode, anvilZKsync, zkSyncSepoliaTestnet, zkSyncSepoliaMainet]
    zksyncNodeType = "zkSyncSepoliaTestnet"
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

        # if debug >= 4:

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

    if debug >= 2:
        print(f"[get_zkSync_merkle_root()] Merkle Root: {merkle_root}")

    return merkle_root

# Add user to the Merkle Tree Offchain and update the state Onchain
def addUserToMerkle(user: str, pw: str):
    """
    Add a user to the Merkle Tree
    """
    # Add the user to the Merkle Tree
    # print(f"[addUserToMerkle()] Old merkle root: {merkleCore.get_root()}")
    userHashAndProof = merkleCore.add_user(user, pw)
    # print(f"[addUserToMerkle()] Data Entries: {userHashAndProof}")
    # print(f"[addUserToMerkle()] New merkle root: {merkleCore.get_root()}")

    # Update the merkle root state onchain
    root = str(merkleCore.get_root())
    built_tx = get_merkle_verifier().functions.storeMerkleRoot(root).build_transaction({
        "from": wallet_addr,
        "chainId": 300,
        "gas": 2000000,
        "gasPrice": w3.to_wei("1", "gwei"),
        "nonce": w3.eth.get_transaction_count(wallet_addr),
    })
    signed_tx = w3.eth.account.sign_transaction(built_tx, private_key=wallet_prv_key)
    signed_tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
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
    if debug >= 1:
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


def verifyUserOnMerkle(hash: str, proof: list[str]):
    """
    Verify a user on the Merkle Tree
    """
    # Verify the user on the Merkle Tree
    validOffchain = merkleCore.verify_proof(hash, proof)


    # [TEST] Verify the user on the blockchain by computing the proof
    # This should be moved to the frontend
    contract = get_merkle_verifier()
    # Call the verifyProof function from the contract
    validOnchain = contract.functions.verifyProof(hash, proof).call()

    results = {
        "valid_Offchain": validOffchain,
        "valid_Onchain": validOnchain,
    }

    return results


"""
Contract init functions
"""


# Returns the contract instance for the Merkle contract, used for verifying proofs
def get_merkle_verifier():
    contract_address, contract_abi = getContractZKsync("Merkle")
    return w3.eth.contract(address=contract_address, abi=contract_abi)
