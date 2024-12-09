import json
import os
from datetime import datetime
from functools import lru_cache

import didkit
from fastapi import Depends
from typing_extensions import Annotated
from web3 import Web3

from ..core.config import Settings


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# Hardhat testnet, Check .env for URL Errors if any
w3 = Web3(Web3.HTTPProvider(settings_dependency().HARDHAT_URL))


def issue_vc(issuer: str, holder: str, credential_subject: dict, private_key: str):
    """
    Issue a W3C compliant Verifiable Credential (VC).
    """
    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "issuanceDate": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "credentialSubject": credential_subject,
    }
    vc_proof = didkit.issue_credential(json.dumps(vc), json.dumps({}), private_key)
    vc["proof"] = json.loads(vc_proof)
    return vc


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


# Get all accounts from hardhat testnet
def get_loaded_accounts():
    return w3.eth.accounts


# Parse accounts.json and return a list of w3 accounts
def get_accounts():
    with open("accounts.json", "r") as file:
        accounts = json.load(file)
    return accounts
