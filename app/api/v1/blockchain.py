import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ...core.config import Settings
from ...utils.web3_utils import getContract, settings_dependency, w3

# Initialize the API router
router = APIRouter()

@router.get("/")
async def health_check():
    """
    Blockchain Endpoint Health Check
    """
    return "Reached Blockchain Endpoint, Router Blockchain is Active"

@router.get("/contract-test")
async def contract_test():
    """
    Test Contract Endpoint
    """
    # Retrieve and concatenate contract information for multiple contracts
    contract = getContract("DIDRegistry")
    contract += getContract("RSAAccumulator")
    contract += getContract("VerifiableCredentialManager")
    return {"contract": contract}

@router.get("/currentAccumulator")
async def current_accumulator():
    """
    Get Current Accumulator
    """
    # Retrieve contract address and ABI for RSAAccumulator
    contract_address, contract_abi = getContract("RSAAccumulator")
    
    # Create a contract instance using web3
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_abi)
    
    # Call the getAccumulator function from the contract
    current_accumulator = contract_instance.functions.getAccumulator().call()
    
    # Convert the accumulator to a hexadecimal string
    current_accumulator = current_accumulator.hex()
    
    # Print the current accumulator for debugging purposes
    print(f"Current Accumulator: \n{current_accumulator}")
    
    # Return the accumulator in a JSON response
    return JSONResponse(content={"Accumulator": current_accumulator}, status_code=200)
