import base64
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, List, Optional
from uuid import UUID

import fastapi
import web3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from eth_keys import keys
from eth_typing import HexStr
from eth_utils import decode_hex
from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request,
                     UploadFile, status)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.responses import (FileResponse, JSONResponse, RedirectResponse,
                               Response)
from fastapi.security import OAuth2PasswordBearer
from gotrue import AuthResponse
from gotrue.errors import AuthApiError
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import settings
from supabase import Client, create_client

# CORS Configuration
origins = [
    # "http://localhost:5173",
    # "http://localhost:5174",
    # "http://localhost:8000",
    "*"
]

# Secret key for encoding and decoding JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# List to store logged in users
logged_in_users = []

# Debug flag for print statements
debug = True


# Database setup
sqlite_file_name = "./awais_database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


"""
MODEL.PY 
"""


class UserIdentity(BaseModel):
    id: UUID
    identity_id: UUID
    user_id: UUID
    identity_data: dict  # This can be expanded if specific fields are known, like email, phone_verified, etc.
    provider: str
    created_at: datetime
    last_sign_in_at: datetime
    updated_at: datetime


class User(BaseModel):
    id: UUID
    app_metadata: dict
    user_metadata: dict
    aud: str
    confirmation_sent_at: Optional[datetime]
    recovery_sent_at: Optional[datetime]
    email_change_sent_at: Optional[datetime]
    new_email: Optional[EmailStr]
    new_phone: Optional[str]
    invited_at: Optional[datetime]
    action_link: Optional[str]
    email: EmailStr
    phone: Optional[str]
    created_at: datetime
    confirmed_at: datetime
    email_confirmed_at: datetime
    phone_confirmed_at: Optional[datetime]
    last_sign_in_at: datetime
    role: str
    updated_at: datetime
    identities: List[UserIdentity]
    is_anonymous: bool
    factors: Optional[List[str]]


class Session(BaseModel):
    provider_token: Optional[str]
    provider_refresh_token: Optional[str]
    access_token: str
    refresh_token: str
    expires_in: int
    expires_at: int
    token_type: str
    user: User


# Models
class User1(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    username: str
    email: str
    phone: str
    password_hash: str
    public_key: str = Field(nullable=True)
    private_key: str = Field(nullable=True)
    blockchain_address: str = Field(nullable=True)
    role: str
    did: str = Field(nullable=True)
    access_token: str = Field(default=None, nullable=True)
    isPWLess: bool
    isOnline: bool


class LoginRequest(BaseModel):
    username: str
    password: str  # This field is still required for password-based users


class Token(BaseModel):
    access_token: str
    token_type: str


class ChallengeRequest(BaseModel):
    address: str  # Ethereum address for the challenge


# SignRequest schema
class SignRequest(BaseModel):
    address: str
    message: str
    signature: str


class VerifyRequest(BaseModel):
    address: str  # Ethereum address
    message: str  # Message to be verified
    signature: str  # Signed message


class RegisterDID(BaseModel):
    user: str
    public_key: str


class IssueVC(BaseModel):
    holder: str
    credential_hash: str


class RevokeVC(BaseModel):
    holder: str
    credential_hash: str


"""
UTILS.PY
"""

"""
This file will house most of the util 
functions required by the server
"""


SECRET_KEY = "SomeVerySecretKeyHena"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token expiry time
# Web3 setup
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))  # Adjust the provider as needed


# Parse the AuthResponse returned after auth operations
# Used here to extract all the relevant attributes
def extractUserInfo(user: AuthResponse):

    user_id = user.user.id
    # login_time = datetime.now(timezone.utc)

    # Extract user information
    user_data = {
        "id": user_id,
        "app_metadata": user.user.app_metadata,
        "user_metadata": user.user.user_metadata,
        "aud": user.user.aud,
        "confirmation_sent_at": user.user.confirmation_sent_at,
        "recovery_sent_at": user.user.recovery_sent_at,
        "email_change_sent_at": user.user.email_change_sent_at,
        "new_email": user.user.new_email,
        "new_phone": user.user.new_phone,
        "invited_at": user.user.invited_at,
        "action_link": user.user.action_link,
        "email": user.user.email,
        "phone": user.user.phone,
        "created_at": user.user.created_at,
        "confirmed_at": user.user.confirmed_at,
        "email_confirmed_at": user.user.email_confirmed_at,
        "phone_confirmed_at": user.user.phone_confirmed_at,
        "last_sign_in_at": user.user.last_sign_in_at,
        "role": user.user.role,
        "updated_at": user.user.updated_at,
        "identities": [
            {
                "id": identity.id,
                "identity_id": identity.identity_id,
                "user_id": identity.user_id,
                "identity_data": identity.identity_data,
                "provider": identity.provider,
                "created_at": identity.created_at,
                "last_sign_in_at": identity.last_sign_in_at,
                "updated_at": identity.updated_at,
            }
            for identity in user.user.identities
        ],
        "is_anonymous": user.user.is_anonymous,
        "factors": user.user.factors,
    }

    return user_data


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


# Print the user object
def print_user(user: User):
    print(f"User {user.username} ({user.email})")
    # print(f"  ID: {user.id}")
    print(f"  Phone Number: {user.phone}")
    print(f"  Role: {user.role}")
    print(f"  DID: {user.did}")
    print(f"  Is Passwordless: {user.isPWLess}")
    if user.isPWLess:
        print(f"  Public Key: {user.public_key}")
        print(f"  Private Key: {user.private_key}")
        print(f"  Blockchain Address: {user.blockchain_address}")
    print(f"  Is Online: {user.isOnline}")
    print()


# Get all accounts from hardhat testnet
def get_loaded_accounts():
    return w3.eth.accounts


# Parse accounts.json and return a list of w3 accounts
def get_accounts():
    with open("accounts.json", "r") as file:
        accounts = json.load(file)
    return accounts


"""
MAIN.PY
"""
SessionDep = Annotated[Session, Depends(get_session)]

# In-memory storage for challenges
challenges = {}


# Print Hello message on server startup and Bye on server shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n\n===== Server Up =====\n\n")
    # Load environment variables
    load_dotenv("./.env")
    create_db_and_tables()

    # Fetch Supabase URL and Key from ENV vars
    try:
        supaURL = settings.SUPABASE_URL
        supaANONKey = settings.SUPABASE_ANON_KEY
        supaSERVKey = settings.SUPABASE_SERV_KEY

        print(
            f"SUPABASE_URL: {supaURL}\nSUPABASE_ANON_KEY: {supaANONKey}\nSUPABASE_SERV_KEY: {supaSERVKey}"
        )
    except KeyError:
        print("ERR: Supabase URL or Key not found in ENV vars")
    yield
    print("\n\n===== Server Shutting down! =====\n\n")


# Main entrypoint
app = FastAPI(lifespan=lifespan)


# Web3 setup
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))  # Hardhat testnet

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/functions/v1/verifyUser/")
async def verify_user(request: Request):
    body = await request.json()
    email = body.get("email")
    pw = body.get("password")

    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )

    try:
        # Attempt to sign in with email and password
        user = supabase.auth.sign_in_with_password({"email": email, "password": pw})

        # print User
        # if debug:
        # print(f"User Data from Supabase: \n{user}")

        # Run Attr extraction
        user_data = extractUserInfo(user)

        # Check if user is already logged in (ensure the check is using UUID comparison)
        if any(UUID(user_data["id"]) == user.id for user in logged_in_users):
            raise Exception("User is already logged in")

        # Convert the user data to Pydantic User model
        user_instance = User(**user_data)

        # Store the user in the logged_in_users list
        logged_in_users.append(user_instance)

        # Print logged-in user information
        if debug:
            print(f"Added user to local store: \n{user_instance}")

        # Return authenticated response
        return JSONResponse(
            content={
                "authenticated": True,
                "role": email.split("@")[1].split(".")[0],
                "uuid": user_data["id"],
            },
            status_code=200,
        )
    except AuthApiError as e:
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=401
        )
    except Exception as e:
        if "WinError 10061" in str(e):
            return JSONResponse(
                content={
                    "authenticated": False,
                    "error": "Supabase docker image is down/not responding",
                },
                status_code=500,
            )
        elif "User is already logged in" in str(
            e
        ):  # Check if the user is already logged in
            return JSONResponse(
                content={
                    "authenticated": True,
                    "role": email.split("@")[1].split(".")[0],
                    "uuid": user_data["id"],
                    "error": "User is already logged in",
                },
                status_code=200,
            )
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@app.get("/functions/v1/getUsers")
async def getUsers():
    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )

    try:
        # Sign in as Anon user and fetch user table and its contents
        # NOTE:: This will not work as the auth table itself is not directly accessible via the API.
        #        Need to use Database queries ig to process and send the data forward
        data = supabase.table("users").select("*", count="exact").execute()
        # Serialize the data to JSON, might not be needed but better safe than sorry
        jsonData = json.dumps(data.data)

        print(f"Data Count: {data.count}")
        print(f"Data: {jsonData}")

        # Return authenticated response
        return JSONResponse(
            content={
                "authenticated": True,
                # "role": email.split("@")[1].split(".")[0],
                # "uuid": user_data["id"],
            },
            status_code=200,
        )
    except Exception as e:
        if "WinError 10061" in str(e):
            return JSONResponse(
                content={
                    "authenticated": False,
                    "error": "Supabase docker image is down/not responding",
                },
                status_code=500,
            )
        else:
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=500
            )


# @app.get("/functions/v1/getLoggedUsers/")
# async def get_logged_users():
#     print("Logged In users")
#     # Iterate over the logged_in_users list and print the user information sequentially
#     for user in logged_in_users:
#         print(f"User: {user}\n")
#     # return JSONResponse(content={"logged_in_users": [user.dict() for user in logged_in_users]}, status_code=200)


# Route to signout a user that browser holds the uuid for. NOT COMPLETE YET
@app.post("/functions/v1/signout/")
async def signout_user(request: Request):
    body = await request.json()
    user_id = body.get("user_id")

    global logged_in_users
    logged_in_users = [user for user in logged_in_users if user.id != user_id]

    # Sign out from supabase
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )
    response = supabase.auth.sign_out(user_id)
    print(response)

    return JSONResponse(content={"signed_out": True}, status_code=200)


"""
##############################################################################
"""


"""
##############################################
############### PROFILE ROUTES ###############
##############################################
"""


@app.post("/api/profile/")
async def get_user_profile(request: Request, session: SessionDep):
    # Assume since the user is logged in, the token is valid
    body = await request.json()
    token = body.get("token")
    print(f"token: {token}")

    # Get the user from the database based on the token
    with Session(engine) as session:
        statement = select(User).where(User.access_token == token)
        user = session.exec(statement).first()

    print(f"IN USER PROFILE")
    # Get the DID from the blockchain
    print(f"User Address: {user.blockchain_address}")
    did = "Couldnt find from Blockchain"
    if user.isPWLess:
        did = get_did(HexStr(user.blockchain_address))
    else:
        did = "Passwordless not enabled"
    print(f"User DID: {did}")

    # Load user profile into User Object
    user = {
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "public_key": user.public_key if user.isPWLess else "Passwordless not enabled",
        "private_key": (
            user.private_key if user.isPWLess else "Passwordless not enabled"
        ),
        "blockchain_address": (
            user.blockchain_address if user.isPWLess else "Passwordless not enabled"
        ),
        "role": user.role,
        "isPWLess": user.isPWLess,
        "isOnline": user.isOnline,
        "did": did if user.isPWLess else "Passwordless not enabled",
    }

    print(user)

    return JSONResponse(status_code=200, content=user)


"""
##############################################
######## ADMIN DASHBOARD ROUTES ##############
##############################################
"""


@app.get("/api/users")
async def get_all_users(session: SessionDep):
    users = session.exec(select(User)).all()
    return users


@app.get("/api/users/active")
async def get_active_users(session: SessionDep):
    active_users_count = len(
        session.exec(select(User).where(User.isOnline == True)).all()
    )
    return {"active_users": active_users_count}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        return HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"success": True}


@app.put("/api/users/{user_id}")
async def update_user(user_id: int, user_data: dict, session: SessionDep):
    """
    Update a user's information based on the user_id and the new data provided in the request body.
    """
    # Fetch user from the database
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    print(f"Updating user ({user.email})")
    print(f"Changes:")

    # Update user attributes based on the user_data
    for key, value in user_data.items():
        if hasattr(user, key):  # Only update valid attributes
            old_value = getattr(user, key)
            setattr(user, key, value)
            if old_value != value:
                print(f"  {key}: {old_value} -> {value}")

    # If the user is passwordless, generate keys
    if user.isPWLess:
        print(f"Checking if any address is available")

        accounts = get_accounts()
        address = None
        private_key = None

        # Get the list of existing users with blockchain addresses
        users_in_db = session.exec(select(User)).all()

        for account in accounts:
            # Ensure the address is not already in use
            if account["account"] not in [
                user.blockchain_address for user in users_in_db
            ]:
                address = account["account"]
                private_key = account["privateKey"]
                break

        if not address:
            return {"success": False, "error": "No available accounts."}

        # Generate the public key from the private key
        public_key = generate_public_key(private_key, isBase64=False, isPEM=False)

        # Register DID
        did = f"did:key:{address[2:]}"
        print(f"Checking if DID exists: {did}")
        try:
            get_did(address=HexStr(address))
        except ContractLogicError or ValueError as e:
            print(f"Error: {e}")
            print(f"Registering DID: {did}")
            register_did(address=address, did=did)
        # Update user blockchain-related fields
        user.did = did
        user.blockchain_address = address
        user.private_key = private_key
        user.public_key = public_key

        print(
            f"SUCCESS! Generated:\n Address: {address}\n Private Key: {private_key}\n Public Key: {public_key}\n DID: {did}"
        )

    elif not user.isPWLess:
        # Clear blockchain-related fields if not passwordless
        user.public_key = None
        user.private_key = None
        user.blockchain_address = None

    # Add and commit the changes to the database
    session.add(user)
    session.commit()  # Ensure changes are committed to DB
    session.refresh(user)  # Refresh the user object to get the latest data from DB

    return {"success": True, "user": user}


"""
##############################################
####### PASSWORD-BASED AUTHENTICATION ########
##############################################
"""


def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        print(f"[VRFY_TKN] TOKEN email: {email}")
        if email is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return email
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")


@app.post("/verify-token")
async def verify_user_token(request: Request):
    try:
        body = await request.json()
        print(f"[VRFY_TKN] Body: {body}")
        token = body.get("token")
        print(f"Verifying token: {token}")
        email = verify_token(token=token)
        # Set the rest of the users to offline
        with Session(engine) as session:
            statement = select(User).where(User.email != email)
            users = session.exec(statement).all()
            for user in users:
                user.isOnline = False
                session.add(user)
                session.commit()
                session.refresh(user)

        # Set Token in the DB
        with Session(engine) as session:
            statement = select(User).where(User.email == email)
            user = session.exec(statement).first()
            user.access_token = token
            user.isOnline = True
            session.add(user)
            session.commit()
            session.refresh(user)

        return JSONResponse(status_code=200, content="Token is valid")
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content="Error verifying token.")


# Helper function to create the JWT token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/token", response_model=Token)
async def login_for_access_token(request: Request, db: Session = Depends(get_session)):

    # Grab the role from the request body
    body = await request.json()
    role = body.get("email").split("@")[1].split(".")[0]

    # Use the existing `verify_password` function for user authentication
    authentication_result = await verify_password(request, db)

    print(f"Authentication Result: {authentication_result}")

    if not authentication_result.get("authenticated"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=authentication_result.get("error", "Invalid credentials"),
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If authentication is successful, return the token
    return JSONResponse(
        content={
            "access_token": authentication_result["access_token"],
            "role": role,
            "token_type": "bearer",
        }
    )


# Function to verify password and authenticate user
async def verify_password(request: Request, db: Session) -> Dict:
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    print(f"[VRFY_PW] Body: {body}")

    if not email or not password:
        return {"authenticated": False, "error": "Missing email or password in BODY"}

    # Query user from the database
    statement = select(User).where(User.email == email)
    user = db.exec(statement).first()

    # If user not found or password is incorrect, return error
    if not user or password != user.password_hash:
        return {"authenticated": False, "error": "Invalid email or password"}

    # if not user or not pwd_context.verify(
    #     password, user.password_hash
    # ):  # Use bcrypt to verify password hash
    #     return {"authenticated": False, "error": "Invalid email or password"}

    role = email.split("@")[1].split(".")[0]
    if role not in ["admin", "user"]:
        role = "user"

    # Generate JWT token
    access_token = create_access_token(data={"sub": user.email, "role": role})

    return {
        "authenticated": True,
        "access_token": access_token,
        "role": role,
    }


@app.post("/api/auth/password/register")
async def register_user(request: Request):
    try:
        body = await request.json()
        username = body.get("username")
        email = body.get("email")
        phoneNumber = body.get("phone")
        role = body.get("role")
        password = body.get("password")
        isPWLess = body.get("isPWLess", False)

        print(
            f"Got in Body:\n Username: {username}\n Email: {email}\n Phone: {phoneNumber}\n Role: {role}\n Password: {password}\n isPWLess: {isPWLess}"
        )

        # Check if user already exists, then return error
        with Session(engine) as session:
            statement = select(User).where(User.email == email)
            user = session.exec(statement).first()

        if user:
            return {"success": False, "error": "User already exists."}

        user = User(
            username=username,
            email=email,
            phone=phoneNumber,
            password_hash=password,
            role=role,
            isPWLess=False,  # Only enable passwordless when user triggers it
            isOnline=False,
        )

        print_user(user)
        try:
            with Session(engine) as session:
                session.add(user)
                session.commit()
                session.refresh(user)
        except Exception as e:
            print(e)
            return JSONResponse(status_code=400, content="Error registering user.")

        return {"success": True}
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content="Error registering user.")


"""
#############################################
######## PASSWORDLESS AUTHENTICATION ########
#############################################
"""


@app.get("/api/auth/PKI/challenge")
async def get_challenge(address: str):
    if not w3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address.")

    # Generate a random challenge for the user
    challenge = secrets.token_hex(32)
    challenges[address] = challenge
    print(f"Generated challenge for {address}: {challenge}")
    return {"message": challenge}


# Helper function to verify the signature (updated to work with message hash and Ethereum prefix)
def verify_signature(message: str, signature: str, address: str, web3: Web3) -> bool:
    try:
        # Ensure the message is a hex string, if not, raise an error
        if message.startswith("0x"):
            message_bytes = bytes.fromhex(
                message[2:]
            )  # Convert from hex to bytes (ignore '0x')
        else:
            # If it's a string message, encode it as bytes
            message_bytes = message.encode("utf-8")

        # Step 1: Hash the message
        message_hash = web3.solidity_keccak(
            ["bytes"], [message_bytes]
        )  # keccak256 of the message

        # Step 2: Prefix the message hash with the Ethereum message prefix
        prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
        prefixed_hash = web3.solidity_keccak(
            ["bytes", "bytes"], [prefix, message_bytes]
        )

        # Step 3: Recover the address from the signature
        recovered_address = web3.eth.account._recover_hash(
            prefixed_hash, signature=signature
        )

        # Step 4: Compare the recovered address with the provided address
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(f"Error: {e}")
        return False


@app.post("/api/auth/PKI/sign")
async def sign_message(request: Request):
    body = await request.json()
    address = body.get("address")
    message = body.get("message")
    originalMessage = challenges.get(address)  # This is the original challenge message
    signature = body.get("signature")

    print(f"Original Message: {originalMessage} {type(originalMessage)}")
    print(f"Message:          {message} {type(message)}")
    print(f"Message Length: {len(message)}")
    print(f"Signature: {signature}")

    if not message or message != originalMessage:
        raise HTTPException(status_code=400, detail="Invalid challenge or address.")

    # Verify the signature using the message hash with Ethereum prefix
    is_valid = verify_signature(message, signature, address, w3)

    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid signature.")

    return {"authenticated": True, "message": "Signature is valid, user authenticated."}
