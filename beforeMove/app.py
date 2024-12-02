import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict
from uuid import UUID

from dotenv import load_dotenv
from eth_typing import HexStr
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import OAuth2PasswordBearer

# from gotrue.errors import AuthApiError
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlmodel import Session, SQLModel, create_engine, select
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from supabase.client import (
    AuthApiError,
    AuthSessionMissingError,
    AuthWeakPasswordError,
    NotConnectedError,
)
from supabase.lib.client_options import ClientOptions
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import settings
from model import Session, SignRequest, Token, User, VerifyRequest
from supabase import Client, create_client
from utils import (
    ALGORITHM,
    SECRET_KEY,
    extractUserInfo,
    generate_public_key,
    get_accounts,
    get_did,
    get_loaded_accounts,
    initialize_contract,
    json_serialize,
    print_user,
    register_did,
    revoke_did,
    verify_signature,
)

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


@app.get("/auth/v1/getUsers")
async def getUsers():
    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_SERV_KEY"),
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )

    try:
        # Fetch users from Supabase (admin API for listing users)
        users_response = supabase.auth.admin.list_users(page=1, per_page=100)

        # Check the structure of the response (print it for inspection)
        print(f"Users Response: {users_response}")

        # The response might be a list of User objects. We need to serialize them.
        users = users_response  # The response is a list of User objects

        # Serialize user data to JSON-friendly format
        serialized_users = []
        for user in users:
            serialized_user = {
                "id": user.id,
                "app_metadata": json_serialize(user.app_metadata),
                "user_metadata": json_serialize(user.user_metadata),
                "aud": user.aud,
                "confirmation_sent_at": json_serialize(user.confirmation_sent_at),
                "recovery_sent_at": json_serialize(user.recovery_sent_at),
                "email_change_sent_at": json_serialize(user.email_change_sent_at),
                "new_email": user.new_email,
                "new_phone": user.new_phone,
                "invited_at": json_serialize(user.invited_at),
                "action_link": user.action_link,
                "email": user.email,
                "phone": user.phone,
                "created_at": json_serialize(user.created_at),
                "confirmed_at": json_serialize(user.confirmed_at),
                "email_confirmed_at": json_serialize(user.email_confirmed_at),
                "phone_confirmed_at": json_serialize(user.phone_confirmed_at),
                "last_sign_in_at": json_serialize(user.last_sign_in_at),
                "role": user.role,
                "updated_at": json_serialize(user.updated_at),
                "identities": json_serialize(user.identities),
                "is_anonymous": user.is_anonymous,
                "factors": json_serialize(user.factors),
            }
            serialized_users.append(serialized_user)

        # Print the serialized user data
        print(f"Serialized Users: {serialized_users}")

        # Initialize the list to hold the return users
        returnUsers = []

        # Loop through serialized users
        for user in serialized_users:
            # Print User id for debugging
            print(f"User ID: {user['id']}")

            if user["user_metadata"] == {}:  # Check if user_metadata is empty
                print(f"No User Metadata for {user['id']}")
                returnUser = {
                    "id": user["id"],
                    "firstName": user[
                        "email"
                    ],  # Using email as first name for users without metadata
                    "secondName": "",  # No second name if no metadata
                    # Set online to true if last_sign_in_at was 5 mins ago. time is stored as 2024-12-01T20:53:27.176864+00:00
                    "online": (
                        True
                        if user["last_sign_in_at"]
                        > datetime.now(timezone.utc) - timedelta(minutes=5)
                        else False
                    ),  # Check if the user is authenticated
                }
                # Append the return user to the list
                returnUsers.append(returnUser)
                print(f"Return USR: \n{returnUser}")
            else:
                # User has metadata, so extract first and last names
                returnUser = {
                    "id": user["id"],
                    "firstName": user["user_metadata"].get(
                        "firstName", ""
                    ),  # Safely get firstName or empty string
                    "secondName": user["user_metadata"].get(
                        "lastName", ""
                    ),  # Safely get lastName or empty string
                    "online": (
                        True if user["aud"] == "authenticated" else False
                    ),  # Check if the user is authenticated
                }

                # Append the return user to the list
                returnUsers.append(returnUser)
                print(f"Return USR: \n{returnUser}")

        # Debug print the return users list
        print(f"Return OBJ: \n{returnUsers}")

        # Return the JSON response with the serialized user data
        return JSONResponse(
            content=returnUsers,
            status_code=200,
        )
    except Exception as e:
        print(f"General Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
    except AuthApiError as e:
        print(f"Auth Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=401)


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


"""
##############################################
############### PROFILE ROUTES ###############
##############################################
"""


@app.post("/aurora/aurora/api/profile/")
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


@app.get("/aurora/api/users")
async def get_all_users(session: SessionDep):
    users = session.exec(select(User)).all()
    return users


@app.get("/aurora/api/users/active")
async def get_active_users(session: SessionDep):
    active_users_count = len(
        session.exec(select(User).where(User.isOnline == True)).all()
    )
    return {"active_users": active_users_count}


@app.delete("/aurora/api/users/{user_id}")
async def delete_user(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        return HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"success": True}


@app.put("/aurora/api/users/{user_id}")
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

"""
################################################################
######################## JWT AUTH TOKEN ########################
################################################################
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


"""
################################################################
################################################################
################################################################
"""


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


@app.post("/aurora/api/auth/password/register")
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


@app.get("/aurora/api/auth/PKI/challenge")
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


@app.post("/aurora/api/auth/PKI/sign")
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
