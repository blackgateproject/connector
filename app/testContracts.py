import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache

import didkit
import web3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_keys import keys
from eth_utils import decode_hex
from fastapi import Depends
from fastapi.responses import JSONResponse
from gotrue import AuthResponse
from gotrue.types import AuthResponse
from supabase import Client, create_client
from supabase.client import AuthApiError
from supabase.lib.client_options import ClientOptions
from typing_extensions import Annotated
from web3 import Web3
from utils.web3_utils import getContractDetails, w3

getContractDetails("DIDRegistry")
