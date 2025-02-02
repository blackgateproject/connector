import asyncio
import base64
import json
import os
import random
from datetime import datetime

from didkit import didkit
from eth_keys import keys
from eth_utils import decode_hex

print(f"Hello from Python! didkit version: {didkit.get_version()}")

print(f"Attempt to test did:ethr")

# Generate a new keypair
# key = keys.PrivateKey(os.urandom(32))
key = keys.PrivateKey(
    decode_hex("44412651fa75acd96cd31b7c03166a22c64a173dea2bf1f81df141b0ac3d6dbe")
)
private_key = key.to_hex()
public_key_bytes = key.public_key.to_bytes()
public_key = key.public_key.to_hex()
public_key_bytes = key.public_key.to_bytes()

private_jwk = json.dumps(
    {
        "kty": "EC",
        "crv": "secp256k1",
        "d": base64.urlsafe_b64encode(bytes.fromhex(private_key[2:]))
        .decode()
        .rstrip("="),
        "x": base64.urlsafe_b64encode(public_key_bytes[:32]).decode().rstrip("="),
        "y": base64.urlsafe_b64encode(public_key_bytes[32:]).decode().rstrip("="),
    }
)
address = key.public_key.to_checksum_address()
print(
    f"Generated keypair: \nPRV:{private_key} \nPUB:{public_key} \nADDR:{address}\nJWK:{private_jwk}\n"
)


did_ethr = f"did:ethr:{address}"
print(f"Generated DID: {did_ethr}\n")


# Generate didDoc
async def resolve_did(did):
    return await didkit.resolve_did(did, "{}")


did_doc = asyncio.run(resolve_did(did_ethr))

print(f"Resolved DID Document: {did_doc}\n")

# Sign VC
credential = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "issuer": did_ethr,
    "credentialSubject": {"id": "did:example:123"},
    "issuanceDate": datetime.utcnow().isoformat() + "Z",
}

proof_options = json.dumps(
    {"proofPurpose": "assertionMethod", "verificationMethod": f"{did_ethr}#controller"}
)


# Sign using DIDKit
async def issue_cred(credential, proof_options, private_key):
    return await didkit.issue_credential(
        json.dumps(credential), proof_options, private_key
    )


signed_credential = asyncio.run(issue_cred(credential, proof_options, private_jwk))

print(f"Signed Credential: {signed_credential}\n")
