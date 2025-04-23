"""
Test reveals the following steps to sign the user up and then verify their creds. Context:: Connector + Blockchain
Assume accumulator class is already setup

===== User Registration ======
call acc.add("keccak256(user data)")
acc.add returns a tuple (accVal, proof, prime)
send accVal to blockchain to update accumulator
send accVal, proof, prime to user to present when theyre verifying their creds

===== User Verification ======
user provides accVal, proof, prime
better yet, user themselves perform this transaction, send the tx id to connector
connector verifies this transaction against user's address

"""

import os
import sys

from Crypto.Hash import keccak
from web3 import Web3

sys.path.append(os.path.join(os.path.dirname(__file__)))
from core.accumulator import AccumulatorClass
from utils.accumulator_utils import *

acc = AccumulatorClass()

# Step 1: Set up the accumulator
# modulus, generator, secrets_dict = acc.setup()

modulus = acc.MODULUS
generator = acc.GENERATOR
secrets_dict = acc.SECRETS_DICT

print(
    f"SETUP: \n\tModulus = {to_padded_num_str(modulus, 384)}\n\tGenerator = {to_padded_num_str(generator, 384)}\n\tSecretsDICT() = {acc.SECRETS_DICT}"
)
# print(
#     f"SETUP: \n\tModulus = {modulus}\n\tGenerator = {generator}\n\tSecretsDICT() = {acc.SECRETS_DICT}"
# )


# Create a new values array, call it value1 and fill it with the hash of the data
values = ["1", "2", "3", "4"]
# for i in range(4):
# values[i] = Web3.solidity_keccak(["string"], [values[i]]).hex()
print(f"VALUES: {values}")

# Step 2: Add elements to the accumulator
# Adding 4 elements (hashes of data represented as strings here)
accVal1, val1Proof, prime1 = acc.add(generator, values[0])
accVal2, val2Proof, prime2 = acc.add(accVal1, values[1])
accVal3, val3Proof, prime3 = acc.add(accVal2, values[2])
accVal4, val4Proof, prime4 = acc.add(accVal3, values[3])

# # Print out the added accumulator values
print(
    f"ADD: \n\tValue1 = {to_padded_num_str(accVal1, 384)}\n\tValue2 = {to_padded_num_str(accVal2, 384)}\n\tValue3 = {to_padded_num_str(accVal3, 384)}\n\tValue4 = {to_padded_num_str(accVal4, 384)}"
)

# print(f"ADDED Val1, Val2, Val3, Val4\n\n")

# Print out the proofs for 3rd and 4th values
# print(f"\nProof for value3: {val3Proof}")
# print(f"Proof for value4: {val4Proof}")

# Step3.5: Print out the secret_dict after it got updated
print(f"\nSECRET_DICT: {acc.SECRETS_DICT}\n")

# Step 4: Verify the proofs
# You will need the original values and their respective proofs to verify the membership
is_verified_1 = acc.verify_membership(
    accVal1,
    values[0],
    val1Proof,
)
is_verified_2 = acc.verify_membership(
    accVal2,
    values[1],
    val2Proof,
)
is_verified_3 = acc.verify_membership(
    accVal3,
    values[2],
    val3Proof,
)
is_verified_4 = acc.verify_membership(
    accVal4,
    values[3],
    val4Proof,
)

print(f"Verification for value1: {is_verified_1}")
print(f"Verification for value2: {is_verified_2}")
print(f"Verification for value3: {is_verified_3}")
print(f"Verification for value4: {is_verified_4}")
