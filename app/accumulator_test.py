import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__)))
from core.accumulator import AccumulatorClass
from utils.accumulator_utils import *



# Assuming that `AccumulatorClass` is already implemented as you've shown.
acc = AccumulatorClass()

# Step 1: Set up the accumulator
modulus, generator, secrets_dict = acc.setup()

print(
    f"SETUP: \n\tModulus = {to_padded_num_str(modulus, 384)}\n\tGenerator = {to_padded_num_str(generator, 384)}\n\tSecretsDICT() = {acc.SECRETS_DICT}"
)

values = [
    "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6",
    "ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5",
    "2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de",
    "13600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060",
]

# Step 2: Add elements to the accumulator
# Adding 4 elements (hashes of data represented as strings here)
accVal1, val1Proof, prime1 = acc.add(generator, values[0])
accVal2, val2Proof, prime2 = acc.add(accVal1, values[1])
accVal3, val3Proof, prime3 = acc.add(accVal2, values[2])
accVal4, val4Proof, prime4 = acc.add(accVal3, values[3])

# # Print out the added accumulator values
print(
    f"ADD: \n\tValue1 = {to_padded_num_str(accVal1, 384)}\n\tValue2 = {to_padded_num_str(accVal2, 384)}\n\tValue3 = {accVal3}\n\tValue4 = {accVal4}"
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
