# This file is used to generate a proof for the RSAAccumulator smart contract
import secrets
import sys

from helpfunctions import hash_to_prime
from main import add, generate_proof, setup


def to_padded_num_str(num, length_in_bytes):
    length_in_hex_str = length_in_bytes * 2 + 2
    num_str = format(num, "#0" + str(length_in_hex_str) + "x")
    return num_str


modulus, initial_accumulator, secrets_dict = setup()

element1 = secrets.randbelow(pow(2, 256))
accumulator1 = add(initial_accumulator, secrets_dict, element1, modulus)
proof1, prime1 = generate_proof(element1, initial_accumulator, secrets_dict, modulus)

element2 = secrets.randbelow(pow(2, 256))
accumulator2 = add(accumulator1, secrets_dict, element2, modulus)
proof2, prime2 = generate_proof(element2, accumulator1, secrets_dict, modulus)

print(f"\nModulus:\n{to_padded_num_str(modulus, 384)}")
print(f"\nInitial Accumulator:\n{to_padded_num_str(initial_accumulator, 384)}")
print(f"\nProof1: \n{to_padded_num_str(proof1, 384)}")
print(f"\nPrime1: \n{to_padded_num_str(prime1, 32)}")
print(f"\nAccumulator1: \n{to_padded_num_str(accumulator1, 384)}")
print(f"\nProof2: \n{to_padded_num_str(proof2, 384)}")
print(f"\nPrime2: \n{to_padded_num_str(prime2, 32)}")
print(f"\nAccumulator2: \n{to_padded_num_str(accumulator2, 384)}")

sys.stdout.flush()
