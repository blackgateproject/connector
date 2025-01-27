import math
import secrets

from ..utils.accumulator_utils import (
    bezoute_coefficients,
    calculate_product,
    concat,
    generate_two_large_distinct_primes,
    hash_to_prime,
    mul_inv,
    shamir_trick,
)


class AccumulatorClass:
    def __init__(self):
        self.currentAccumulator = 0
        self.modulus = 0
        self.RSA_KEY_SIZE = 3072
        self.RSA_PRIME_SIZE = int(self.RSA_KEY_SIZE / 2)
        self.ACCUMULATED_PRIME_SIZE = 128
        self.GQUADDIVISOR = 20

    def setup(self, modulus: int = None, A0: int = None):
        """
        Setup the RSA accumulator
        :return: n, A0, S
        """
        if not modulus:
            # draw strong primes p,q
            p, q = generate_two_large_distinct_primes(self.RSA_PRIME_SIZE)
            n = p * q
        else:
            n = modulus
        # draw random number within range of [0,n-1]

        if not A0:
            A0 = secrets.randbelow(n)
        else:
            A0 = A0
        self.currentAccumulator = A0
        return n, A0, dict()

    def add(self, A, S, x, n):
        """
        Add an element to the accumulator
        :param A: current accumulator value
        :param S: set of accumulated elements
        :param x: element to add
        :param n: modulus
        :return: new accumulator value
        """
        if x in S.keys():
            return A
        else:
            hash_prime, nonce = hash_to_prime(x, self.ACCUMULATED_PRIME_SIZE)
            A = pow(A, hash_prime, n)
            S[x] = nonce
            return A

    def batch_add(self, A_pre_add, S, x_list, n):
        """
        Batch add elements to the accumulator
        :param A_pre_add: accumulator value before addition
        :param S: set of accumulated elements
        :param x_list: list of elements to add
        :param n: modulus
        :return: new accumulator value and proof of exponentiation
        """
        product = 1
        for x in x_list:
            if x not in S.keys():
                hash_prime, nonce = hash_to_prime(x, self.ACCUMULATED_PRIME_SIZE)
                S[x] = nonce
                product *= hash_prime
        A_post_add = pow(A_pre_add, product, n)
        return A_post_add, self.prove_exponentiation(A_pre_add, product, A_post_add, n)

    def prove_membership(self, A0, S, x, n):
        """
        Prove membership of an element in the accumulator
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param x: element to prove membership for
        :param n: modulus
        :return: proof of membership
        """
        if x not in S.keys():
            return None
        else:
            product = 1
            for element in S.keys():
                if element != x:
                    nonce = S[element]
                    product *= hash_to_prime(
                        element, self.ACCUMULATED_PRIME_SIZE, nonce
                    )[0]
            A = pow(A0, product, n)
            return A

    def prove_non_membership(self, A0, S, x, x_nonce, n):
        """
        Prove non-membership of an element in the accumulator
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param x: element to prove non-membership for
        :param x_nonce: nonce for the element
        :param n: modulus
        :return: proof of non-membership
        """
        if x in S.keys():
            return None
        else:
            product = 1
            for element in S.keys():
                nonce = S[element]
                product *= hash_to_prime(element, self.ACCUMULATED_PRIME_SIZE, nonce)[0]
        prime = hash_to_prime(x, self.ACCUMULATED_PRIME_SIZE, x_nonce)[0]
        a, b = bezoute_coefficients(prime, product)
        if a < 0:
            positive_a = -a
            inverse_A0 = mul_inv(A0, n)
            d = pow(inverse_A0, positive_a, n)
        else:
            d = pow(A0, a, n)
        return d, b

    def verify_non_membership(self, A0, A_final, d, b, x, x_nonce, n):
        """
        Verify non-membership proof
        :param A0: initial accumulator value
        :param A_final: final accumulator value
        :param d: proof component
        :param b: proof component
        :param x: element to verify non-membership for
        :param x_nonce: nonce for the element
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        prime = hash_to_prime(x, self.ACCUMULATED_PRIME_SIZE, x_nonce)[0]
        if b < 0:
            positive_b = -b
            inverse_A_final = mul_inv(A_final, n)
            second_power = pow(inverse_A_final, positive_b, n)
        else:
            second_power = pow(A_final, b, n)
        return (pow(d, prime, n) * second_power) % n == A0

    def batch_prove_membership(self, A0, S, x_list, n):
        """
        Batch prove membership of elements in the accumulator
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param x_list: list of elements to prove membership for
        :param n: modulus
        :return: proof of membership
        """
        product = 1
        for element in S.keys():
            if element not in x_list:
                nonce = S[element]
                product *= hash_to_prime(element, self.ACCUMULATED_PRIME_SIZE, nonce)[0]
        A = pow(A0, product, n)
        return A

    def batch_prove_membership_with_NIPoE(self, A0, S, x_list, n, w):
        """
        Batch prove membership with NI-PoE
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param x_list: list of elements to prove membership for
        :param n: modulus
        :param w: final accumulator value
        :return: proof of membership with NI-PoE
        """
        u = self.batch_prove_membership(A0, S, x_list, n)
        nonces_list = []
        for x in x_list:
            nonces_list.append(S[x])
        product = self.__calculate_primes_product(x_list, nonces_list)
        Q, l_nonce = self.prove_exponentiation(u, product, w, n)
        return Q, l_nonce, u

    def prove_membership_with_NIPoE(self, g, S, x, n, w):
        """
        Prove membership with NI-PoE
        :param g: initial accumulator value
        :param S: set of accumulated elements
        :param x: element to prove membership for
        :param n: modulus
        :param w: final accumulator value
        :return: proof of membership with NI-PoE
        """
        u = self.prove_membership(g, S, x, n)
        x_prime, x_nonce = hash_to_prime(x=x, nonce=S[x])
        Q, l_nonce = self.prove_exponentiation(u, x_prime, w, n)
        return Q, l_nonce, u

    def prove_exponentiation(self, u, x, w, n):
        """
        Prove exponentiation
        :param u: initial accumulator value
        :param x: element to prove exponentiation for
        :param w: final accumulator value
        :param n: modulus
        :return: proof of exponentiation
        """
        l, nonce = hash_to_prime(concat(x, u, w))
        q = x // l
        Q = pow(u, q, n)
        return Q, nonce

    def verify_exponentiation(self, Q, l_nonce, u, x, x_nonce, w, n):
        """
        Verify exponentiation proof
        :param Q: proof component
        :param l_nonce: nonce for l
        :param u: initial accumulator value
        :param x: element to verify exponentiation for
        :param x_nonce: nonce for the element
        :param w: final accumulator value
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        x = hash_to_prime(x=x, nonce=x_nonce)[0]
        return self.__verify_exponentiation(Q, l_nonce, u, x, w, n)

    def batch_verify_membership_with_NIPoE(
        self, Q, l_nonce, u, x_list, x_nonces_list, w, n
    ):
        """
        Batch verify membership with NI-PoE
        :param Q: proof component
        :param l_nonce: nonce for l
        :param u: initial accumulator value
        :param x_list: list of elements to verify membership for
        :param x_nonces_list: list of nonces for the elements
        :param w: final accumulator value
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        product = self.__calculate_primes_product(x_list, x_nonces_list)
        return self.__verify_exponentiation(Q, l_nonce, u, product, w, n)

    def __verify_exponentiation(self, Q, l_nonce, u, x, w, n):
        """
        Helper function to verify exponentiation
        :param Q: proof component
        :param l_nonce: nonce for l
        :param u: initial accumulator value
        :param x: element to verify exponentiation for
        :param w: final accumulator value
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        l = hash_to_prime(x=(concat(x, u, w)), nonce=l_nonce)[0]
        r = x % l
        # check (Q^l)(u^r) == w
        return (pow(Q, l, n) % n) * (pow(u, r, n) % n) % n == w

    def delete(self, A0, A, S, x, n):
        """
        Delete an element from the accumulator
        :param A0: initial accumulator value
        :param A: current accumulator value
        :param S: set of accumulated elements
        :param x: element to delete
        :param n: modulus
        :return: new accumulator value
        """
        if x not in S.keys():
            return A
        else:
            del S[x]
            product = 1
            for element in S.keys():
                nonce = S[element]
                product *= hash_to_prime(element, self.ACCUMULATED_PRIME_SIZE, nonce)[0]
            Anew = pow(A0, product, n)
            return Anew

    def batch_delete(self, A0, S, x_list, n):
        """
        Batch delete elements from the accumulator
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param x_list: list of elements to delete
        :param n: modulus
        :return: new accumulator value
        """
        for x in x_list:
            del S[x]

        if len(S) == 0:
            return A0

        return self.batch_add(A0, S, x_list, n)

    def batch_delete_using_membership_proofs(
        self,
        A_pre_delete,
        S,
        x_list,
        proofs_list,
        n,
        agg_indexes=[],
    ):
        """
        Batch delete elements using membership proofs
        :param A_pre_delete: accumulator value before deletion
        :param S: set of accumulated elements
        :param x_list: list of elements to delete
        :param proofs_list: list of membership proofs
        :param n: modulus
        :param agg_indexes: list of aggregation indexes
        :return: new accumulator value and proof of exponentiation
        """
        is_aggregated = len(agg_indexes) > 0
        if is_aggregated and len(proofs_list) != len(agg_indexes):
            return None

        if (not is_aggregated) and len(x_list) != len(proofs_list):
            return None

        members = []
        if is_aggregated:
            # sanity - verify each and every proof individually
            for i, indexes in enumerate(agg_indexes):
                current_x_list = x_list[indexes[0] : indexes[1]]
                current_nonce_list = [S[x] for x in current_x_list]
                product = self.__calculate_primes_product(
                    current_x_list, current_nonce_list
                )
                members.append(product)
                for x in current_x_list:
                    del S[x]
        else:
            for x in x_list:
                members.append(hash_to_prime(x, self.ACCUMULATED_PRIME_SIZE, S[x])[0])
                del S[x]

        A_post_delete = proofs_list[0]
        product = members[0]

        for i in range(len(members))[1:]:
            A_post_delete = shamir_trick(
                A_post_delete, proofs_list[i], product, members[i], n
            )
            product *= members[i]

        return A_post_delete, self.prove_exponentiation(
            A_post_delete, product, A_pre_delete, n
        )

    def verify_membership(self, A, x, nonce, proof, n):
        """
        Verify membership proof
        :param A: accumulator value
        :param x: element to verify membership for
        :param nonce: nonce for the element
        :param proof: proof of membership
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        return self.__verify_membership(
            A,
            hash_to_prime(x=x, num_of_bits=self.ACCUMULATED_PRIME_SIZE, nonce=nonce)[0],
            proof,
            n,
        )

    def batch_verify_membership(self, A, x_list, nonce_list, proof, n):
        """
        Batch verify membership proofs
        :param A: accumulator value
        :param x_list: list of elements to verify membership for
        :param nonce_list: list of nonces for the elements
        :param proof: proof of membership
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        product = self.__calculate_primes_product(x_list, nonce_list)
        return self.__verify_membership(A, product, proof, n)

    def __calculate_primes_product(self, x_list, nonce_list):
        """
        Helper function to calculate product of primes
        :param x_list: list of elements
        :param nonce_list: list of nonces for the elements
        :return: product of primes
        """
        if len(x_list) != len(nonce_list):
            return None

        primes_list = [
            hash_to_prime(x, nonce=nonce_list[i])[0] for i, x in enumerate(x_list)
        ]
        product = calculate_product(primes_list)
        return product

    def __verify_membership(self, A, x, proof, n):
        """
        Helper function to verify membership
        :param A: accumulator value
        :param x: element to verify membership for
        :param proof: proof of membership
        :param n: modulus
        :return: True if proof is valid, False otherwise
        """
        return pow(proof, x, n) == A

    def create_all_membership_witnesses(self, A0, S, n):
        """
        Create all membership witnesses
        :param A0: initial accumulator value
        :param S: set of accumulated elements
        :param n: modulus
        :return: list of membership witnesses
        """
        primes = [hash_to_prime(x=x, nonce=S[x])[0] for x in S.keys()]
        return self.root_factor(A0, primes, n)

    def root_factor(self, g, primes, N):
        """
        Helper function to create root factor
        :param g: initial accumulator value
        :param primes: list of primes
        :param N: modulus
        :return: list of root factors
        """
        n = len(primes)
        if n == 1:
            return [g]

        n_tag = n // 2
        primes_L = primes[n_tag:n]
        product_L = calculate_product(primes_L)
        g_L = pow(g, product_L, N)

        primes_R = primes[0:n_tag]
        product_R = calculate_product(primes_R)
        g_R = pow(g, product_R, N)

        L = self.root_factor(g_L, primes_R, N)
        R = self.root_factor(g_R, primes_L, N)

        return L + R

    def aggregate_membership_witnesses(self, A, witnesses_list, x_list, nonces_list, n):
        """
        Aggregate membership witnesses
        :param A: accumulator value
        :param witnesses_list: list of witnesses
        :param x_list: list of elements
        :param nonces_list: list of nonces for the elements
        :param n: modulus
        :return: aggregated witness and proof of exponentiation
        """
        primes = []
        for i in range(len(x_list)):
            prime = hash_to_prime(
                x_list[i], self.ACCUMULATED_PRIME_SIZE, nonces_list[i]
            )[0]
            primes.append(prime)

        agg_wit = witnesses_list[0]
        product = primes[0]

        for i in range(len(x_list))[1:]:
            agg_wit = shamir_trick(agg_wit, witnesses_list[i], product, primes[i], n)
            product *= primes[i]

        return agg_wit, self.prove_exponentiation(agg_wit, product, A, n)

    def generate_proof(self, element, accumulator, secrets_dict, modulus):
        """
        Generate proof of membership
        :param element: element to generate proof for
        :param accumulator: accumulator value
        :param secrets_dict: dictionary of secrets
        :param modulus: modulus
        :return: proof of membership and prime
        """
        nonce = secrets_dict[element]
        proof = self.prove_membership(accumulator, secrets_dict, element, modulus)
        prime, nonce = hash_to_prime(x=element, nonce=nonce)
        return proof, prime

    """
    ====== from generate_proof.py ======
    """
    def to_padded_num_str_FROMFILE(num, length_in_bytes):
        length_in_hex_str = length_in_bytes * 2 + 2
        num_str = format(num, "#0" + str(length_in_hex_str) + "x")
        return num_str

    def generate_proof_FROMFILE(self):
        n, A0, S = self.setup()

        x = secrets.randbelow(pow(2, 256))
        A1 = self.add(A0, S, x, n)
        nonce = S[x]
        proof = self.prove_membership(A0, S, x, n)
        prime, nonce = hash_to_prime(x=x, nonce=nonce)

        print(
            self.to_padded_num_str(n, 384)
            + ","
            + self.to_padded_num_str(proof, 384)
            + ","
            + self.to_padded_num_str(prime, 32)
            + ","
            + self.to_padded_num_str(A1, 384)
        )

    """
    ==== calculate mod exp gas ====
    """

    def mult_complexity(self, x):
        """
        Calculate multiplication complexity
        :param x: input value
        :return: multiplication complexity
        """
        if x <= 64:
            return x**2
        elif x <= 1024:
            return x**2 // 4 + 96 * x - 3072
        else:
            return x**2 // 16 + 480 * x - 199680

    def calculate_gas_consumption(
        # EIP198 gas calculation. All lengths in bytes.
        self,
        length_of_base,
        length_of_exponent,
        length_of_modulus,
        exponent,
    ):
        """
        Calculate gas consumption
        :param length_of_base: length of base in bytes
        :param length_of_exponent: length of exponent in bytes
        :param length_of_modulus: length of modulus in bytes
        :param exponent: exponent value
        :return: gas consumption
        """
        return math.floor(
            self.mult_complexity(max(length_of_modulus, length_of_base))
            * max(self.adjusted_exponent_length(length_of_exponent, exponent), 1)
            / self.GQUADDIVISOR
        )

    def adjusted_exponent_length(self, length_of_exponent, exponent):
        """
        Adjust exponent length
        :param length_of_exponent: length of exponent in bytes
        :param exponent: exponent value
        :return: adjusted exponent length
        """
        print(
            "adjusted_exponent_length("
            + str(length_of_exponent)
            + ", "
            + str(exponent)
            + ")"
        )
        if exponent == 0:
            return 0
        elif length_of_exponent <= 32:
            # return the index of the highest bit in exponent
            print("#1, returning: " + str(len(bin(exponent)) - 2))
            return len(bin(exponent)) - 3  # first two characters are '0b' prefix
        else:
            length_of_exponent_bits = length_of_exponent * 8
            exponent_binary = format(
                exponent, "#0" + str(length_of_exponent_bits + 2) + "b"
            )  # +2 for '0b' prefix
            exponent_first_256_bits = exponent_binary[2:258]
            highest_bit_in_exponent_first_256_bits = (
                0 if exponent == 0 else 255 - exponent_first_256_bits.find("1")
            )
            return (
                8 * (length_of_exponent - 32) + highest_bit_in_exponent_first_256_bits
            )
