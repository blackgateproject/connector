from unittest import TestCase

from ..core.accumulator import AccumulatorClass

accumulator = AccumulatorClass()

"""
Awais:: Havent tested yet
"""
class CalculateGasTest(TestCase):
    def test_adjusted_exponent_length(self):
        exponent = pow(2, 100 * 8 - 3)
        self.assertEqual(accumulator.adjusted_exponent_length(100, exponent), 797)

    def test_calculate_gas_consumption(self):
        length_of_base = 1
        length_of_exponent = 32
        length_of_modulus = 32
        base = 3
        exponent = int(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", 16
        )
        modulus = int(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16
        )
        self.assertEqual(
            accumulator.calculate_gas_consumption(
                length_of_base, length_of_exponent, length_of_modulus, exponent
            ),
            13056,
        )
