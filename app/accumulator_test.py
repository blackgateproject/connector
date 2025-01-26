from core.accumulator import AccumulatorClass

accumulator = AccumulatorClass()

n, a0, s = accumulator.setup()

print(
    f"Accumulator setup:\n\tN = {accumulator.modulus}\n\tA0 = {accumulator.currentAccumulator}\n\trandomDict() S = {s}"
)
