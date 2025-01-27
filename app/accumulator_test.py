import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__)))
from core.accumulator import AccumulatorClass

acc = AccumulatorClass()

print(f"SETUP: {acc.setup()}")