import sys
import os

# Make `src` importable as a top-level package root so that
# `from src.swarmshield.xxx import ...` works from any pytest invocation.
sys.path.insert(0, os.path.dirname(__file__))
