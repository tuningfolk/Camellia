#!/usr/bin/env python3
"""The SQUARE attack on AES"""

from functools import reduce
from random import randbytes

# import aes
# import utilities


KEY = b"\xaa" + bytes(15)
ROUNDS = 4


def gen_lambda_set(passive_bytes: bytes) -> list[bytes]:
    """Generate a Λ-set with active bytes at index 0"""
    return [i.to_bytes(1, "big") + passive_bytes for i in range(256)]


# def setup(key: bytes, rounds: int) -> list[bytes]:
#     """Oracle to produce a variable-round AES-encrypted Λ-set"""
#     lambda_set = gen_lambda_set(randbytes(1) * 15)

print(gen_lambda_set(b""))