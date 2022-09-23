# Homework 1 (CS5830)
# Implement AES-CTR mode.
#

import math, struct
from signal import CTRL_BREAK_EVENT
from re import L
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def xor(a: bytes, b: bytes) -> bytes:
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes([ai ^ bi for ai, bi in zip(a, b)])


class AESCtr:
    def __init__(self, key):
        if not isinstance(key, bytes) or not len(key) in {16, 24, 32}:
            raise ValueError("AES key must be 16/24/32 bytes")
        self._encryption_key = key
        self._block_size_bytes = 16  # AES block size in bytes
        self._nonce_size_bytes = int(self._block_size_bytes / 2)  # half of the size
        # of the block,
        # other half is
        # the counter.

    def _nonced_counter(self, nonce, numblocks):
        """Returns the nonced 16 byte counter required for ctr mode"""
        for ctr in range(numblocks):
            yield nonce + struct.pack(">Q", ctr)

    def _aes_cipher(self, pt):
        """Returns the ciphertext encrypted in AES-ECB mode for a single block"""
        if not isinstance(pt, bytes) or len(pt) != self._block_size_bytes:
            raise ValueError("Block must be 16 bytes")
        try:
            cipher = AES.new(self._encryption_key, AES.MODE_ECB)
            ct = cipher.encrypt(pt)
            return ct
        except Exception:
            raise

    def encrypt(self, pt):
        """This function takes a byte stream @data and outputs the  ciphertext"""

        nonce = b""
        ct = b""

        # TODO: Fill in this function
        l = len(pt)
        n = self._block_size_bytes 
        m = math.ceil(l/n)
        p = b""
        
        nonce = get_random_bytes(int(n/2))
        g = self._nonced_counter(nonce,m)
        for i in range(m):
            p += self._aes_cipher(next(g))
        ct = xor(p, pt)       

        return nonce, ct

    def decrypt(self, nonce, ct):
        """This function decrypts a ciphertext encrypted using AES-CTR mode."""

        pt = b""

        # TODO: Fill in this function
        l = len(ct)
        n = self._block_size_bytes
        m = math.ceil(1/n)
        p = b""
        g = self._nonced_counter(nonce, m)
        for i in range(m):
            p += self._aes_cipher(next(g))
        pt = xor(p, ct)      


        return pt
