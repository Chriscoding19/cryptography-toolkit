"""
modern_ciphers.py
-----------------
Implements modern symmetric encryption ciphers using Python's
built-in hashlib and secrets modules — no cryptography library needed.

Ciphers:
  1. AES-256-CBC  — Industry standard block cipher (simulated via hashlib + XOR)
  2. AES-256-CTR  — Counter mode (stream cipher from block cipher)
  3. ChaCha20     — Stream cipher used in TLS 1.3, simulated
  4. XSalsa20     — Extended nonce variant

Note: These implement the cryptographic concepts using Python's
      secrets/hashlib for educational demonstration. Production use
      should use the 'cryptography' library or PyCryptodome.
"""

import os
import hashlib
import hmac
import secrets
import struct
from typing import Tuple


# ══════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (truncated to shorter length)."""
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding — pad to multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def derive_key(password: str, salt: bytes = None,
               iterations: int = 100_000, key_len: int = 32) -> Tuple[bytes, bytes]:
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256.
    This is the standard way to convert a password to a cryptographic key.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=key_len)
    return key, salt


# ══════════════════════════════════════════════════════════════════
# BLOCK CIPHER (AES conceptual — using SHA-256 as PRF)
# ══════════════════════════════════════════════════════════════════

def _prf_block(key: bytes, data: bytes) -> bytes:
    """
    Pseudorandom function using HMAC-SHA256 as a block cipher primitive.
    Produces a keystream block for use in CBC/CTR modes.
    """
    return hmac.new(key, data, hashlib.sha256).digest()[:16]


class AES_CBC:
    """
    AES-CBC mode (Cipher Block Chaining) — conceptual implementation.

    CBC: Each plaintext block is XORed with the previous ciphertext block
    before encryption. Requires an IV (initialisation vector) for the first block.

    Properties:
      ✓ Each block depends on all previous blocks (avalanche effect)
      ✗ Sequential (cannot be parallelised for encryption)
      ✗ IV must be random and unique per message
    """

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key  = key
        self.name = f"AES-{len(key)*8}-CBC"

    def encrypt(self, plaintext: str, iv: bytes = None) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, iv)."""
        if iv is None:
            iv = secrets.token_bytes(self.BLOCK_SIZE)
        data   = pkcs7_pad(plaintext.encode())
        prev   = iv
        result = bytearray()

        for i in range(0, len(data), self.BLOCK_SIZE):
            block     = data[i:i+self.BLOCK_SIZE]
            xored     = xor_bytes(block, prev)
            # Use HMAC-SHA256 as our block cipher (conceptual AES substitute)
            keystream = _prf_block(self.key, prev + bytes([i//self.BLOCK_SIZE]))
            encrypted = xor_bytes(xored, keystream)
            result.extend(encrypted)
            prev = encrypted

        return bytes(result), iv

    def decrypt(self, ciphertext: bytes, iv: bytes) -> str:
        """Returns decrypted plaintext."""
        prev   = iv
        result = bytearray()

        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block     = ciphertext[i:i+self.BLOCK_SIZE]
            keystream = _prf_block(self.key, prev + bytes([i//self.BLOCK_SIZE]))
            xored     = xor_bytes(block, keystream)
            decrypted = xor_bytes(xored, prev)
            result.extend(decrypted)
            prev = block

        return pkcs7_unpad(bytes(result)).decode()


class AES_CTR:
    """
    AES-CTR mode (Counter mode) — turns block cipher into stream cipher.

    CTR: Encrypts successive counter values then XORs with plaintext.
    The counter increments for each block.

    Properties:
      ✓ Can be parallelised (random access to any block)
      ✓ No padding needed
      ✓ Same security as CBC with proper nonce
      ✗ Nonce must NEVER be reused with same key (catastrophic failure)
    """

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        self.key  = key
        self.name = f"AES-{len(key)*8}-CTR"

    def _keystream(self, nonce: bytes, counter: int) -> bytes:
        """Generate one keystream block."""
        counter_block = nonce + struct.pack('>Q', counter)
        return _prf_block(self.key, counter_block)

    def encrypt(self, plaintext: str, nonce: bytes = None) -> Tuple[bytes, bytes]:
        if nonce is None:
            nonce = secrets.token_bytes(8)
        data    = plaintext.encode()
        result  = bytearray()
        counter = 0

        for i in range(0, len(data), self.BLOCK_SIZE):
            block     = data[i:i+self.BLOCK_SIZE]
            keystream = self._keystream(nonce, counter)[:len(block)]
            result.extend(xor_bytes(block, keystream))
            counter += 1

        return bytes(result), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        # CTR mode: decryption is identical to encryption
        plaintext_bytes = bytearray()
        counter         = 0
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block     = ciphertext[i:i+self.BLOCK_SIZE]
            keystream = self._keystream(nonce, counter)[:len(block)]
            plaintext_bytes.extend(xor_bytes(block, keystream))
            counter += 1
        return bytes(plaintext_bytes).decode()


# ══════════════════════════════════════════════════════════════════
# CHACHA20 STREAM CIPHER (Simplified)
# ══════════════════════════════════════════════════════════════════

class ChaCha20:
    """
    ChaCha20 stream cipher (simplified implementation for demonstration).
    Used in TLS 1.3, WireGuard, and SSH.

    Based on the Salsa20 design by D.J. Bernstein.
    Uses 32-bit add-rotate-XOR operations — fast in software without hardware AES.
    256-bit key, 96-bit nonce, 32-bit counter.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key")
        self.key  = key
        self.name = "ChaCha20-256"

    @staticmethod
    def _rotl32(v: int, n: int) -> int:
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def _quarter_round(self, state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF; state[d] ^= state[a]; state[d] = self._rotl32(state[d], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF; state[b] ^= state[c]; state[b] = self._rotl32(state[b], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF; state[d] ^= state[a]; state[d] = self._rotl32(state[d],  8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF; state[b] ^= state[c]; state[b] = self._rotl32(state[b],  7)

    def _block(self, key: bytes, counter: int, nonce: bytes) -> bytes:
        """Generate one 64-byte keystream block (ChaCha20 core)."""
        # Constants: "expand 32-byte k"
        CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key_words  = list(struct.unpack('<8I', key))
        nonce_words= list(struct.unpack('<3I', nonce))

        state = CONSTANTS + key_words + [counter] + nonce_words
        work  = state[:]

        for _ in range(10):  # 20 rounds = 10 double rounds
            # Column rounds
            self._quarter_round(work, 0, 4, 8, 12)
            self._quarter_round(work, 1, 5, 9, 13)
            self._quarter_round(work, 2, 6, 10, 14)
            self._quarter_round(work, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(work, 0, 5, 10, 15)
            self._quarter_round(work, 1, 6, 11, 12)
            self._quarter_round(work, 2, 7, 8, 13)
            self._quarter_round(work, 3, 4, 9, 14)

        output = [(work[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        return struct.pack('<16I', *output)

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream  = bytearray()
        counter = 1
        while len(stream) < length:
            stream.extend(self._block(self.key, counter, nonce))
            counter += 1
        return bytes(stream[:length])

    def encrypt(self, plaintext: str, nonce: bytes = None) -> Tuple[bytes, bytes]:
        if nonce is None:
            nonce = secrets.token_bytes(12)
        data      = plaintext.encode()
        keystream = self._keystream(nonce, len(data))
        return xor_bytes(data, keystream), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        keystream = self._keystream(nonce, len(ciphertext))
        return xor_bytes(ciphertext, keystream).decode()
