"""
symmetric.py
------------
Symmetric encryption implementations:

  1. AES-256  — Industry standard block cipher (using Python stdlib)
  2. XOR Stream Cipher — Simple symmetric stream cipher
  3. Block Cipher modes: ECB vs CBC comparison
  4. Key derivation with PBKDF2

Uses Python's built-in 'hashlib' and 'hmac' — no external deps.
AES is implemented via the secrets/hashlib approach for key derivation
and a pure-Python AES for demonstration.
"""

import os
import hashlib
import hmac
import struct
import secrets
from typing import Tuple


# ══════════════════════════════════════════════════════════════════
# KEY DERIVATION
# ══════════════════════════════════════════════════════════════════

def derive_key(password: str, salt: bytes = None,
               iterations: int = 100_000, key_len: int = 32) -> Tuple[bytes, bytes]:
    """
    PBKDF2-HMAC-SHA256 key derivation.
    Converts a password into a cryptographic key with:
      - Salt: prevents rainbow table attacks
      - Iterations: makes brute force slow (100K iterations ≈ 0.1s)
      - Output: 256-bit (32 byte) key suitable for AES-256
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                               salt, iterations, dklen=key_len)
    return key, salt


# ══════════════════════════════════════════════════════════════════
# PURE PYTHON AES-256 (Educational Implementation)
# ══════════════════════════════════════════════════════════════════

# AES S-Box
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0]*256
for i,v in enumerate(_SBOX): _INV_SBOX[v] = i

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a): return ((a<<1)^0x1b) & 0xff if (a&0x80) else (a<<1)&0xff
def _gmul(a,b):
    p = 0
    for _ in range(8):
        if b&1: p ^= a
        hi = a & 0x80
        a = (a<<1)&0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p


class AES:
    """
    Pure-Python AES implementation (FIPS 197).
    Supports 128/192/256-bit keys.
    For educational demonstration — use cryptography library in production.
    """

    def __init__(self, key: bytes):
        klen = len(key)
        if klen not in (16,24,32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key  = key
        self.nr   = {16:10, 24:12, 32:14}[klen]
        self.nk   = klen // 4
        self._rk  = self._key_expansion(key)

    def _key_expansion(self, key):
        w  = [list(key[i*4:(i+1)*4]) for i in range(self.nk)]
        for i in range(self.nk, 4*(self.nr+1)):
            tmp = w[-1][:]
            if i % self.nk == 0:
                tmp = [_SBOX[tmp[j]] for j in (1,2,3,0)]
                tmp[0] ^= _RCON[(i//self.nk)-1]
            elif self.nk > 6 and i % self.nk == 4:
                tmp = [_SBOX[b] for b in tmp]
            w.append([w[-self.nk][j]^tmp[j] for j in range(4)])
        return [[w[i*4+j] for j in range(4)] for i in range(self.nr+1)]

    def _add_round_key(self, state, rk):
        return [[state[r][c]^rk[c][r] for c in range(4)] for r in range(4)]

    def _sub_bytes(self, state, inv=False):
        box = _INV_SBOX if inv else _SBOX
        return [[box[state[r][c]] for c in range(4)] for r in range(4)]

    def _shift_rows(self, state, inv=False):
        if inv:
            return [[state[r][(c-r)%4] for c in range(4)] for r in range(4)]
        return [[state[r][(c+r)%4] for c in range(4)] for r in range(4)]

    def _mix_cols(self, state, inv=False):
        out = [[0]*4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            if not inv:
                out[0][c] = _gmul(2,col[0])^_gmul(3,col[1])^col[2]^col[3]
                out[1][c] = col[0]^_gmul(2,col[1])^_gmul(3,col[2])^col[3]
                out[2][c] = col[0]^col[1]^_gmul(2,col[2])^_gmul(3,col[3])
                out[3][c] = _gmul(3,col[0])^col[1]^col[2]^_gmul(2,col[3])
            else:
                out[0][c] = _gmul(0xe,col[0])^_gmul(0xb,col[1])^_gmul(0xd,col[2])^_gmul(0x9,col[3])
                out[1][c] = _gmul(0x9,col[0])^_gmul(0xe,col[1])^_gmul(0xb,col[2])^_gmul(0xd,col[3])
                out[2][c] = _gmul(0xd,col[0])^_gmul(0x9,col[1])^_gmul(0xe,col[2])^_gmul(0xb,col[3])
                out[3][c] = _gmul(0xb,col[0])^_gmul(0xd,col[1])^_gmul(0x9,col[2])^_gmul(0xe,col[3])
        return out

    def _bytes_to_state(self, block):
        return [[block[c*4+r] for c in range(4)] for r in range(4)]

    def _state_to_bytes(self, state):
        return bytes(state[r][c] for c in range(4) for r in range(4))

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        s = self._bytes_to_state(list(block))
        s = self._add_round_key(s, self._rk[0])
        for rnd in range(1, self.nr):
            s = self._sub_bytes(s)
            s = self._shift_rows(s)
            s = self._mix_cols(s)
            s = self._add_round_key(s, self._rk[rnd])
        s = self._sub_bytes(s)
        s = self._shift_rows(s)
        s = self._add_round_key(s, self._rk[self.nr])
        return self._state_to_bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        s = self._bytes_to_state(list(block))
        s = self._add_round_key(s, self._rk[self.nr])
        for rnd in range(self.nr-1, 0, -1):
            s = self._shift_rows(s, inv=True)
            s = self._sub_bytes(s, inv=True)
            s = self._add_round_key(s, self._rk[rnd])
            s = self._mix_cols(s, inv=True)
        s = self._shift_rows(s, inv=True)
        s = self._sub_bytes(s, inv=True)
        s = self._add_round_key(s, self._rk[0])
        return self._state_to_bytes(s)


def _pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ── AES-ECB (Electronic Codebook) — INSECURE, for demonstration ──

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    ECB mode: each 16-byte block encrypted independently.
    INSECURE: identical plaintext blocks → identical ciphertext blocks.
    Pattern leakage makes it cryptographically weak.
    """
    aes     = AES(key)
    padded  = _pad(plaintext)
    return b''.join(aes.encrypt_block(padded[i:i+16])
                    for i in range(0, len(padded), 16))

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    aes = AES(key)
    pt  = b''.join(aes.decrypt_block(ciphertext[i:i+16])
                   for i in range(0, len(ciphertext), 16))
    return _unpad(pt)


# ── AES-CBC (Cipher Block Chaining) — SECURE ──────────────────────

def aes_cbc_encrypt(plaintext: bytes, key: bytes,
                    iv: bytes = None) -> Tuple[bytes, bytes]:
    """
    CBC mode: each block XORed with previous ciphertext before encryption.
    IV (Initialization Vector) ensures same plaintext → different ciphertext.
    This is the industry-standard mode for symmetric encryption.
    """
    if iv is None:
        iv  = secrets.token_bytes(16)
    aes     = AES(key)
    padded  = _pad(plaintext)
    prev    = iv
    blocks  = []
    for i in range(0, len(padded), 16):
        block  = bytes(a^b for a,b in zip(padded[i:i+16], prev))
        enc    = aes.encrypt_block(block)
        blocks.append(enc)
        prev   = enc
    return b''.join(blocks), iv

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    aes    = AES(key)
    prev   = iv
    blocks = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec   = bytes(a^b for a,b in zip(aes.decrypt_block(block), prev))
        blocks.append(dec)
        prev  = block
    return _unpad(b''.join(blocks))


# ── XOR Stream Cipher ──────────────────────────────────────────────

class XORStreamCipher:
    """
    Simple symmetric stream cipher using a keystream derived from a seed.
    Demonstrates the concept of stream ciphers.
    NOT secure — use ChaCha20 or AES-CTR in practice.
    """

    def __init__(self, key: bytes):
        self.key = key

    def _keystream(self, length: int) -> bytes:
        """Generate keystream by hashing key + counter."""
        stream = b''
        counter = 0
        while len(stream) < length:
            block = hashlib.sha256(self.key + struct.pack('>Q', counter)).digest()
            stream += block
            counter += 1
        return stream[:length]

    def encrypt(self, plaintext: bytes) -> bytes:
        ks = self._keystream(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)   # XOR is its own inverse
