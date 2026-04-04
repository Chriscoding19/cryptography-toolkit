"""
asymmetric.py - RSA, Diffie-Hellman, ElGamal from scratch. Pure Python stdlib.
"""
import random, math, hashlib
from typing import Tuple


def miller_rabin(n: int, k: int = 20) -> bool:
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    witnesses = [2,3,5,7,11,13,17,19,23,29,31,37]
    for a in witnesses:
        if a >= n: continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n): return n


def extended_gcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a % m, m)
    if g != 1: raise ValueError("No modular inverse")
    return x % m


def mod_pow(base, exp, mod): return pow(base, exp, mod)


class RSA:
    """RSA public-key cryptosystem. Security: integer factorisation problem."""

    def __init__(self, bits: int = 512):
        self.bits = bits
        self.n = self.e = self.d = None
        self.public_key = self.private_key = None

    def generate_keys(self) -> dict:
        half = self.bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        while q == p: q = generate_prime(half)
        self.n   = p * q
        phi      = (p - 1) * (q - 1)
        self.e   = 65537
        if math.gcd(self.e, phi) != 1: self.e = 3
        while math.gcd(self.e, phi) != 1: self.e += 2
        self.d   = mod_inverse(self.e, phi)
        self.public_key  = (self.n, self.e)
        self.private_key = (self.n, self.d)
        return {
            "public_key":  {"n": self.n, "e": self.e},
            "private_key": {"n": self.n, "d": self.d},
            "key_bits":    self.bits,
            "n_bits":      self.n.bit_length(),
        }

    def encrypt(self, m: int) -> int:
        if m >= self.n: raise ValueError("Message too large")
        return pow(m, self.e, self.n)

    def decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def encrypt_text(self, msg: str) -> list:
        return [self.encrypt(b) for b in msg.encode("utf-8")]

    def decrypt_text(self, enc: list) -> str:
        return bytes(self.decrypt(c) for c in enc).decode("utf-8")

    def sign(self, message: str) -> int:
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.n
        return pow(h, self.d, self.n)

    def verify(self, message: str, signature: int) -> bool:
        h   = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.n
        dec = pow(signature, self.e, self.n)
        return h == dec


# Standard 512-bit DH prime (small for speed; use 2048+ in production)
DH_PRIME     = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
DH_GENERATOR = 2


class DiffieHellman:
    """
    Diffie-Hellman key exchange (1976).
    Allows two parties to establish a shared secret over an insecure channel.
    Security: discrete logarithm problem.
    """
    def __init__(self, prime=None, generator=DH_GENERATOR):
        self.p           = prime or DH_PRIME
        self.g           = generator
        self.private_key = random.randint(2, self.p - 2)
        self.public_key  = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public: int) -> int:
        return pow(other_public, self.private_key, self.p)

    def shared_secret_to_key(self, shared: int) -> bytes:
        raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
        return hashlib.sha256(raw).digest()


class ElGamal:
    """ElGamal encryption (1985). Based on DH. Security: discrete log."""
    def __init__(self, bits: int = 256):
        self.p = generate_prime(bits)
        self.g = 2
        self.x = random.randint(1, self.p - 2)
        self.y = pow(self.g, self.x, self.p)

    def generate_keys(self):
        return {"p": self.p, "g": self.g, "y": self.y, "x": self.x}

    def encrypt(self, m: int) -> Tuple[int, int]:
        if m >= self.p: raise ValueError("Message >= p")
        k  = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return c1, c2

    def decrypt(self, c1: int, c2: int) -> int:
        s     = pow(c1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        return (c2 * s_inv) % self.p
