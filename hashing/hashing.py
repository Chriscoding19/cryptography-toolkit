"""
hashing.py - Cryptographic hash functions and related constructs.
"""
import hashlib
import hmac as hmac_module
import secrets
from typing import List


class HashFunction:
    ALGORITHMS = {
        "md5": hashlib.md5, "sha1": hashlib.sha1,
        "sha224": hashlib.sha224, "sha256": hashlib.sha256,
        "sha384": hashlib.sha384, "sha512": hashlib.sha512,
    }

    @staticmethod
    def hash(data, algorithm="sha256"):
        if isinstance(data, str): data = data.encode("utf-8")
        algo = HashFunction.ALGORITHMS.get(algorithm.lower())
        if not algo: raise ValueError(f"Unknown algorithm: {algorithm}")
        return algo(data).hexdigest()

    @staticmethod
    def hash_all(data):
        if isinstance(data, str): data = data.encode("utf-8")
        return {name: algo(data).hexdigest() for name, algo in HashFunction.ALGORITHMS.items()}

    @staticmethod
    def verify(data, expected_hash, algorithm="sha256"):
        return hmac_module.compare_digest(HashFunction.hash(data, algorithm), expected_hash)


class HMAC:
    def __init__(self, key: bytes, algorithm="sha256"):
        self.key = key
        self.algorithm = algorithm

    def compute(self, message) -> str:
        if isinstance(message, str): message = message.encode("utf-8")
        mac = hmac_module.new(self.key, message, digestmod=getattr(hashlib, self.algorithm))
        return mac.hexdigest()

    def verify(self, message, tag: str) -> bool:
        return hmac_module.compare_digest(self.compute(message), tag)

    @staticmethod
    def generate_key(bits=256) -> bytes:
        return secrets.token_bytes(bits // 8)


class PasswordHasher:
    ITERATIONS = 100_000
    SALT_LEN   = 32
    KEY_LEN    = 32

    def hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(self.SALT_LEN)
        key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.ITERATIONS, dklen=self.KEY_LEN)
        return f"{salt.hex()}:{key.hex()}"

    def verify_password(self, password: str, stored: str) -> bool:
        try:
            salt_hex, key_hex = stored.split(":")
            salt = bytes.fromhex(salt_hex)
            stored_key = bytes.fromhex(key_hex)
        except Exception:
            return False
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.ITERATIONS, dklen=self.KEY_LEN)
        return hmac_module.compare_digest(computed, stored_key)

    def demonstrate_salting(self) -> dict:
        password = "password123"
        h1 = self.hash_password(password)
        h2 = self.hash_password(password)
        plain = hashlib.sha256(password.encode()).hexdigest()
        return {
            "password": password, "unsalted_sha256": plain,
            "salted_hash_1": h1[:40]+"...", "salted_hash_2": h2[:40]+"...",
            "hashes_differ": h1 != h2,
            "both_verify": self.verify_password(password, h1) and self.verify_password(password, h2),
        }


class MerkleTree:
    def __init__(self, data_items: List[str]):
        self.data   = data_items
        self.leaves = [hashlib.sha256(d.encode()).hexdigest() for d in data_items]
        self.root   = self._build(self.leaves[:])

    @staticmethod
    def _combine(a, b):
        return hashlib.sha256((a + b).encode()).hexdigest()

    def _build(self, nodes):
        if not nodes: return ""
        while len(nodes) > 1:
            if len(nodes) % 2 == 1: nodes.append(nodes[-1])
            nodes = [self._combine(nodes[i], nodes[i+1]) for i in range(0, len(nodes), 2)]
        return nodes[0]

    def get_proof(self, index: int) -> List[dict]:
        proof = []
        nodes = self.leaves[:]
        idx   = index
        while len(nodes) > 1:
            if len(nodes) % 2 == 1: nodes.append(nodes[-1])
            sibling   = idx ^ 1
            direction = "right" if idx % 2 == 0 else "left"
            if sibling < len(nodes):
                proof.append({"hash": nodes[sibling], "direction": direction})
            nodes = [self._combine(nodes[i], nodes[i+1]) for i in range(0, len(nodes), 2)]
            idx //= 2
        return proof

    def verify_proof(self, leaf_data: str, index: int, proof: List[dict], root: str) -> bool:
        current = hashlib.sha256(leaf_data.encode()).hexdigest()
        idx     = index
        for step in proof:
            sibling = step["hash"]
            current = self._combine(current, sibling) if idx % 2 == 0 else self._combine(sibling, current)
            idx //= 2
        return current == root


class HashChain:
    def __init__(self, seed: str, length: int = 10):
        self.seed  = seed
        self.chain = self._build(seed, length)

    @staticmethod
    def _build(seed, n):
        chain = [hashlib.sha256(seed.encode()).hexdigest()]
        for _ in range(1, n):
            chain.append(hashlib.sha256(chain[-1].encode()).hexdigest())
        return chain

    def get(self, index: int) -> str:
        return self.chain[index]

    def verify_link(self, h1: str, h2: str) -> bool:
        return hashlib.sha256(h1.encode()).hexdigest() == h2


def checksum_file(filepath: str, algorithm="sha256") -> str:
    h = getattr(hashlib, algorithm)()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()


def verify_file(filepath: str, expected: str, algorithm="sha256") -> bool:
    return hmac_module.compare_digest(checksum_file(filepath, algorithm), expected)
