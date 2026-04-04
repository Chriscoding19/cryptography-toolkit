"""
tests/test_cryptography.py — Unit tests for the Cryptography Toolkit.
Run: python3 tests/test_cryptography.py
"""
import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from classical.classical  import (CaesarCipher, VigenereCipher, RailFenceCipher,
                                   PlayfairCipher, OneTimePad, frequency_analysis)
from symmetric.symmetric  import (AES, aes_ecb_encrypt, aes_ecb_decrypt,
                                   aes_cbc_encrypt, aes_cbc_decrypt,
                                   XORStreamCipher, derive_key)
from asymmetric.asymmetric import (RSA, DiffieHellman, ElGamal,
                                    miller_rabin, generate_prime, mod_inverse, mod_pow)
from hashing.hashing       import (HashFunction, HMAC, PasswordHasher,
                                    MerkleTree, HashChain)


# ── Classical Ciphers ──────────────────────────────────────────────

class TestCaesar(unittest.TestCase):
    def test_roundtrip(self):
        c = CaesarCipher(13); t = "Hello World"
        self.assertEqual(c.decrypt(c.encrypt(t)), t)
    def test_rot13(self):
        self.assertEqual(CaesarCipher(13).encrypt("ABC"), "NOP")
    def test_preserves_spaces(self):
        c = CaesarCipher(3)
        self.assertEqual(c.encrypt("Hello, World! 123"), "Khoor, Zruog! 123")
    def test_shift_zero(self):
        self.assertEqual(CaesarCipher(0).encrypt("HELLO"), "HELLO")
    def test_brute_force(self):
        c = CaesarCipher(7); ct = c.encrypt("HELLO")
        results = [r["plaintext"] for r in c.brute_force(ct)]
        self.assertIn("HELLO", results)
    def test_case_preserved(self):
        self.assertEqual(CaesarCipher(1).encrypt("aZ"), "bA")

class TestVigenere(unittest.TestCase):
    def test_roundtrip(self):
        v = VigenereCipher("SECRET"); t = "ATTACK AT DAWN"
        self.assertEqual(v.decrypt(v.encrypt(t)), t)
    def test_known(self):
        self.assertEqual(VigenereCipher("KEY").encrypt("ABC"), "KFA")
    def test_case_insensitive_key(self):
        self.assertEqual(VigenereCipher("secret").encrypt("HI"),
                         VigenereCipher("SECRET").encrypt("HI"))
    def test_invalid_key(self):
        with self.assertRaises(ValueError): VigenereCipher("123")
    def test_kasiski(self):
        v = VigenereCipher("KEY"); ct = v.encrypt("ATTACKATDAWNATTACKATDAWN")
        r = v.kasiski_test(ct); self.assertIn("repeated_sequences", r)

class TestRailFence(unittest.TestCase):
    def test_roundtrip_3(self):
        r = RailFenceCipher(3); t = "WEAREDISCOVEREDFLEEATONCE"
        self.assertEqual(r.decrypt(r.encrypt(t)), t)
    def test_roundtrip_2(self):
        r = RailFenceCipher(2); t = "HELLOWORLD"
        self.assertEqual(r.decrypt(r.encrypt(t)), t)
    def test_invalid(self):
        with self.assertRaises(ValueError): RailFenceCipher(1)
    def test_single_char(self):
        r = RailFenceCipher(3)
        self.assertEqual(r.decrypt(r.encrypt("X")), "X")

class TestPlayfair(unittest.TestCase):
    def test_encrypt_length(self):
        p = PlayfairCipher("MONARCHY"); ct = p.encrypt("HELLO")
        self.assertGreater(len(ct), 0); self.assertEqual(len(ct) % 2, 0)
    def test_ij_equiv(self):
        p = PlayfairCipher("KEY")
        self.assertEqual(p.encrypt("INJECT"), p.encrypt("INIECT"))

class TestOTP(unittest.TestCase):
    def test_roundtrip(self):
        ct, key = OneTimePad.encrypt_text("Hello, World!")
        self.assertEqual(OneTimePad.decrypt_text(ct, key), "Hello, World!")
    def test_key_length(self):
        ct, key = OneTimePad.encrypt_text("TEST")
        self.assertEqual(len(key), 4)
    def test_xor_inverse(self):
        data = b"secret"; key = OneTimePad.generate_key(len(data))
        self.assertEqual(OneTimePad.decrypt(OneTimePad.encrypt(data, key), key), data)
    def test_different_ciphertexts(self):
        ct1, _ = OneTimePad.encrypt_text("HI"); ct2, _ = OneTimePad.encrypt_text("HI")
        self.assertNotEqual(ct1, ct2)

class TestFrequency(unittest.TestCase):
    def test_returns_dict(self):
        r = frequency_analysis("HELLO WORLD")
        self.assertIn("letter_frequencies", r); self.assertIn("index_of_coincidence", r)
    def test_monoalphabetic_ic(self):
        c = CaesarCipher(7); t = "THEQUICKBROWNFOX" * 20
        r = frequency_analysis(c.encrypt(t))
        self.assertGreater(r["index_of_coincidence"], 0.05)


# ── Symmetric ─────────────────────────────────────────────────────

class TestAES(unittest.TestCase):
    def setUp(self):
        self.k16 = b"0123456789abcdef"
        self.k32 = b"0123456789abcdef" * 2

    def test_block_roundtrip_128(self):
        a = AES(self.k16); blk = b"YELLOW SUBMARINE"
        self.assertEqual(a.decrypt_block(a.encrypt_block(blk)), blk)

    def test_block_roundtrip_256(self):
        a = AES(self.k32); blk = b"YELLOW SUBMARINE"
        self.assertEqual(a.decrypt_block(a.encrypt_block(blk)), blk)

    def test_invalid_key(self):
        with self.assertRaises(ValueError): AES(b"short")

    def test_ecb_roundtrip(self):
        pt = b"Hello, AES World"
        self.assertEqual(aes_ecb_decrypt(aes_ecb_encrypt(pt, self.k16), self.k16), pt)

    def test_cbc_roundtrip(self):
        pt = b"Hello, CBC Mode!"
        ct, iv = aes_cbc_encrypt(pt, self.k32)
        self.assertEqual(aes_cbc_decrypt(ct, self.k32, iv), pt)

    def test_ecb_pattern_leak(self):
        blk = b"AAAAAAAAAAAAAAAA"; ct = aes_ecb_encrypt(blk * 3, self.k16)
        self.assertEqual(ct[0:16], ct[16:32])
        self.assertEqual(ct[16:32], ct[32:48])

    def test_cbc_no_pattern_leak(self):
        blk = b"AAAAAAAAAAAAAAAA"; ct, iv = aes_cbc_encrypt(blk * 3, self.k16)
        self.assertNotEqual(ct[0:16], ct[16:32])

class TestXORStream(unittest.TestCase):
    def test_roundtrip(self):
        c = XORStreamCipher(b"key"); pt = b"Hello stream!"
        self.assertEqual(c.decrypt(c.encrypt(pt)), pt)
    def test_different_key(self):
        pt = b"SECRET"
        self.assertNotEqual(XORStreamCipher(b"k1").encrypt(pt),
                            XORStreamCipher(b"k2").encrypt(pt))

class TestKeyDerivation(unittest.TestCase):
    def test_key_length(self):
        k, salt = derive_key("pass"); self.assertEqual(len(k), 32)
    def test_same_salt_same_key(self):
        salt = b"16bytesaltvalue!"
        k1, _ = derive_key("p", salt=salt); k2, _ = derive_key("p", salt=salt)
        self.assertEqual(k1, k2)
    def test_diff_salt_diff_key(self):
        k1, _ = derive_key("p"); k2, _ = derive_key("p")
        self.assertNotEqual(k1, k2)


# ── Asymmetric ────────────────────────────────────────────────────

class TestMath(unittest.TestCase):
    def test_mod_pow(self): self.assertEqual(mod_pow(2, 10, 1000), 24)
    def test_mod_inverse(self): self.assertEqual(mod_inverse(3, 7), 5)
    def test_miller_primes(self):
        for p in [2,3,5,7,11,97,101,997]: self.assertTrue(miller_rabin(p))
    def test_miller_composites(self):
        for c in [4,6,9,15,100,1000]: self.assertFalse(miller_rabin(c))
    def test_generate_prime(self):
        p = generate_prime(64); self.assertTrue(miller_rabin(p))

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.rsa = RSA(bits=256); self.rsa.generate_keys()

    def test_key_generation(self):
        keys = self.rsa.generate_keys()
        self.assertIn("public_key", keys); self.assertGreater(keys["n_bits"], 100)

    def test_encrypt_decrypt_int(self):
        ct = self.rsa.encrypt(42); self.assertEqual(self.rsa.decrypt(ct), 42)

    def test_encrypt_decrypt_text(self):
        self.assertEqual(self.rsa.decrypt_text(self.rsa.encrypt_text("Hi")), "Hi")

    def test_sign_verify(self):
        sig = self.rsa.sign("msg"); self.assertTrue(self.rsa.verify("msg", sig))

    def test_tampered_sig(self):
        sig = self.rsa.sign("original")
        self.assertFalse(self.rsa.verify("tampered", sig))

class TestDH(unittest.TestCase):
    def test_shared_secret(self):
        a = DiffieHellman(); b = DiffieHellman()
        self.assertEqual(a.compute_shared_secret(b.public_key),
                         b.compute_shared_secret(a.public_key))
    def test_key_length(self):
        a = DiffieHellman(); b = DiffieHellman()
        k = a.shared_secret_to_key(a.compute_shared_secret(b.public_key))
        self.assertEqual(len(k), 32)
    def test_different_sessions(self):
        a1=DiffieHellman();b1=DiffieHellman()
        a2=DiffieHellman();b2=DiffieHellman()
        self.assertNotEqual(a1.compute_shared_secret(b1.public_key),
                            a2.compute_shared_secret(b2.public_key))

class TestElGamal(unittest.TestCase):
    def test_roundtrip(self):
        eg = ElGamal(128); m = 42
        c1, c2 = eg.encrypt(m); self.assertEqual(eg.decrypt(c1, c2), m)


# ── Hashing ───────────────────────────────────────────────────────

class TestHashFunction(unittest.TestCase):
    def test_sha256_empty(self):
        self.assertEqual(HashFunction.hash("", "sha256"),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    def test_hash_all(self):
        r = HashFunction.hash_all("test")
        self.assertIn("sha256", r); self.assertIn("sha512", r)
    def test_verify_correct(self):
        h = HashFunction.hash("hi"); self.assertTrue(HashFunction.verify("hi", h))
    def test_verify_wrong(self):
        self.assertFalse(HashFunction.verify("hi", "badhash"))
    def test_avalanche(self):
        h1 = HashFunction.hash("Hello"); h2 = HashFunction.hash("hello")
        self.assertGreater(sum(a!=b for a,b in zip(h1,h2)), 10)

class TestHMAC(unittest.TestCase):
    def test_compute_verify(self):
        h = HMAC(HMAC.generate_key()); tag = h.compute("msg")
        self.assertTrue(h.verify("msg", tag))
    def test_wrong_msg(self):
        h = HMAC(HMAC.generate_key()); tag = h.compute("orig")
        self.assertFalse(h.verify("changed", tag))
    def test_wrong_key(self):
        tag = HMAC(HMAC.generate_key()).compute("msg")
        self.assertFalse(HMAC(HMAC.generate_key()).verify("msg", tag))

class TestPasswordHasher(unittest.TestCase):
    def setUp(self): self.ph = PasswordHasher()
    def test_hash_verify(self):
        h = self.ph.hash_password("secret")
        self.assertTrue(self.ph.verify_password("secret", h))
    def test_wrong_password(self):
        h = self.ph.hash_password("right")
        self.assertFalse(self.ph.verify_password("wrong", h))
    def test_unique_hashes(self):
        h1 = self.ph.hash_password("pw"); h2 = self.ph.hash_password("pw")
        self.assertNotEqual(h1, h2)
    def test_demo(self):
        r = self.ph.demonstrate_salting()
        self.assertTrue(r["hashes_differ"]); self.assertTrue(r["both_verify"])

class TestMerkleTree(unittest.TestCase):
    def setUp(self): self.t = MerkleTree(["tx1","tx2","tx3","tx4"])
    def test_deterministic(self):
        self.assertEqual(self.t.root, MerkleTree(["tx1","tx2","tx3","tx4"]).root)
    def test_change_detected(self):
        self.assertNotEqual(self.t.root, MerkleTree(["tx1","tx2","tx3","CHANGED"]).root)
    def test_proof_verify(self):
        proof = self.t.get_proof(0)
        self.assertTrue(self.t.verify_proof("tx1", 0, proof, self.t.root))
    def test_tamper_rejected(self):
        proof = self.t.get_proof(1)
        self.assertFalse(self.t.verify_proof("tampered", 1, proof, self.t.root))

class TestHashChain(unittest.TestCase):
    def test_length(self):
        hc = HashChain("seed", 5); self.assertEqual(len(hc.chain), 5)
    def test_links(self):
        hc = HashChain("seed", 5)
        for i in range(4): self.assertTrue(hc.verify_link(hc.chain[i], hc.chain[i+1]))


if __name__ == "__main__":
    print("Running Cryptography Toolkit tests...\n")
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestCaesar, TestVigenere, TestRailFence, TestPlayfair, TestOTP,
                TestFrequency, TestAES, TestXORStream, TestKeyDerivation,
                TestMath, TestRSA, TestDH, TestElGamal,
                TestHashFunction, TestHMAC, TestPasswordHasher,
                TestMerkleTree, TestHashChain]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
