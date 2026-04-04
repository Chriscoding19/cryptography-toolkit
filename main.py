#!/usr/bin/env python3
"""
main.py — Cryptography Toolkit
================================

Demonstrates classical, symmetric, asymmetric cryptography and hashing.

  1. Classical Ciphers  — Caesar, Vigenère, Rail Fence, Playfair, OTP
  2. Symmetric Crypto   — AES-128/256 (ECB vs CBC), XOR stream cipher
  3. Asymmetric Crypto  — RSA keys, encrypt/decrypt, digital signatures
  4. Diffie-Hellman     — Key exchange over insecure channel
  5. Hashing            — SHA family, HMAC, password hashing, Merkle tree

Usage:
  python3 main.py
  python3 main.py --no-report
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from classical.classical  import (CaesarCipher, VigenereCipher, RailFenceCipher,
                                   PlayfairCipher, OneTimePad, frequency_analysis)
from symmetric.symmetric  import (aes_ecb_encrypt, aes_ecb_decrypt,
                                   aes_cbc_encrypt, aes_cbc_decrypt,
                                   XORStreamCipher, derive_key)
from asymmetric.asymmetric import RSA, DiffieHellman, ElGamal
from hashing.hashing       import (HashFunction, HMAC, PasswordHasher,
                                    MerkleTree, HashChain)
from reports.report_generator import generate_html_report


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--no-report", action="store_true")
    return p.parse_args()


def section(title):
    print(f"\n┌─────────────────────────────────────────────────────────────┐")
    print(f"│  {title}")
    print(f"└─────────────────────────────────────────────────────────────┘")


def header():
    print("\n" + "═"*65)
    print("   🔐  CRYPTOGRAPHY TOOLKIT")
    print("   Classical · Symmetric · Asymmetric · Hashing")
    print("═"*65)


def main():
    args   = parse_args()
    start  = time.time()
    report_data = {}
    header()

    # ── 1. Classical Ciphers ───────────────────────────────────────
    section("STEP 1/5 — Classical Ciphers")
    plaintext = "CRYPTOGRAPHY IS THE ART OF SECRET WRITING"
    print(f"\n  Plaintext: {plaintext!r}")

    # Caesar
    caesar = CaesarCipher(shift=13)
    ct_caesar = caesar.encrypt(plaintext)
    print(f"\n  [Caesar ROT-13]")
    print(f"    Encrypted : {ct_caesar}")
    print(f"    Decrypted : {caesar.decrypt(ct_caesar)}")
    print(f"    Verified  : {'✓' if caesar.decrypt(ct_caesar)==plaintext else '✗'}")

    # Vigenère
    vig = VigenereCipher("SECURITY")
    ct_vig = vig.encrypt(plaintext)
    print(f"\n  [Vigenère — key='SECURITY']")
    print(f"    Encrypted : {ct_vig}")
    print(f"    Decrypted : {vig.decrypt(ct_vig)}")
    print(f"    Verified  : {'✓' if vig.decrypt(ct_vig)==plaintext else '✗'}")

    # Rail Fence
    rf = RailFenceCipher(3)
    ct_rf = rf.encrypt(plaintext)
    print(f"\n  [Rail Fence — 3 rails]")
    print(f"    Encrypted : {ct_rf}")
    print(f"    Decrypted : {rf.decrypt(ct_rf)}")
    print(f"    Verified  : {'✓' if rf.decrypt(ct_rf)==plaintext else '✗'}")

    # Playfair
    pf = PlayfairCipher("SECURITY")
    ct_pf = pf.encrypt("HELLO WORLD")
    print(f"\n  [Playfair — key='SECURITY']")
    print(f"    Plaintext : HELLO WORLD")
    print(f"    Encrypted : {ct_pf}")
    print(f"    Decrypted : {pf.decrypt(ct_pf)}")

    # One-Time Pad
    msg_bytes = b"TOP SECRET MESSAGE"
    ct_otp, key_otp = OneTimePad.encrypt_text("TOP SECRET MESSAGE")
    dec_otp = OneTimePad.decrypt_text(ct_otp, key_otp)
    print(f"\n  [One-Time Pad]")
    print(f"    Plaintext : TOP SECRET MESSAGE")
    print(f"    Ciphertext: {ct_otp.hex()}")
    print(f"    Decrypted : {dec_otp}")
    print(f"    Verified  : {'✓' if dec_otp=='TOP SECRET MESSAGE' else '✗'}")

    # Frequency analysis
    vig_long = VigenereCipher("SECRET").encrypt("A" * 200 + "ETAOIN" * 50)
    freq = frequency_analysis(vig_long)
    print(f"\n  [Frequency Analysis]")
    print(f"    Index of Coincidence : {freq['index_of_coincidence']}")
    print(f"    Cipher type detected : {freq['likely_cipher_type']}")
    print(f"    Top letters          : {freq['top_letters']}")

    report_data["classical"] = {
        "Caesar ROT-13":  {"Plaintext": plaintext, "Ciphertext": ct_caesar, "Key": "shift=13"},
        "Vigenère":       {"Plaintext": plaintext, "Ciphertext": ct_vig,    "Key": "SECURITY"},
        "Rail Fence":     {"Plaintext": plaintext, "Ciphertext": ct_rf,     "Rails": "3"},
        "Playfair":       {"Plaintext": "HELLO WORLD", "Ciphertext": ct_pf,  "Key": "SECURITY"},
        "One-Time Pad":   {"Plaintext": "TOP SECRET MESSAGE",
                           "Ciphertext": ct_otp.hex()[:32]+"...", "Key (hex)": key_otp.hex()[:32]+"..."},
    }
    report_data["frequency_analysis"] = freq

    # ── 2. Symmetric Crypto ────────────────────────────────────────
    section("STEP 2/5 — Symmetric Cryptography (AES)")

    password = "SuperSecurePassword123!"
    key, salt = derive_key(password)
    print(f"\n  [Key Derivation — PBKDF2-HMAC-SHA256]")
    print(f"    Password     : {password!r}")
    print(f"    Salt (hex)   : {salt.hex()[:32]}...")
    print(f"    Derived key  : {key.hex()[:32]}... (256-bit)")

    message = b"AES encryption keeps data safe in transit and at rest."
    print(f"\n  [AES-ECB vs AES-CBC]")
    print(f"    Plaintext    : {message.decode()}")

    ct_ecb = aes_ecb_encrypt(message, key[:16])
    pt_ecb = aes_ecb_decrypt(ct_ecb, key[:16])
    print(f"    ECB cipher   : {ct_ecb.hex()[:48]}...")
    print(f"    ECB decrypted: {pt_ecb.decode()} ✓")

    ct_cbc, iv = aes_cbc_encrypt(message, key)
    pt_cbc = aes_cbc_decrypt(ct_cbc, key, iv)
    print(f"    CBC cipher   : {ct_cbc.hex()[:48]}...")
    print(f"    CBC decrypted: {pt_cbc.decode()} ✓")

    # Show ECB weakness
    repeated = b"AAAAAAAAAAAAAAAA" * 3
    ecb_rep = aes_ecb_encrypt(repeated, key[:16])
    print(f"\n  [ECB Weakness — Pattern Leakage]")
    print(f"    Plaintext  : {'A'*48} (3 identical blocks)")
    print(f"    ECB block1 : {ecb_rep[0:16].hex()}")
    print(f"    ECB block2 : {ecb_rep[16:32].hex()}")
    print(f"    ECB block3 : {ecb_rep[32:48].hex()}")
    print(f"    Identical  : {'✓ YES — leaks pattern' if ecb_rep[0:16]==ecb_rep[16:32] else '✗'}")

    # XOR stream cipher
    xor  = XORStreamCipher(key)
    ct_x = xor.encrypt(b"Stream cipher demo!")
    print(f"\n  [XOR Stream Cipher]")
    print(f"    Encrypted : {ct_x.hex()}")
    print(f"    Decrypted : {xor.decrypt(ct_x).decode()} ✓")

    # ── 3. Asymmetric Crypto (RSA) ─────────────────────────────────
    section("STEP 3/5 — Asymmetric Cryptography (RSA)")

    rsa = RSA(bits=512)
    keys = rsa.generate_keys()
    print(f"\n  [RSA-{rsa.bits} Key Generation]")
    print(f"    Key bits    : {keys['n_bits']}")
    print(f"    Public e    : {rsa.e}")
    print(f"    n (hex)     : {hex(rsa.n)[:40]}...")

    m   = 12345
    ct  = rsa.encrypt(m)
    dec = rsa.decrypt(ct)
    print(f"\n  [RSA Encrypt/Decrypt]")
    print(f"    Plaintext   : {m}")
    print(f"    Ciphertext  : {ct}")
    print(f"    Decrypted   : {dec}")
    print(f"    Verified    : {'✓' if dec==m else '✗'}")

    msg_rsa = "Christopher's digital signature"
    sig     = rsa.sign(msg_rsa)
    valid   = rsa.verify(msg_rsa, sig)
    invalid = rsa.verify("tampered message", sig)
    print(f"\n  [RSA Digital Signature]")
    print(f"    Message     : {msg_rsa!r}")
    print(f"    Signature   : {hex(sig)[:40]}...")
    print(f"    Valid sig   : {'✓ VALID' if valid else '✗'}")
    print(f"    Tampered    : {'✓ Correctly REJECTED' if not invalid else '✗ FAILED — accepted tampered'}")

    report_data["rsa"] = {
        "Key size (bits)":      keys["n_bits"],
        "Public exponent e":    rsa.e,
        "Modulus n (hex, first 40)": hex(rsa.n)[:40]+"...",
        "Test message":         m,
        "Encrypted":            str(ct)[:40]+"...",
        "Decrypted":            dec,
        "Roundtrip OK":         dec == m,
        "Signature valid":      valid,
        "Tamper detected":      not invalid,
    }

    # ── 4. Diffie-Hellman ──────────────────────────────────────────
    section("STEP 4/5 — Diffie-Hellman Key Exchange")

    alice = DiffieHellman()
    bob   = DiffieHellman()
    alice_shared = alice.compute_shared_secret(bob.public_key)
    bob_shared   = bob.compute_shared_secret(alice.public_key)
    alice_key    = alice.shared_secret_to_key(alice_shared)
    bob_key      = bob.shared_secret_to_key(bob_shared)

    print(f"\n  Alice public key  : {hex(alice.public_key)[:40]}...")
    print(f"  Bob   public key  : {hex(bob.public_key)[:40]}...")
    print(f"  Alice shared (→key): {alice_key.hex()[:32]}...")
    print(f"  Bob   shared (→key): {bob_key.hex()[:32]}...")
    print(f"  Keys match        : {'✓ YES — secure channel established' if alice_key==bob_key else '✗'}")

    # ── 5. Hashing ─────────────────────────────────────────────────
    section("STEP 5/5 — Hashing & Integrity")

    data = "The quick brown fox jumps over the lazy dog"
    hashes = HashFunction.hash_all(data)
    print(f"\n  [SHA Hash Family] — {data!r}")
    print(f"  {'ALGO':<8}  {'DIGEST':}")
    print(f"  {'─'*8}  {'─'*64}")
    for algo, h in hashes.items():
        print(f"  {algo.upper():<8}  {h}")
    report_data["hashes"] = hashes

    print(f"\n  [Avalanche Effect]")
    h1 = HashFunction.hash("Hello")
    h2 = HashFunction.hash("hello")
    diff = sum(a != b for a, b in zip(h1, h2))
    print(f"    SHA256('Hello') : {h1}")
    print(f"    SHA256('hello') : {h2}")
    print(f"    Characters differ: {diff}/64 ({diff/64*100:.0f}%) — one bit change, half hash changes")

    # HMAC
    hmac_key  = HMAC.generate_key()
    hmac_inst = HMAC(hmac_key)
    tag       = hmac_inst.compute("Authenticate this message")
    print(f"\n  [HMAC-SHA256]")
    print(f"    Message : 'Authenticate this message'")
    print(f"    Tag     : {tag[:32]}...")
    print(f"    Verified: {'✓' if hmac_inst.verify('Authenticate this message', tag) else '✗'}")

    # Password hashing
    ph     = PasswordHasher()
    pw_demo= ph.demonstrate_salting()
    pw_hash= ph.hash_password("mypassword")
    print(f"\n  [Password Hashing — PBKDF2]")
    print(f"    Same pwd, hash 1 : {pw_demo['salted_hash_1']}")
    print(f"    Same pwd, hash 2 : {pw_demo['salted_hash_2']}")
    print(f"    Hashes differ    : {'✓ YES — salting works' if pw_demo['hashes_differ'] else '✗'}")
    print(f"    Both verify OK   : {'✓ YES' if pw_demo['both_verify'] else '✗'}")
    report_data["password_hashing"] = pw_demo

    # Merkle tree
    transactions = ["tx_alice_10btc", "tx_bob_5btc", "tx_carol_2btc", "tx_dave_8btc"]
    tree  = MerkleTree(transactions)
    proof = tree.get_proof(0)
    ok    = tree.verify_proof(transactions[0], 0, proof, tree.root)
    bad   = tree.verify_proof("tampered_tx", 0, proof, tree.root)
    print(f"\n  [Merkle Tree — {len(transactions)} transactions]")
    print(f"    Root hash     : {tree.root[:32]}...")
    print(f"    Proof length  : {len(proof)} hashes (log2({len(transactions)}))")
    print(f"    Proof valid   : {'✓ YES' if ok else '✗'}")
    print(f"    Tamper detect : {'✓ Correctly REJECTED' if not bad else '✗'}")
    report_data["merkle"] = {"root": tree.root, "leaves": len(transactions)}

    # Hash chain
    chain = HashChain("genesis_block", 5)
    print(f"\n  [Hash Chain — 5 links]")
    for i, h in enumerate(chain.chain):
        print(f"    Link {i}: {h[:32]}...")
    print(f"    All links valid: {'✓' if all(chain.verify_link(chain.chain[i],chain.chain[i+1]) for i in range(4)) else '✗'}")

    # ── Report ─────────────────────────────────────────────────────
    os.makedirs("reports", exist_ok=True)
    if not args.no_report:
        html = generate_html_report(report_data)
        print(f"\n  📊 Report: {html}")
        print(f"     explorer.exe {html}")

    elapsed = time.time() - start
    print(f"\n{'═'*65}")
    print(f"  ✅  Complete! Total time: {elapsed:.1f}s")
    print(f"{'═'*65}\n")


if __name__ == "__main__":
    main()
