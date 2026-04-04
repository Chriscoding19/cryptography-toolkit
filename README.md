# Cryptography Toolkit

A comprehensive cryptography implementation covering classical, symmetric, asymmetric, and hashing — all in pure Python with zero external dependencies.

---

## 📐 Architecture

```
cryptography-toolkit/
├── main.py                          ← Full demo pipeline (5 steps)
├── requirements.txt                 ← No external deps!
├── classical/
│   └── classical.py                 ← Caesar, Vigenère, Rail Fence, Playfair, OTP, Frequency Analysis
├── symmetric/
│   └── symmetric.py                 ← AES-128/256 (pure Python), ECB vs CBC, XOR stream cipher, PBKDF2
├── asymmetric/
│   └── asymmetric.py                ← RSA, Diffie-Hellman, ElGamal (from scratch)
├── hashing/
│   └── hashing.py                   ← SHA family, HMAC, Password hashing, Merkle tree, Hash chain
├── reports/
│   └── report_generator.py          ← HTML report
└── tests/
    └── test_cryptography.py         ← 67 unit tests
```

---

## Quick Start

```bash
# No dependencies — pure Python 3.8+
python3 main.py

# Run tests
python3 tests/test_cryptography.py

# View HTML report
explorer.exe reports/crypto_report_*.html
```

---

## What's Implemented

### Classical Ciphers (5)
| Cipher | Type | Security |
|---|---|---|
| **Caesar** | Monoalphabetic substitution | Trivial — 26 possible keys |
| **Vigenère** | Polyalphabetic substitution | Resisted 300 years — broken by Kasiski |
| **Rail Fence** | Transposition | Weak — pattern visible |
| **Playfair** | Digraph substitution | Used in WWI by British forces |
| **One-Time Pad** | XOR / Vernam | **Theoretically unbreakable** (Shannon 1949) |

### Symmetric Cryptography
- **AES-128 / AES-256** — Pure Python implementation (FIPS 197 compliant)
  - **ECB mode** — demonstrates pattern leakage weakness
  - **CBC mode** — secure, industry-standard
- **XOR Stream Cipher** — keystream via SHA-256 counter mode
- **PBKDF2-HMAC-SHA256** — key derivation from passwords (100K iterations)

### Asymmetric Cryptography (3)
| Algorithm | Security Basis | Used For |
|---|---|---|
| **RSA** | Integer factorisation | Encrypt/decrypt, digital signatures |
| **Diffie-Hellman** | Discrete logarithm | Key exchange over insecure channel |
| **ElGamal** | Discrete logarithm | Public-key encryption |

### Hashing & Integrity
- **SHA family** — MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **HMAC-SHA256** — authentication + integrity (requires secret key)
- **Password Hashing** — PBKDF2 with salt (100K iterations, constant-time verify)
- **Merkle Tree** — O(log n) integrity proofs (used in Bitcoin, Ethereum)
- **Hash Chain** — S/KEY one-time passwords and blockchain linking
- **Avalanche Effect** — demonstrated: 1-bit input change → ~50% hash change

---

## Technologies
- **Language**: Python 3.8+ (zero external dependencies)
- **Stdlib used**: `hashlib`, `hmac`, `secrets`, `struct`, `random`, `math`
