"""
classical.py
------------
Classical cipher implementations:

  1. Caesar Cipher       — Shift cipher (ROT-n)
  2. Vigenère Cipher     — Polyalphabetic substitution
  3. Rail Fence Cipher   — Transposition cipher
  4. Playfair Cipher     — Digraph substitution (5x5 key square)
  5. One-Time Pad        — Theoretically unbreakable (Vernam cipher)
  6. Frequency Analysis  — Cryptanalysis of substitution ciphers
"""

import string
import random
from collections import Counter


# ══════════════════════════════════════════════════════════════════
# 1. CAESAR CIPHER
# ══════════════════════════════════════════════════════════════════

class CaesarCipher:
    """
    ROT-n shift cipher. Each letter shifted by 'shift' positions.
    Key space: 26 (trivially brute-forceable).
    """

    def __init__(self, shift: int = 13):
        self.shift = shift % 26

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, self.shift)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, -self.shift)

    def _transform(self, text: str, shift: int) -> str:
        result = []
        for ch in text:
            if ch.isupper():
                result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            elif ch.islower():
                result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(ch)
        return ''.join(result)

    def brute_force(self, ciphertext: str) -> list:
        """Try all 26 shifts and return all possible plaintexts."""
        return [
            {"shift": i, "plaintext": self._transform(ciphertext, -i)}
            for i in range(26)
        ]


# ══════════════════════════════════════════════════════════════════
# 2. VIGENÈRE CIPHER
# ══════════════════════════════════════════════════════════════════

class VigenereCipher:
    """
    Polyalphabetic substitution using a repeating keyword.
    Each letter uses a different Caesar shift based on key character.
    Resisted cryptanalysis for 300 years ('le chiffre indéchiffrable').
    """

    def __init__(self, key: str):
        self.key = ''.join(c.upper() for c in key if c.isalpha())
        if not self.key:
            raise ValueError("Key must contain at least one letter")

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, encrypt: bool) -> str:
        result = []
        key_idx = 0
        for ch in text:
            if ch.isalpha():
                shift     = ord(self.key[key_idx % len(self.key)]) - ord('A')
                if not encrypt:
                    shift = -shift
                base      = ord('A') if ch.isupper() else ord('a')
                new_ch    = chr((ord(ch) - base + shift) % 26 + base)
                result.append(new_ch)
                key_idx += 1
            else:
                result.append(ch)
        return ''.join(result)

    def kasiski_test(self, ciphertext: str, min_len: int = 3) -> dict:
        """
        Kasiski examination: find repeated sequences to estimate key length.
        Returns distance GCDs as probable key lengths.
        """
        ct      = ''.join(c for c in ciphertext.upper() if c.isalpha())
        repeats = {}
        for length in range(min_len, min_len + 4):
            for i in range(len(ct) - length):
                seq = ct[i:i+length]
                for j in range(i+length, len(ct) - length + 1):
                    if ct[j:j+length] == seq:
                        dist = j - i
                        if seq not in repeats:
                            repeats[seq] = []
                        repeats[seq].append(dist)

        from math import gcd
        from functools import reduce
        gcds = []
        for distances in repeats.values():
            if len(distances) > 1:
                g = reduce(gcd, distances)
                gcds.append(g)

        key_len_votes = Counter(gcds)
        return {
            "repeated_sequences": len(repeats),
            "probable_key_lengths": key_len_votes.most_common(5),
        }


# ══════════════════════════════════════════════════════════════════
# 3. RAIL FENCE CIPHER
# ══════════════════════════════════════════════════════════════════

class RailFenceCipher:
    """
    Transposition cipher. Text written diagonally across 'rails'
    then read row by row.
    """

    def __init__(self, rails: int = 3):
        if rails < 2:
            raise ValueError("Need at least 2 rails")
        self.rails = rails

    def encrypt(self, plaintext: str) -> str:
        fence  = [[] for _ in range(self.rails)]
        rail   = 0
        going_down = True
        for ch in plaintext:
            fence[rail].append(ch)
            if rail == self.rails - 1:
                going_down = False
            elif rail == 0:
                going_down = True
            rail += 1 if going_down else -1
        return ''.join(''.join(r) for r in fence)

    def decrypt(self, ciphertext: str) -> str:
        n      = len(ciphertext)
        fence  = [[] for _ in range(self.rails)]
        rail   = 0
        going_down = True
        pattern = []
        for i in range(n):
            pattern.append(rail)
            if rail == self.rails - 1:
                going_down = False
            elif rail == 0:
                going_down = True
            rail += 1 if going_down else -1

        counts = Counter(pattern)
        idx    = 0
        rows   = {}
        for r in range(self.rails):
            rows[r] = list(ciphertext[idx:idx+counts[r]])
            idx += counts[r]

        result = []
        row_ptrs = {r: 0 for r in range(self.rails)}
        for r in pattern:
            result.append(rows[r][row_ptrs[r]])
            row_ptrs[r] += 1
        return ''.join(result)


# ══════════════════════════════════════════════════════════════════
# 4. PLAYFAIR CIPHER
# ══════════════════════════════════════════════════════════════════

class PlayfairCipher:
    """
    Digraph substitution cipher using a 5x5 key square (I=J).
    Used by British forces in WWI. Much stronger than simple substitution.
    """

    def __init__(self, key: str):
        self.matrix, self.pos = self._build_matrix(key)

    def _build_matrix(self, key: str):
        key   = ''.join(c.upper() for c in key if c.isalpha()).replace('J','I')
        seen  = []
        for c in key + string.ascii_uppercase.replace('J',''):
            if c not in seen:
                seen.append(c)
        matrix = [seen[i*5:(i+1)*5] for i in range(5)]
        pos    = {seen[i]: (i//5, i%5) for i in range(25)}
        return matrix, pos

    def _prepare(self, text: str) -> list:
        text  = ''.join(c.upper() for c in text if c.isalpha()).replace('J','I')
        pairs = []
        i     = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                pairs.append((a,'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        return pairs

    def _transform_pair(self, a: str, b: str, encrypt: bool) -> str:
        ra, ca = self.pos[a]
        rb, cb = self.pos[b]
        d      = 1 if encrypt else -1

        if ra == rb:                    # Same row
            return self.matrix[ra][(ca+d)%5] + self.matrix[rb][(cb+d)%5]
        elif ca == cb:                  # Same column
            return self.matrix[(ra+d)%5][ca] + self.matrix[(rb+d)%5][cb]
        else:                           # Rectangle
            return self.matrix[ra][cb]  + self.matrix[rb][ca]

    def encrypt(self, plaintext: str) -> str:
        return ''.join(self._transform_pair(a,b,True)  for a,b in self._prepare(plaintext))

    def decrypt(self, ciphertext: str) -> str:
        pairs = [(ciphertext[i], ciphertext[i+1]) for i in range(0,len(ciphertext),2)]
        return ''.join(self._transform_pair(a,b,False) for a,b in pairs)


# ══════════════════════════════════════════════════════════════════
# 5. ONE-TIME PAD (Vernam Cipher)
# ══════════════════════════════════════════════════════════════════

class OneTimePad:
    """
    Theoretically unbreakable cipher (proven by Shannon, 1949).
    Requirements: key must be truly random, same length as message, used only once.
    XOR-based implementation on bytes.
    """

    @staticmethod
    def generate_key(length: int) -> bytes:
        return bytes(random.randint(0, 255) for _ in range(length))

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        if len(key) < len(plaintext):
            raise ValueError("Key must be at least as long as plaintext")
        return bytes(p ^ k for p, k in zip(plaintext, key))

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """XOR is its own inverse — decrypt is identical to encrypt."""
        return OneTimePad.encrypt(ciphertext, key)

    @staticmethod
    def encrypt_text(plaintext: str, key: bytes = None) -> tuple:
        """Encrypt a string. Returns (ciphertext_bytes, key_bytes)."""
        data = plaintext.encode('utf-8')
        if key is None:
            key = OneTimePad.generate_key(len(data))
        ct   = OneTimePad.encrypt(data, key)
        return ct, key

    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes) -> str:
        return OneTimePad.decrypt(ciphertext, key).decode('utf-8')


# ══════════════════════════════════════════════════════════════════
# 6. FREQUENCY ANALYSIS (Cryptanalysis)
# ══════════════════════════════════════════════════════════════════

ENGLISH_FREQ = {
    'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,
    'H':6.09,'R':5.99,'D':4.25,'L':4.03,'C':2.78,'U':2.76,'M':2.41,
    'W':2.36,'F':2.23,'G':2.02,'Y':1.97,'P':1.93,'B':1.49,'V':0.98,
    'K':0.77,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07,
}


def frequency_analysis(ciphertext: str) -> dict:
    """
    Analyse letter frequencies in ciphertext and compare to English.
    Most useful for breaking simple substitution ciphers.
    """
    letters = [c.upper() for c in ciphertext if c.isalpha()]
    total   = len(letters)
    if total == 0:
        return {}

    counts = Counter(letters)
    freq   = {ch: round(counts.get(ch,0)/total*100, 2) for ch in string.ascii_uppercase}

    # Index of Coincidence — high (~0.065) = monoalphabetic, low (~0.038) = polyalphabetic
    ic = sum(counts[c]*(counts[c]-1) for c in counts) / (total*(total-1)) if total > 1 else 0

    return {
        "letter_frequencies": freq,
        "index_of_coincidence": round(ic, 4),
        "likely_cipher_type": "Monoalphabetic" if ic > 0.055 else "Polyalphabetic",
        "top_letters": [ch for ch,_ in Counter(counts).most_common(5)],
        "english_top": list("ETAOINSHRD"),
        "total_letters": total,
    }
