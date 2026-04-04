"""
classical_ciphers.py
--------------------
Implements classical (historical) encryption ciphers:

  1. Caesar Cipher      — Simple letter shift (ROT-N)
  2. Vigenere Cipher    — Polyalphabetic substitution with key
  3. Rail Fence Cipher  — Transposition cipher
  4. Playfair Cipher    — Digraph substitution (WW1 era)
  5. One-Time Pad       — Theoretically unbreakable XOR cipher
  6. Atbash Cipher      — Reverse alphabet substitution
"""

import string
import random


# ══════════════════════════════════════════════════════════════════
# 1. CAESAR CIPHER
# ══════════════════════════════════════════════════════════════════

class CaesarCipher:
    """
    Shifts each letter by 'shift' positions in the alphabet.
    ROT13 is Caesar with shift=13.
    Easily broken by frequency analysis (only 25 possible keys).
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
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return ''.join(result)

    def brute_force(self, ciphertext: str) -> list:
        """Try all 25 possible shifts."""
        return [
            {"shift": s, "text": self._transform(ciphertext, -s)}
            for s in range(1, 26)
        ]

    @property
    def name(self):
        return f"Caesar (shift={self.shift})"


# ══════════════════════════════════════════════════════════════════
# 2. VIGENERE CIPHER
# ══════════════════════════════════════════════════════════════════

class VigenereCipher:
    """
    Polyalphabetic substitution cipher using a repeating keyword.
    Each letter is shifted by the corresponding key letter's position.
    Much stronger than Caesar — resisted analysis for 300 years.
    Broken by Kasiski examination (finding key length via repeated trigrams).
    """

    def __init__(self, key: str):
        self.key = key.upper()
        if not all(c.isalpha() for c in self.key):
            raise ValueError("Key must contain only letters")

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, encrypt: bool) -> str:
        result  = []
        key_idx = 0
        for ch in text:
            if ch.isalpha():
                shift = ord(self.key[key_idx % len(self.key)]) - ord('A')
                if not encrypt:
                    shift = -shift
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                key_idx += 1
            else:
                result.append(ch)
        return ''.join(result)

    @property
    def name(self):
        return f"Vigenere (key='{self.key}')"


# ══════════════════════════════════════════════════════════════════
# 3. RAIL FENCE CIPHER (Transposition)
# ══════════════════════════════════════════════════════════════════

class RailFenceCipher:
    """
    Transposition cipher that writes text in a zigzag pattern
    across N 'rails' then reads off row by row.

    Example with 3 rails: "WEAREDISCOVEREDFLEEATON"
    Rail 0: W . . . E . . . I . . . V . . . E . . . T . .
    Rail 1: . E . R . D . S . O . E . E . F . E . A . O .
    Rail 2: . . A . . . C . . . R . . . L . . . N . . . .
    Ciphertext: WEIVET ERDSOEEFEA OACRL N
    """

    def __init__(self, rails: int = 3):
        if rails < 2:
            raise ValueError("Rails must be >= 2")
        self.rails = rails

    def encrypt(self, plaintext: str) -> str:
        fence = self._build_fence(len(plaintext))
        rows  = [[] for _ in range(self.rails)]
        for i, ch in enumerate(plaintext):
            rows[fence[i]].append(ch)
        return ''.join(''.join(row) for row in rows)

    def decrypt(self, ciphertext: str) -> str:
        n     = len(ciphertext)
        fence = self._build_fence(n)
        # Count characters per rail
        counts = [fence.count(r) for r in range(self.rails)]
        # Split ciphertext into rails
        rows   = []
        idx    = 0
        for c in counts:
            rows.append(list(ciphertext[idx:idx+c]))
            idx += c
        # Read off in zigzag order
        result   = []
        rail_idx = [0] * self.rails
        for rail in fence:
            result.append(rows[rail][rail_idx[rail]])
            rail_idx[rail] += 1
        return ''.join(result)

    def _build_fence(self, n: int) -> list:
        """Return rail index for each position."""
        fence = []
        rail  = 0
        delta = 1
        for _ in range(n):
            fence.append(rail)
            if rail == 0:
                delta = 1
            elif rail == self.rails - 1:
                delta = -1
            rail += delta
        return fence

    @property
    def name(self):
        return f"Rail Fence (rails={self.rails})"


# ══════════════════════════════════════════════════════════════════
# 4. PLAYFAIR CIPHER
# ══════════════════════════════════════════════════════════════════

class PlayfairCipher:
    """
    Digraph substitution cipher operating on pairs of letters.
    Uses a 5x5 key square (I and J share a cell).
    Used by the British military in WW1.
    """

    def __init__(self, key: str):
        self.key    = key.upper().replace('J', 'I')
        self.matrix = self._build_matrix()
        self.pos     = {ch: divmod(i, 5) for i, ch in enumerate(self.matrix)}

    def _build_matrix(self) -> list:
        seen   = []
        matrix = []
        for ch in self.key + string.ascii_uppercase:
            ch = ch.upper()
            if ch == 'J':
                ch = 'I'
            if ch.isalpha() and ch not in seen:
                seen.append(ch)
                matrix.append(ch)
        return matrix

    def _prepare(self, text: str) -> str:
        """Clean text and insert filler X between double letters."""
        text   = text.upper().replace('J', 'I')
        text   = ''.join(c for c in text if c.isalpha())
        result = []
        i      = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                result.extend([a, 'X'])
                i += 1
            else:
                result.extend([a, b])
                i += 2
        if len(result) % 2:
            result.append('X')
        return ''.join(result)

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, encrypt: bool) -> str:
        prepared = self._prepare(text)
        result   = []
        shift    = 1 if encrypt else -1

        for i in range(0, len(prepared), 2):
            a, b   = prepared[i], prepared[i+1]
            ra, ca = self.pos[a]
            rb, cb = self.pos[b]

            if ra == rb:          # Same row
                na = self.matrix[ra*5 + (ca+shift) % 5]
                nb = self.matrix[rb*5 + (cb+shift) % 5]
            elif ca == cb:        # Same column
                na = self.matrix[((ra+shift)%5)*5 + ca]
                nb = self.matrix[((rb+shift)%5)*5 + cb]
            else:                 # Rectangle
                na = self.matrix[ra*5 + cb]
                nb = self.matrix[rb*5 + ca]

            result.extend([na, nb])

        return ''.join(result)

    @property
    def name(self):
        return f"Playfair (key='{self.key[:8]}...')"


# ══════════════════════════════════════════════════════════════════
# 5. ONE-TIME PAD
# ══════════════════════════════════════════════════════════════════

class OneTimePad:
    """
    Theoretically unbreakable cipher proven by Claude Shannon (1949).
    Key must be:
      - Truly random
      - At least as long as the plaintext
      - Never reused (hence "one-time")
      - Kept completely secret

    XORs each byte of plaintext with a random key byte.
    Without the key, ciphertext is informationally secure.
    """

    def __init__(self, key: bytes = None):
        self.key = key

    def generate_key(self, length: int) -> bytes:
        """Generate a cryptographically random key."""
        import os
        self.key = os.urandom(length)
        return self.key

    def encrypt(self, plaintext: str) -> bytes:
        data = plaintext.encode('utf-8')
        if self.key is None:
            self.generate_key(len(data))
        if len(self.key) < len(data):
            raise ValueError("Key must be at least as long as plaintext")
        return bytes(p ^ k for p, k in zip(data, self.key))

    def decrypt(self, ciphertext: bytes) -> str:
        if self.key is None:
            raise ValueError("No key available for decryption")
        return bytes(c ^ k for c, k in zip(ciphertext, self.key)).decode('utf-8')

    @property
    def name(self):
        return "One-Time Pad (XOR)"


# ══════════════════════════════════════════════════════════════════
# 6. ATBASH CIPHER
# ══════════════════════════════════════════════════════════════════

class AtbashCipher:
    """
    Ancient Hebrew cipher: A↔Z, B↔Y, C↔X, ...
    Self-inverse (encryption = decryption).
    Named for the first two and last two Hebrew letters.
    """

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext)   # Self-inverse

    def _transform(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isupper():
                result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
            elif ch.islower():
                result.append(chr(ord('z') - (ord(ch) - ord('a'))))
            else:
                result.append(ch)
        return ''.join(result)

    @property
    def name(self):
        return "Atbash (reverse alphabet)"
