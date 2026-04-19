"""
crypto_engine.py
================
Core cryptographic operations for the Secure File Sharing System.
Implements a Sign-then-Encrypt hybrid workflow using RSA-2048 + AES-256-CBC.

Workflow Summary:
  ENCRYPT: hash(file) → sign(hash, sender_priv) → aes_key → encrypt(file, aes_key, CBC)
           → wrap(aes_key, recipient_pub) → bundle(ciphertext, wrapped_key, signature, iv)
  DECRYPT: unwrap(aes_key, recipient_priv) → decrypt(ciphertext, aes_key, iv)
           → hash(plaintext) → verify(signature, hash, sender_pub)
"""

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RSA_KEY_BITS   = 2048          # RSA key size (NIST minimum for long-term security)
AES_KEY_BYTES  = 32            # 256-bit AES key
AES_BLOCK_BYTES = 16           # AES block size (fixed at 128 bits)


# ---------------------------------------------------------------------------
# CryptoEngine  –  stateless helper; all methods are @staticmethod
# ---------------------------------------------------------------------------
class CryptoEngine:
    """
    Provides all low-level cryptographic primitives.
    No state is stored here — keys and data are passed in explicitly,
    which makes the class easy to unit-test and audit.
    """

    # ------------------------------------------------------------------ #
    #  Key Generation                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_rsa_keypair() -> tuple[bytes, bytes]:
        """
        Generate an RSA-2048 key pair.

        Returns
        -------
        (private_key_pem, public_key_pem) as raw bytes.

        Security notes:
          • PyCryptodome's RSA.generate() uses os.urandom() internally,
            which delegates to the OS CSPRNG (/dev/urandom on Linux,
            CryptGenRandom on Windows).
          • The private key PEM is unencrypted here; the caller (KeyManager)
            is responsible for protecting it on disk (e.g., passphrase or
            file-permission hardening).
        """
        key = RSA.generate(RSA_KEY_BITS)
        private_pem = key.export_key("PEM")          # PKCS#1 format
        public_pem  = key.publickey().export_key("PEM")
        return private_pem, public_pem

    # ------------------------------------------------------------------ #
    #  Hashing                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def sha256_file(filepath: str) -> bytes:
        """
        Compute SHA-256 of a file in 64 KiB chunks to support large files
        without loading the entire content into memory.

        Returns the raw 32-byte digest.
        """
        h = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.digest()

    @staticmethod
    def sha256_bytes(data: bytes) -> bytes:
        """Compute SHA-256 of an in-memory byte string."""
        return hashlib.sha256(data).digest()

    # ------------------------------------------------------------------ #
    #  Digital Signature  (RSA-PSS with SHA-256)                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def sign(digest: bytes, private_key_pem: bytes) -> bytes:
        """
        Sign a SHA-256 digest using RSA-PSS.

        Why PSS instead of PKCS#1 v1.5?
        RSA-PSS provides a security proof under the random oracle model,
        while PKCS#1 v1.5 signatures have known structural weaknesses
        (Bleichenbacher-style attacks on some implementations).

        Parameters
        ----------
        digest          : 32-byte SHA-256 hash of the plaintext.
        private_key_pem : Sender's RSA private key in PEM format.

        Returns
        -------
        Raw signature bytes.
        """
        key  = RSA.import_key(private_key_pem)
        h    = SHA256.new(digest)          # wrap digest so PSS can re-hash
        sig  = pss.new(key).sign(h)
        return sig

    @staticmethod
    def verify_signature(digest: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """
        Verify an RSA-PSS signature.

        Returns True on success, False on any verification failure.
        Failures include: wrong key, tampered file, corrupted signature.
        """
        try:
            key = RSA.import_key(public_key_pem)
            h   = SHA256.new(digest)
            pss.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------ #
    #  AES-256-CBC  –  symmetric file encryption                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_aes_key() -> bytes:
        """
        Generate a 256-bit AES session key using the OS CSPRNG.
        This key is used for exactly ONE encryption operation, then
        discarded (forward secrecy at the file level).
        """
        return os.urandom(AES_KEY_BYTES)

    @staticmethod
    def encrypt_aes_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-CBC.

        IV Handling
        -----------
        A fresh 16-byte Initialization Vector is generated via os.urandom()
        for every encryption call. The IV does NOT need to be secret — it
        only needs to be unpredictable and unique per (key, message) pair.
        It is stored alongside the ciphertext in the Vault bundle so the
        recipient can reconstruct the cipher state during decryption.

        PKCS#7 padding is applied so that the plaintext length is always
        a multiple of the 16-byte AES block size.

        Returns
        -------
        (iv, ciphertext)  –  both as raw bytes.
        """
        iv      = os.urandom(AES_BLOCK_BYTES)          # fresh IV every call
        cipher  = AES.new(key, AES.MODE_CBC, iv)
        padded  = pad(plaintext, AES_BLOCK_BYTES)       # PKCS#7
        return iv, cipher.encrypt(padded)

    @staticmethod
    def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt AES-256-CBC ciphertext and remove PKCS#7 padding.

        Raises ValueError if padding is invalid (indicating tampering or
        wrong key — never silently return garbled plaintext).
        """
        cipher    = AES.new(key, AES.MODE_CBC, iv)
        padded    = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES_BLOCK_BYTES)      # raises on bad padding
        return plaintext

    # ------------------------------------------------------------------ #
    #  RSA Key Wrapping  (AES key transport)                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def wrap_aes_key(aes_key: bytes, recipient_public_pem: bytes) -> bytes:
        """
        Encrypt (wrap) the AES session key with the recipient's RSA public
        key using OAEP padding (SHA-256 hash, MGF1 mask).

        Why OAEP?
        OAEP is probabilistic (adds randomness), which means encrypting
        the same AES key twice produces different ciphertexts. This
        defeats any chosen-ciphertext or replay attack on the key transport.
        """
        pub_key  = RSA.import_key(recipient_public_pem)
        cipher   = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
        return cipher.encrypt(aes_key)

    @staticmethod
    def unwrap_aes_key(wrapped_key: bytes, recipient_private_pem: bytes) -> bytes:
        """
        Decrypt (unwrap) the AES session key using the recipient's RSA
        private key.  Raises ValueError on decryption failure.
        """
        priv_key = RSA.import_key(recipient_private_pem)
        cipher   = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
        return cipher.decrypt(wrapped_key)

    # ------------------------------------------------------------------ #
    #  Security Analysis  –  AES-ECB Pattern Leakage Demo                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def encrypt_aes_ecb_demo(plaintext: bytes, key: bytes) -> bytes:
        """
        INTENTIONALLY INSECURE — for educational demonstration ONLY.

        AES-ECB (Electronic Code Book) encrypts each 16-byte block
        independently with the same key and NO IV.  This means:
          • Identical plaintext blocks → identical ciphertext blocks.
          • Structural patterns in the plaintext (e.g., uniform-colour
            regions in a bitmap) survive encryption as structural patterns
            in the ciphertext.

        Known Plaintext Attack (KPA) relevance:
        If an attacker knows any 16-byte block of plaintext AND the
        corresponding ciphertext block, they can build a dictionary of
        block→ciphertext mappings.  Because ECB is deterministic and
        stateless, every future occurrence of that plaintext block in ANY
        message encrypted with the same key will match the dictionary entry.

        CBC prevents this because each plaintext block is XOR'd with the
        previous ciphertext block before encryption, making the output of
        each block depend on all prior blocks AND the IV.

        USE THIS FUNCTION ONLY for generating "bad" ciphertext to visualise
        pattern leakage in your project report.  Never use ECB in production.
        """
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(plaintext, AES_BLOCK_BYTES)
        return cipher.encrypt(padded)
