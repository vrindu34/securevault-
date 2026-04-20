

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad



RSA_KEY_BITS   = 2048          # RSA key size (NIST minimum for long-term security)
AES_KEY_BYTES  = 32            # 256-bit AES key
AES_BLOCK_BYTES = 16           # AES block size (fixed at 128 bits)



class CryptoEngine:
   

    @staticmethod
    def generate_rsa_keypair() -> tuple[bytes, bytes]:
       
        key = RSA.generate(RSA_KEY_BITS)
        private_pem = key.export_key("PEM")          # PKCS#1 format
        public_pem  = key.publickey().export_key("PEM")
        return private_pem, public_pem

   
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
        
        return hashlib.sha256(data).digest()

   
    @staticmethod
    def sign(digest: bytes, private_key_pem: bytes) -> bytes:
      
        key  = RSA.import_key(private_key_pem)
        h    = SHA256.new(digest)          # wrap digest so PSS can re-hash
        sig  = pss.new(key).sign(h)
        return sig

    @staticmethod
    def verify_signature(digest: bytes, signature: bytes, public_key_pem: bytes) -> bool:
     
        try:
            key = RSA.import_key(public_key_pem)
            h   = SHA256.new(digest)
            pss.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def generate_aes_key() -> bytes:
      
        return os.urandom(AES_KEY_BYTES)

    @staticmethod
    def encrypt_aes_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    
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
       
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(plaintext, AES_BLOCK_BYTES)
        return cipher.encrypt(padded)
