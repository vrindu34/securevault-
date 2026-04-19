"""
vault_io.py
===========
Handles reading plaintext files, writing/reading Vault bundles, and
the full Encrypt / Decrypt orchestration that ties CryptoEngine +
KeyManager together.

Vault Bundle Format
-------------------
A ".vault" file is a raw binary file with a simple length-prefixed layout:

  [4 bytes]  magic number  0x5641554C  ("VAUL")
  [4 bytes]  version       0x00000001
  [4 bytes]  len(wrapped_key)
  [N bytes]  wrapped_key   (RSA-OAEP encrypted AES key)
  [4 bytes]  len(signature)
  [N bytes]  signature     (RSA-PSS signature over SHA-256 of plaintext)
  [16 bytes] iv            (AES-CBC initialisation vector, always 16 bytes)
  [4 bytes]  len(ciphertext)
  [N bytes]  ciphertext    (AES-256-CBC encrypted file content)

All multi-byte integers are big-endian.

Why a custom binary format instead of JSON/base64?
  • No encoding overhead for large files (binary is ~33 % smaller than base64)
  • Deterministic parsing — no ambiguity from JSON libraries
  • Easy to inspect with a hex editor for coursework demonstration
"""

import struct
from pathlib import Path
from dataclasses import dataclass

from crypto_engine import CryptoEngine
from key_manager    import KeyManager


# ---------------------------------------------------------------------------
# Vault directory
# ---------------------------------------------------------------------------
VAULT_DIR = Path("vault/files")

MAGIC   = b"VAUL"
VERSION = struct.pack(">I", 1)          # big-endian uint32 = 1


# ---------------------------------------------------------------------------
# VaultBundle  –  simple data-transfer object
# ---------------------------------------------------------------------------
@dataclass
class VaultBundle:
    """In-memory representation of a vault file's contents."""
    wrapped_key : bytes   # RSA-OAEP( AES_key, recipient_pub )
    signature   : bytes   # RSA-PSS( SHA256(plaintext), sender_priv )
    iv          : bytes   # 16-byte AES-CBC initialisation vector
    ciphertext  : bytes   # AES-256-CBC( plaintext )


# ---------------------------------------------------------------------------
# FileIO  –  serialise / deserialise vault bundles
# ---------------------------------------------------------------------------
class FileIO:
    """Low-level binary read/write for .vault files."""

    @staticmethod
    def write_vault(bundle: VaultBundle, output_path: Path) -> None:
        """
        Serialise a VaultBundle to disk using the length-prefixed format
        described in the module docstring.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        def pack_field(data: bytes) -> bytes:
            """Prefix a byte string with its 4-byte big-endian length."""
            return struct.pack(">I", len(data)) + data

        with open(output_path, "wb") as fh:
            fh.write(MAGIC)
            fh.write(VERSION)
            fh.write(pack_field(bundle.wrapped_key))
            fh.write(pack_field(bundle.signature))
            fh.write(bundle.iv)                    # always 16 bytes, no prefix needed
            fh.write(pack_field(bundle.ciphertext))

    @staticmethod
    def read_vault(vault_path: Path) -> VaultBundle:
        """
        Deserialise a .vault file back into a VaultBundle.

        Raises ValueError on magic/version mismatch (wrong file type or
        corrupted header).
        """
        with open(vault_path, "rb") as fh:
            data = fh.read()

        offset = 0

        def read_field() -> bytes:
            nonlocal offset
            length = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            field  = data[offset: offset + length]
            offset += length
            return field

        # Validate magic and version
        magic   = data[0:4];  offset = 4
        version = data[4:8];  offset = 8

        if magic != MAGIC:
            raise ValueError(f"Not a valid vault file (bad magic: {magic!r})")
        if version != VERSION:
            raise ValueError(f"Unsupported vault version: {version!r}")

        wrapped_key = read_field()
        signature   = read_field()
        iv          = data[offset: offset + 16];  offset += 16
        ciphertext  = read_field()

        return VaultBundle(
            wrapped_key=wrapped_key,
            signature=signature,
            iv=iv,
            ciphertext=ciphertext,
        )


# ---------------------------------------------------------------------------
# VaultManager  –  high-level Encrypt / Decrypt orchestration
# ---------------------------------------------------------------------------
class VaultManager:
    """
    Orchestrates the full Sign-then-Encrypt and Decrypt-then-Verify workflows.

    Dependencies are injected (KeyManager, CryptoEngine, FileIO) to make
    each layer independently testable.
    """

    def __init__(self, vault_dir: Path = VAULT_DIR):
        self.vault_dir  = vault_dir
        self.key_manager = KeyManager()

    # ------------------------------------------------------------------ #
    #  ENCRYPT  –  "Lock" a file into a Vault bundle                      #
    # ------------------------------------------------------------------ #

    def encrypt_file(
        self,
        plaintext_path : str | Path,
        sender         : str,
        recipient      : str,
        output_name    : str | None = None,
    ) -> Path:
        """
        Full Sign-then-Encrypt pipeline.

        Steps
        -----
        1. Read the plaintext file from disk.
        2. Compute SHA-256(plaintext).
        3. Sign the digest with sender's RSA private key  →  signature.
        4. Generate a random AES-256 session key.
        5. Encrypt plaintext with AES-256-CBC (fresh IV)  →  (iv, ciphertext).
        6. Wrap the AES key with recipient's RSA public key  →  wrapped_key.
        7. Serialise (wrapped_key, signature, iv, ciphertext) to a .vault file.

        Parameters
        ----------
        plaintext_path : Path to the file to encrypt.
        sender         : Username of the signing party (must have private key).
        recipient      : Username of the decrypting party (must have public key in DB).
        output_name    : Optional vault filename stem (default: original filename + '.vault').

        Returns the Path of the created .vault file.
        """
        plaintext_path = Path(plaintext_path)
        if not plaintext_path.exists():
            raise FileNotFoundError(f"Input file not found: {plaintext_path}")

        print(f"\n[VaultManager] Encrypting '{plaintext_path.name}' ...")
        print(f"  Sender    : {sender}")
        print(f"  Recipient : {recipient}")

        # Step 1 – read plaintext
        plaintext = plaintext_path.read_bytes()
        print(f"  File size : {len(plaintext):,} bytes")

        # Step 2 – hash
        digest = CryptoEngine.sha256_bytes(plaintext)
        print(f"  SHA-256   : {digest.hex()}")

        # Step 3 – sign
        sender_priv = self.key_manager.load_private_key(sender)
        signature   = CryptoEngine.sign(digest, sender_priv)
        print(f"  Signature : {len(signature)} bytes (RSA-PSS)")

        # Step 4 – AES session key
        aes_key = CryptoEngine.generate_aes_key()

        # Step 5 – encrypt
        iv, ciphertext = CryptoEngine.encrypt_aes_cbc(plaintext, aes_key)
        print(f"  IV        : {iv.hex()}  (stored in vault, not secret)")
        print(f"  Ciphertext: {len(ciphertext):,} bytes (AES-256-CBC)")

        # Step 6 – wrap AES key
        recipient_pub = self.key_manager.get_public_key(recipient)
        wrapped_key   = CryptoEngine.wrap_aes_key(aes_key, recipient_pub)
        print(f"  Wrapped key: {len(wrapped_key)} bytes (RSA-OAEP)")

        # Step 7 – write vault
        stem        = output_name or plaintext_path.name
        vault_path  = self.vault_dir / f"{stem}.vault"
        bundle      = VaultBundle(wrapped_key, signature, iv, ciphertext)
        FileIO.write_vault(bundle, vault_path)

        print(f"  ✓ Vault written → {vault_path}")
        return vault_path

    # ------------------------------------------------------------------ #
    #  DECRYPT  –  "Unlock" a Vault bundle                                #
    # ------------------------------------------------------------------ #

    def decrypt_file(
        self,
        vault_path  : str | Path,
        recipient   : str,
        sender      : str,
        output_path : str | Path | None = None,
    ) -> Path:
        """
        Full Decrypt-then-Verify pipeline.

        Steps
        -----
        1. Deserialise the .vault file  →  VaultBundle.
        2. Unwrap the AES key using recipient's RSA private key.
        3. Decrypt ciphertext with AES-256-CBC using recovered key + stored IV.
        4. Compute SHA-256(plaintext).
        5. Verify signature using sender's RSA public key.
        6. Write plaintext to output_path.

        Raises
        ------
        ValueError  : if signature verification fails (tampering detected).
        Any exception from OAEP decryption if the wrong private key is used.

        Returns the Path of the decrypted output file.
        """
        vault_path = Path(vault_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {vault_path}")

        print(f"\n[VaultManager] Decrypting '{vault_path.name}' ...")
        print(f"  Recipient : {recipient}")
        print(f"  Sender    : {sender}")

        # Step 1 – parse vault
        bundle = FileIO.read_vault(vault_path)

        # Step 2 – unwrap AES key
        recipient_priv = self.key_manager.load_private_key(recipient)
        aes_key        = CryptoEngine.unwrap_aes_key(bundle.wrapped_key, recipient_priv)
        print(f"  AES key unwrapped successfully")

        # Step 3 – decrypt
        plaintext = CryptoEngine.decrypt_aes_cbc(bundle.ciphertext, aes_key, bundle.iv)
        print(f"  Decrypted : {len(plaintext):,} bytes")

        # Step 4 – hash plaintext
        digest = CryptoEngine.sha256_bytes(plaintext)
        print(f"  SHA-256   : {digest.hex()}")

        # Step 5 – verify signature
        sender_pub = self.key_manager.get_public_key(sender)
        valid      = CryptoEngine.verify_signature(digest, bundle.signature, sender_pub)

        if not valid:
            raise ValueError(
                "⚠  SIGNATURE VERIFICATION FAILED!\n"
                "The file may have been tampered with, or the sender identity is wrong.\n"
                "Do NOT trust the decrypted content."
            )
        print(f"  ✓ Signature valid — authenticity and integrity confirmed")

        # Step 6 – write plaintext
        if output_path is None:
            stem        = vault_path.stem          # removes '.vault'
            output_path = Path("vault/decrypted") / stem
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(plaintext)
        print(f"  ✓ Plaintext written → {output_path}")
        return output_path

    # ------------------------------------------------------------------ #
    #  Security Analysis  –  ECB pattern leakage demo                    #
    # ------------------------------------------------------------------ #

    def ecb_demo(self, plaintext_path: str | Path, aes_key: bytes | None = None) -> Path:
        """
        Encrypt a file with AES-ECB and save the result for visual comparison.

        If no aes_key is supplied, a random 256-bit key is generated.
        Returns the path of the ECB-encrypted output file.

        Usage in your report
        --------------------
        1. Use a 24-bit BMP bitmap (no compression) as input — the raw pixel
           data will show pattern leakage visually similar to the classic
           "ECB Penguin" demonstration.
        2. Encrypt the same file with CBC using encrypt_file().
        3. Compare the two outputs in a hex editor or image viewer.
        """
        plaintext_path = Path(plaintext_path)
        plaintext      = plaintext_path.read_bytes()

        if aes_key is None:
            aes_key = CryptoEngine.generate_aes_key()

        ecb_cipher = CryptoEngine.encrypt_aes_ecb_demo(plaintext, aes_key)

        out_path = Path("vault/ecb_demo") / (plaintext_path.name + ".ecb_demo")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(ecb_cipher)

        print(f"\n[ECB Demo] Output → {out_path}")
        print("  WARNING: ECB output shows pattern leakage. Do NOT use in production.")
        return out_path
