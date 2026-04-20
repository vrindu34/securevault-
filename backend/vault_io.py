

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
