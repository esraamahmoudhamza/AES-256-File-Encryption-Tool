# File Encryption Tool - Python + CustomTkinter (AES-256-GCM)
# -----------------------------------------------------------
# Requirements:
#   pip install customtkinter cryptography
#
# Features:
# - AES-256-GCM encryption with PBKDF2-HMAC(SHA-256) key derivation
# - Per-file random salt & nonce, strong parameters (200k PBKDF2 iterations)
# - Streams large files in chunks (no need to load into memory)
# - Stores original filename inside the encrypted file header
# - Progress bar, status messages, show/hide password, light/dark toggle
# - Nice minimal UI with CustomTkinter
#
# File format (little endian where relevant):
#   [4 bytes]  magic: b'FET1'
#   [16]       salt
#   [12]       nonce
#   [2]        name_len (unsigned short)
#   [name_len] original basename (utf-8)
#   [...]      ciphertext stream
#   [16]       GCM tag (appended at end)
#
# Decryption restores the original filename next to the .enc file unless a custom output directory is chosen.

