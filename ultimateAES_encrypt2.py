#!/usr/bin/env python3
"""
UltimateAES_encrypt (uae)

Encrypts an input file with AES-CBC and writes:
 - payload.b64  : base64 of IV||ciphertext
 - key.b64      : base64 of the raw key (if requested)

Output formats:
 - b64     : base64 (IV + ciphertext)
 - c       : C-style unsigned char array (IV + ciphertext)
 - vb      : Visual Basic-style Byte() array (IV + ciphertext)
 - hex     : continuous hex string (IV + ciphertext) e.g. 0011aaff...
 - csharp  : C# byte[] initializer (IV + ciphertext)

The script now prints the total byte count of IV+ciphertext (decimal and hex) for all outputs.
"""
import argparse
import base64
import os
import sys
import secrets
import string
import random
from hashlib import sha256
from Crypto.Cipher import AES

def parse_args():
    parser = argparse.ArgumentParser(description="Encrypts a binary file. Extract shellcode w/ShellcodeFormatter.")
    parser.add_argument("-i", "--input", default="uae.bin", help="Input binary file to encrypt.")
    parser.add_argument("-k", "--key", default="", help="Encryption key (string). If empty and --generate-key not used, will exit.")
    parser.add_argument("--generate-key", action="store_true", help="Generate a random 32-byte key and save it to key.b64.")
    parser.add_argument("-f", "--format", default="b64", choices=["b64", "c", "vb", "hex", "csharp"],
                        help="Output format: b64, c, vb, hex, or csharp.")
    parser.add_argument("--save-key", action="store_true", help="Save the raw key (base64) to ./key.b64")
    return parser.parse_args()

def get_random_string(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

def derive_key(key_input):
    """Derive a fixed-length key (32 bytes) from provided string/bytes using SHA-256."""
    if isinstance(key_input, str):
        key_bytes = key_input.encode('utf-8')
    else:
        key_bytes = key_input
    return sha256(key_bytes).digest()  # 32 bytes

def pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len]) * padding_len

def encrypt(aes_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # AES key must be 16, 24 or 32 bytes. Truncate to supported length.
    if len(aes_key) >= 32:
        k = aes_key[:32]
    elif len(aes_key) >= 24:
        k = aes_key[:24]
    else:
        k = aes_key[:16]
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, 16))

def to_c_array(data: bytes, varname="payload", chunk=16, byte_count=None):
    parts = [', '.join(f'0x{b:02x}' for b in data[i:i+chunk]) for i in range(0, len(data), chunk)]
    body = ",\n    ".join(parts)
    header = f"/* payload bytes: {byte_count} (0x{byte_count:02x}) */\n" if byte_count is not None else ""
    return f"{header}unsigned char {varname}[] = {{\n    {body}\n}};"

def to_vb_array(data: bytes, varname="payload", chunk=16, byte_count=None):
    hex_items = [f"&H{b:02X}" for b in data]
    lines = []
    for i in range(0, len(hex_items), chunk):
        lines.append(', '.join(hex_items[i:i+chunk]))
    if len(lines) == 1:
        body = lines[0]
    else:
        body = " _\n    ".join(lines)
    header = f"\' payload bytes: {byte_count} (0x{byte_count:02x})\n" if byte_count is not None else ""
    return f"{header}Dim {varname} As Byte() = {{ {body} }}"

def to_hex_string(data: bytes):
    """Return a continuous lowercase hex string (no prefix)."""
    return ''.join(f'{b:02x}' for b in data)

def to_csharp_array(data: bytes, varname="payload", chunk=16, byte_count=None):
    parts = [', '.join(f'0x{b:02x}' for b in data[i:i+chunk]) for i in range(0, len(data), chunk)]
    body = ",\n    ".join(parts)
    header = f"// payload bytes: {byte_count} (0x{byte_count:02x})\n" if byte_count is not None else ""
    return f"{header}byte[] {varname} = new byte[] {{\n    {body}\n}};"

def main():
    args = parse_args()

    # Validate input file
    if not os.path.isfile(args.input):
        print(f"Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Determine key material
    if args.generate_key:
        raw_key = get_random_string(32).encode('utf-8')
    elif args.key:
        raw_key = args.key.encode('utf-8')
    else:
        print("No key provided. Use --generate-key to auto-generate or supply -k KEY.", file=sys.stderr)
        sys.exit(1)

    # Derive AES key (32 bytes)
    hkey = derive_key(raw_key)

    # Random IV (16 bytes)
    iv = secrets.token_bytes(16)

    # Read plaintext
    with open(args.input, "rb") as fh:
        plaintext = fh.read()

    # Encrypt
    ciphertext = encrypt(hkey, iv, plaintext)

    # Final blob: IV || ciphertext
    final_blob = iv + ciphertext

    # Byte count for IV + ciphertext
    byte_count = len(final_blob)

    # Save base64 payload file
    b64 = base64.b64encode(final_blob).decode('utf-8')
    with open("./payload.b64", "w") as fh:
        fh.write(b64)

    # Optionally save the raw key material (base64)
    if args.save_key or args.generate_key:
        key_b64 = base64.b64encode(raw_key).decode('utf-8')
        with open("./key.b64", "w") as fh:
            fh.write(key_b64)

    # Output in requested format (include byte count)
    if args.format == "b64":
        print(f"[+] Base64 output (IV + ciphertext) - bytes: {byte_count} (0x{byte_count:02x}):")
        print(b64)
    elif args.format == "c":
        print(f"[+] C output (IV + ciphertext) - bytes: {byte_count} (0x{byte_count:02x}):")
        print(to_c_array(final_blob, varname="payload", byte_count=byte_count))
    elif args.format == "vb":
        print(f"[+] VB output (IV + ciphertext) - bytes: {byte_count} (0x{byte_count:02x}):")
        print(to_vb_array(final_blob, varname="payload", byte_count=byte_count))
    elif args.format == "hex":
        print(f"[+] Hex output (IV + ciphertext) - bytes: {byte_count} (0x{byte_count:02x}):")
        print(to_hex_string(final_blob))
    else:  # csharp
        print(f"[+] C# output (IV + ciphertext) - bytes: {byte_count} (0x{byte_count:02x}):")
        print(to_csharp_array(final_blob, varname="payload", byte_count=byte_count))

    print("\n[+] Finished. Files written: ./payload.b64" + (", ./key.b64" if (args.save_key or args.generate_key) else ""))

if __name__ == "__main__":
    main()
