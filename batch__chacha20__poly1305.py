import os
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor, as_completed

def derive_key_from_password(password):
    # Derive a 32-byte key from a password using SHA-512, then truncate
    hash_digest = hashlib.sha512(password.encode("utf-8")).digest()
    return hash_digest[:32]

def encrypt_file(filepath, key):
    try:
        nonce = get_random_bytes(12)  # Generate a random 12-byte nonce for each file
        with open(filepath, "rb") as f:
            plaintext = f.read()      # Read entire file content
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Encrypt and generate tag
        with open(filepath, "wb") as f:
            f.write(nonce)           # Write nonce at the beginning (12 bytes)
            f.write(tag)             # Write tag next (16 bytes)
            f.write(ciphertext)      # Then write ciphertext
        return (filepath, True, "")  # Return status tuple
    except Exception as e:
        return (filepath, False, str(e))  # Capture and return any exception

def decrypt_file(filepath, key):
    try:
        with open(filepath, "rb") as f:
            nonce = f.read(12)       # Read nonce (12 bytes)
            tag = f.read(16)         # Read tag (16 bytes)
            ciphertext = f.read()    # Read the rest as ciphertext
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and authenticate
        with open(filepath, "wb") as f:
            f.write(plaintext)       # Write decrypted plaintext back
        return (filepath, True, "")
    except Exception as e:
        return (filepath, False, str(e))  # Return failure and error message

def list_all_files(folder):
    # Recursively collect all file paths (not directories) in the given folder
    files = []
    for root, dirs, filenamelist in os.walk(folder):
        for name in filenamelist:
            files.append(os.path.join(root, name))
    return files

def batch_process_multithreaded(folder, key, encrypt=True, max_workers=None):
    files = list_all_files(folder)  # Get all target files
    total = len(files)
    action = "Encrypting" if encrypt else "Decrypting"
    worker_count = max_workers if max_workers else os.cpu_count() * 2  # Default: 2x logical cores
    print(f"Start {action.lower()} {total} files with max threads: {worker_count}")
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = []
        for filepath in files:
            if encrypt:
                future = executor.submit(encrypt_file, filepath, key)   # Submit encryption task
            else:
                future = executor.submit(decrypt_file, filepath, key)   # Submit decryption task
            futures.append(future)
        finished = 0
        for future in as_completed(futures):  # Iterate completed tasks
            filepath, ok, errmsg = future.result()
            finished += 1
            if ok:
                print(f"[OK] {action}: {filepath}")
            else:
                print(f"[FAIL] {action}: {filepath} Error: {errmsg}")
    print(f"All {action.lower()} tasks finished. (Total {total})")
if __name__ == "__main__":
    option = input("Enter 'e' to encrypt, 'd' to decrypt: ").strip().lower()  # Select operation
    folder = input("Enter the target folder path: ").strip()                  # Input folder
    password = input("Enter your password: ").strip()                         # Input password
    key = derive_key_from_password(password)                                  # Derive key
    if option == "e":
        batch_process_multithreaded(folder, key, encrypt=True)                # Start encryption
    elif option == "d":
        batch_process_multithreaded(folder, key, encrypt=False)               # Start decryption
    else:
        print("Invalid option.")                                              # Invalid input
