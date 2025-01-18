"""
This is a simple implementation of the RSA signature scheme.
"""

import random
import hashlib
from math import gcd


def enc(s: str) -> bytes:
    return s.encode('utf-8')


def dec(s: bytes) -> str:
    return s.decode('utf-8')


def is_prime(n: int, k: int = 128) -> bool:
    """Miller-Rabin primality test"""
    if n <= 3:
        return n > 1
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a prime number with specified bit length"""
    while True:
        n = random.getrandbits(bits)
        # Make sure n is odd and has correct bit length
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n


class RSAKey:
    def __init__(self, bits: int = 2048):
        # Generate two prime numbers
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)

        self.n = p * q
        phi = (p - 1) * (q - 1)

        # Choose public exponent e
        self.e = 65537  # Commonly used value

        # Calculate private exponent d
        self.d = pow(self.e, -1, phi)

    @property
    def public_key(self) -> tuple[int, int]:
        return (self.n, self.e)

    @property
    def private_key(self) -> tuple[int, int]:
        return (self.n, self.d)


def rsa_sign(message: str, private_key: tuple[int, int]) -> int:
    """Sign a message using RSA private key"""
    n, d = private_key

    # Hash the message and convert to integer
    msg_hash = int.from_bytes(hashlib.sha256(enc(message)).digest(), 'big')

    # Sign the hash
    signature = pow(msg_hash, d, n)
    return signature


def rsa_verify(message: str, signature: int, public_key: tuple[int, int]) -> bool:
    """Verify an RSA signature using public key"""
    n, e = public_key

    # Hash the original message
    msg_hash = int.from_bytes(hashlib.sha256(enc(message)).digest(), 'big')

    # Verify the signature
    decrypted_hash = pow(signature, e, n)
    return decrypted_hash == msg_hash


def main():
    # Example usage
    message = "Hello, world!"

    # Generate new RSA key pair
    print("Generating RSA keys (this might take a moment)...")
    key = RSAKey(bits=2048)

    # Sign the message
    signature = rsa_sign(message, key.private_key)

    # Verify the signature
    is_valid = rsa_verify(message, signature, key.public_key)
    print(f"Signature valid: {is_valid}")

    # Print signature and key size
    print(f"Signature size: {signature.bit_length() / 8} bytes")  # 256 bytes
    print(f"Key size: {key.n.bit_length() / 8} bytes")  # 256 bytes


if __name__ == "__main__":
    main()
