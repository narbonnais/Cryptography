"""
This is a simple implementation of the ECDSA signature scheme using the tinyec library.
"""

import tinyec.ec as ec
import tinyec.registry as reg
import random
import hashlib

# Get a standard curve
curve = reg.get_curve("secp192r1")


def enc(s: str) -> bytes:
    return s.encode('utf-8')


def dec(s: bytes) -> str:
    return s.decode('utf-8')


def ecdsa_sign(message: str, keypair: ec.Keypair) -> tuple[int, int]:
    # Convert message to bytes and hash it
    msg_hash = int.from_bytes(hashlib.sha256(enc(message)).digest(), 'big')

    n = keypair.curve.field.n

    while True:
        # Generate random k (nonce)
        k = random.randrange(1, n)

        # Calculate R = k*G and take x coordinate
        R = k * keypair.curve.g
        r = R.x % n

        # If r is 0, try again with different k
        if r == 0:
            continue

        # Calculate s = k^(-1) * (msg_hash + r * private_key) mod n
        k_inv = pow(k, -1, n)
        s = (k_inv * (msg_hash + r * keypair.priv)) % n

        # If s is 0, try again with different k
        if s == 0:
            continue

        return (r, s)


def ecdsa_verify(message: str, signature: tuple[int, int], public_key: ec.Point) -> bool:
    r, s = signature
    curve = public_key.curve
    n = curve.field.n

    # Check if r and s are in [1, n-1]
    if not (1 <= r < n and 1 <= s < n):
        return False

    # Convert message to bytes and hash it
    msg_hash = int.from_bytes(hashlib.sha256(enc(message)).digest(), 'big')

    # Calculate s^(-1) mod n
    s_inv = pow(s, -1, n)

    # Calculate u1 = msg_hash * s^(-1) mod n
    u1 = (msg_hash * s_inv) % n

    # Calculate u2 = r * s^(-1) mod n
    u2 = (r * s_inv) % n

    # Calculate R' = u1*G + u2*public_key
    R_prime = u1 * curve.g + u2 * public_key

    # Verify that R'.x mod n equals r
    return R_prime.x % n == r


def main():
    # Example usage
    message = "Hello, world!"
    keypair = ec.make_keypair(curve)

    # Sign the message
    signature = ecdsa_sign(message, keypair)

    # Verify the signature
    is_valid = ecdsa_verify(message, signature, keypair.pub)
    print(f"Signature valid: {is_valid}")


if __name__ == "__main__":
    main()
