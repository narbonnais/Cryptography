"""
This is a simple implementation of the Schnorr signature scheme using the tinyec library.
"""

import tinyec.ec as ec
import tinyec.registry as reg
import random
import hashlib

c = reg.get_curve("secp192r1")

keypair = ec.make_keypair(c)


def enc(s: str) -> bytes:
    return s.encode('utf-8')


def dec(s: bytes) -> str:
    return s.decode('utf-8')


def schnorr_sign(message: str, keypair: ec.Keypair) -> tuple[ec.Point, int]:
    # Convert message to bytes and hash it
    msg_hash = hashlib.sha256(enc(message)).digest()

    # Generate random k (nonce)
    k = random.randrange(1, keypair.curve.field.n)

    # Calculate R = k*G
    R = k * keypair.curve.g

    # Calculate e = H(R || public_key || message)
    e_input = str(R.x) + str(R.y) + str(keypair.pub.x) + \
        str(keypair.pub.y) + message
    e = int.from_bytes(hashlib.sha256(enc(e_input)).digest(), 'big')

    # Calculate s = k + e*private_key (mod n)
    s = (k + e * keypair.priv) % keypair.curve.field.n

    return (R, s)


def schnorr_verify(message: str, signature: tuple[ec.Point, int], keypair: ec.Keypair) -> bool:
    R, s = signature

    # Calculate e = H(R || public_key || message)
    e_input = str(R.x) + str(R.y) + str(keypair.pub.x) + \
        str(keypair.pub.y) + message
    e = int.from_bytes(hashlib.sha256(enc(e_input)).digest(), 'big')

    # Verify: s*G == R + e*public_key
    left_side = s * keypair.curve.g
    right_side = R + e * keypair.pub

    return left_side == right_side


def main():
    message = "Hello, world!"
    keypair = ec.make_keypair(c)
    signature = schnorr_sign(message, keypair)
    print(schnorr_verify(message, signature, keypair))


if __name__ == "__main__":
    main()
