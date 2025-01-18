"""
This is a simple implementation of the MuSig signature scheme using the tinyec library.
"""

import tinyec.ec as ec
import tinyec.registry as reg
import random
import hashlib
from typing import List, Tuple

# Get a standard curve
curve = reg.get_curve("secp192r1")


def enc(s: str) -> bytes:
    return s.encode('utf-8')


def dec(s: bytes) -> str:
    return s.decode('utf-8')


def compute_L(public_keys: List[ec.Point]) -> bytes:
    """Compute the hash of the lexicographically sorted public keys"""
    sorted_pks = sorted([f"{pk.x},{pk.y}" for pk in public_keys])
    L = hashlib.sha256(enc(",".join(sorted_pks))).digest()
    return L


def compute_key_coefficient(L: bytes, public_key: ec.Point) -> int:
    """Compute the key coefficient (a_i) for a public key"""
    input_bytes = L + enc(f"{public_key.x},{public_key.y}")
    return int.from_bytes(hashlib.sha256(input_bytes).digest(), 'big')


def aggregate_public_keys(public_keys: List[ec.Point]) -> ec.Point:
    """Compute the aggregate public key"""
    L = compute_L(public_keys)

    # Compute the sum of a_i * P_i
    result = None
    for pk in public_keys:
        a_i = compute_key_coefficient(L, pk)
        term = a_i * pk
        if result is None:
            result = term
        else:
            result = result + term

    return result


def generate_nonce(keypair: ec.Keypair) -> Tuple[int, ec.Point]:
    """Generate random nonce and return (r_i, R_i)"""
    r = random.randrange(1, keypair.curve.field.n)
    R = r * keypair.curve.g
    return r, R


def compute_signature_share(message: str, keypair: ec.Keypair, r: int,
                            all_public_keys: List[ec.Point],
                            all_R_points: List[ec.Point]) -> int:
    """Compute signer's share of the signature"""
    # Compute L and key coefficients
    L = compute_L(all_public_keys)
    a_i = compute_key_coefficient(L, keypair.pub)

    # Compute aggregate public key
    agg_pubkey = aggregate_public_keys(all_public_keys)

    # Compute aggregate R
    R_agg = all_R_points[0]
    for R in all_R_points[1:]:
        R_agg = R_agg + R

    # Compute challenge e
    e_input = str(R_agg.x) + str(R_agg.y) + str(agg_pubkey.x) + \
        str(agg_pubkey.y) + message
    e = int.from_bytes(hashlib.sha256(enc(e_input)).digest(), 'big')

    # Compute signer's share of s
    s_i = (r + e * a_i * keypair.priv) % keypair.curve.field.n

    return s_i


def aggregate_signatures(s_values: List[int]) -> int:
    """Combine signature shares into final signature"""
    return sum(s_values) % curve.field.n


def aggregate_R_points(R_points: List[ec.Point]) -> ec.Point:
    """Combine R points into final R"""
    R_agg = R_points[0]
    for R in R_points[1:]:
        R_agg = R_agg + R
    return R_agg


def musig_verify(message: str, signature: Tuple[ec.Point, int],
                 public_keys: List[ec.Point]) -> bool:
    """Verify the aggregate signature"""
    R_agg, s = signature

    # Compute aggregate public key
    agg_pubkey = aggregate_public_keys(public_keys)

    # Compute challenge e
    e_input = str(R_agg.x) + str(R_agg.y) + str(agg_pubkey.x) + \
        str(agg_pubkey.y) + message
    e = int.from_bytes(hashlib.sha256(enc(e_input)).digest(), 'big')

    # Verify: s*G = R_agg + e*agg_pubkey
    left_side = s * curve.g
    right_side = R_agg + e * agg_pubkey

    return left_side == right_side


def main():
    # Example usage with 3 signers
    message = "Hello, MuSig!"

    # Generate keypairs for each signer
    keypairs = [ec.make_keypair(curve) for _ in range(3)]
    public_keys = [kp.pub for kp in keypairs]

    # Round 1: Each signer generates their nonce
    nonces = [generate_nonce(kp) for kp in keypairs]
    r_values = [r for r, _ in nonces]
    R_points = [R for _, R in nonces]

    # Round 2: Each signer computes their signature share
    s_values = [
        compute_signature_share(message, kp, r, public_keys, R_points)
        for kp, r in zip(keypairs, r_values)
    ]

    # Aggregate R points and s values
    R_agg = aggregate_R_points(R_points)
    s_agg = aggregate_signatures(s_values)

    # Verify the aggregate signature
    signature = (R_agg, s_agg)
    is_valid = musig_verify(message, signature, public_keys)
    print(f"Aggregate signature valid: {is_valid}")


if __name__ == "__main__":
    main()
