import random
from math import gcd
from typing import List, Tuple

# -------------------------------------------------------------------
# PVSS CODE
# -------------------------------------------------------------------

def modexp(base: int, exp: int, mod: int) -> int:
    """Compute (base^exp) mod 'mod' efficiently."""
    return pow(base, exp, mod)

def inverse(x: int, q: int) -> int:
    """Compute modular inverse of x mod q (q prime)."""
    # For prime q, x^(q-2) mod q is the inverse of x
    return pow(x, q - 2, q)

def generate_random_poly(secret: int, t: int, q: int) -> List[int]:
    """
    Generate a random polynomial f(x) of degree t over Z_q:
        f(x) = a_0 + a_1*x + ... + a_t*x^t  (mod q)
    with a_0 = secret.
    """
    # a_0 = secret
    coeffs = [secret % q]
    # a_1..a_t = random in [0..q-1]
    for _ in range(t):
        coeffs.append(random.randrange(0, q))
    return coeffs

def eval_poly(coeffs: List[int], x: int, q: int) -> int:
    """Evaluate polynomial at x (mod q)."""
    result = 0
    power_of_x = 1
    for a in coeffs:
        result = (result + a * power_of_x) % q
        power_of_x = (power_of_x * x) % q
    return result

def compute_shares(coeffs: List[int], n: int, q: int) -> List[int]:
    """
    Compute shares S_i = f(i) mod q for i = 1..n.
    Returns list of shares [S_1, S_2, ..., S_n].
    """
    shares = []
    for i in range(1, n + 1):
        share_i = eval_poly(coeffs, i, q)
        shares.append(share_i)
    return shares

def commit_coeffs(coeffs: List[int], g: int, p: int, q: int) -> List[int]:
    """
    Compute commitments to each polynomial coefficient a_j:
        C_j = g^(a_j) mod p
    The exponents a_j are in Z_q, g has order q in mod p.
    """
    return [modexp(g, a_j % q, p) for a_j in coeffs]

def verify_share(share_i: int, i: int, commitments: List[int],
                 g: int, p: int, q: int) -> bool:
    """
    Public verification:
      Check if  g^share_i == ∏(commitments[j]^(i^j)) (mod p).
    Because share_i = f(i) = sum(a_j * i^j) in Z_q, and
      g^(sum(a_j * i^j)) == ∏(g^(a_j))^(i^j) == ∏(commitments[j]^(i^j)).
    """
    lhs = modexp(g, share_i, p)  # g^share_i mod p

    # Compute ∏( C_j^(i^j) ) mod p
    rhs = 1
    i_power = 1
    for C_j in commitments:
        # raise the j-th commitment to i^j (mod q) in exponent
        # but i^j in Z_q is just i_power
        rhs = (rhs * modexp(C_j, i_power, p)) % p
        i_power = (i_power * i) % q  # i^j mod q in next iteration

    return (lhs == rhs)

def lagrange_interpolate(points: List[Tuple[int,int]], q: int) -> int:
    """
    Lagrange interpolation over Z_q (q prime).
    points = [(x_i, f(x_i)), ...].
    Returns f(0) in mod q.
    """
    secret = 0
    for i, (x_i, y_i) in enumerate(points):
        # Compute L_i(0)
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(points):
            if j == i:
                continue
            num = (num * (-x_j)) % q
            den = (den * (x_i - x_j)) % q
        # multiply y_i by L_i(0)
        inv_den = inverse(den, q)
        term = (y_i * num * inv_den) % q
        secret = (secret + term) % q

    return secret

# -------------------------------------------------------------------
# DEMO / MAIN
# -------------------------------------------------------------------

def main():
    """
    Demonstration of a small prime-order group approach:
      - We pick q=23 (a small prime).
      - We pick p=47, where there's a subgroup of order q=23.
      - We pick g=25 in mod 47, which has order 23.
      (In real usage, pick large secure parameters!)
    """

    # 1) Group parameters for demonstration:
    q = 23                       # prime for the "exponent field"
    p = 47                       # a modulus where there's a subgroup of size q
    g = 25                       # generator of that subgroup (order = 23)

    print(f"Using prime-order group with q={q}, p={p}, g={g}")
    print("Any exponent is mod q, commitments are mod p.\n")

    # 2) Suppose we want to share a secret in Z_q
    secret = 7  # must be in [0..q-1]
    print(f"Secret to share (in Z_q) = {secret}")

    # 3) We do threshold t=2 out of n=5
    t = 2
    n = 5
    print(f"Number of participants = {n}, threshold = {t}\n")

    # 4) Generate random polynomial f(x) of degree t with f(0)=secret
    coeffs = generate_random_poly(secret, t, q)
    print(f"Random polynomial coefficients (mod q): {coeffs}")

    # 5) Distribute shares S_i = f(i)
    shares = compute_shares(coeffs, n, q)
    for i, s in enumerate(shares, start=1):
        print(f"  Share for participant {i}: {s}")

    # 6) Publish commitments for verification
    commitments = commit_coeffs(coeffs, g, p, q)
    print("\nCommitments (g^(a_j) mod p):")
    print(commitments)

    # 7) Verify each share publicly
    print("\nVerifying each share with commitments:")
    for i, s in enumerate(shares, start=1):
        ok = verify_share(s, i, commitments, g, p, q)
        print(f"  Share {i} is {'VALID' if ok else 'INVALID'}")

    # 8) Reconstruct the secret from any t=2+1=3 shares
    chosen_indices = [1, 3, 5]  # pick participants #1, #3, #5
    chosen_points = [(i, shares[i-1]) for i in chosen_indices]
    rec_secret = lagrange_interpolate(chosen_points, q)

    print(f"\nReconstructing secret from participants {chosen_indices}:")
    print(f"  Reconstructed secret = {rec_secret}")
    print(f"  Matches original? {rec_secret == secret}")

if __name__ == "__main__":
    main()
