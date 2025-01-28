"""
Demonstration of a threshold scheme built atop the Pedersen Commitment Scheme.
===========================================================================================

DISCLAIMER:
-----------
This code is for educational purposes only. DO NOT USE these small parameters in
any production environment. Real implementations must use much larger (secure)
prime parameters and robust random number generation.

Overview of This Scheme (Section 4.2 Recap):
--------------------------------------------
1) We have a Pedersen Commitment scheme setup with public parameters:
   - p: A large prime
   - q: A prime divisor of (p-1)
   - g: A generator of a subgroup G_q of Z_p* (order q)
   - h: Another generator s.t. log_g(h) is unknown.

2) A Dealer (D) wants to share a secret s in Z_q among n participants, such
   that any subset of size k can reconstruct the secret, but fewer than k
   learn nothing (in an information-theoretic sense).

3) The Dealer:
   (a) Commits to s by choosing random t in Z_q:
         E0 = g^s * h^t mod p
   (b) Chooses two polynomials F(x), G(x) of degree at most k-1 with:
         F(0) = s, G(0) = t
       The other coefficients are picked randomly in Z_q.
   (c) For i=1..k-1, the Dealer commits to each coefficient (F_i, G_i) by publishing:
         E_i = g^{F_i} * h^{G_i} (mod p)
   (d) For each participant P_i (i=1..n), the Dealer privately sends:
         s_i = F(i), t_i = G(i)
       so P_i holds share (s_i, t_i).

4) Verification:
   - Each P_i can (in principle) verify that the Dealer's polynomials are
     consistent with the published commitments E_i.
   - If k participants combine their shares (s_i, t_i), they can reconstruct
     polynomials F'(x), G'(x), and thus recover (s, t) = (F'(0), G'(0)).

5) Security:
   - Hiding: fewer than k participants learn no information about s.
   - Binding: if the Dealer tries to cheat by distributing inconsistent shares,
     the protocol can detect it, or else the Dealer must solve log_g(h),
     which is assumed intractable.

Code Contents:
--------------
 - Context, Commitment, and simple Pedersen functions (commit, verify)
 - Polynomial creation and commitment to coefficients
 - Distribution of shares
 - Example usage demonstrating secret reconstruction

Script Output:
--------------
=== Dealer Distributes the Secret ===
Coefficient commit for i=1: E(F_1, G_1) = 6
Coefficient commit for i=2: E(F_2, G_2) = 18

Dealer published E0 = 2 as commitment to s=5.

Shares distributed to each participant P_i:
  P_1 got (s_1, t_1) = (3, 1)
  P_2 got (s_2, t_2) = (4, 3)
  P_3 got (s_3, t_3) = (8, 4)
  P_4 got (s_4, t_4) = (4, 4)
  P_5 got (s_5, t_5) = (3, 3)

=== Reconstruction by 3 Participants ===
Subset [1, 3, 5] reconstructed s'=5, t'=9 (mod q).
Reconstructed commitment => 2, original => 2
Success! The reconstructed secret opens the same commitment E0.
"""

import random
import dataclasses
from typing import List, Tuple

#
# 1. Basic Pedersen Commitment Data Structures
#
@dataclasses.dataclass
class Context:
    """
    Public parameters for Pedersen commitments:
    - p, q: primes with q | (p-1)
    - g, h: generators in a subgroup of order q in Z_p*
    """
    p: int
    q: int
    g: int
    h: int


@dataclasses.dataclass
class Commitment:
    """
    A Pedersen commitment c = g^s * h^t (mod p).
    """
    c: int


@dataclasses.dataclass
class Proof:
    """
    A simple 'proof' revealing the secret s and randomness t:
    if c = g^s * h^t (mod p).
    """
    s: int
    t: int


#
# 2. Pedersen Commitment Scheme Functions
#
def pedersen_commit(context: Context, s: int, t: int) -> Commitment:
    """
    Compute a Pedersen commitment:
        c = g^s * h^t mod p
    """
    gs = pow(context.g, s, context.p)
    ht = pow(context.h, t, context.p)
    c_val = (gs * ht) % context.p
    return Commitment(c=c_val)


def pedersen_verify(context: Context, commitment: Commitment, proof: Proof) -> bool:
    """
    Verify a Pedersen commitment by checking if:
        commitment.c == g^s * h^t (mod p)
    """
    left = commitment.c
    right = (pow(context.g, proof.s, context.p) *
             pow(context.h, proof.t, context.p)) % context.p
    return left == right


#
# 3. Polynomial Construction for Secret Sharing
#
def make_random_polynomial(degree: int, constant_term: int, q: int) -> List[int]:
    """
    Create a polynomial F(x) of 'degree' with coefficients in Z_q, ensuring
    the constant_term is the specified value (F(0) = constant_term).
    Returns a list of coefficients [F_0, F_1, ..., F_degree].
    """
    # F(0) = constant_term
    poly = [constant_term]
    # For the remaining coefficients, pick random values in Z_q
    for _ in range(degree):
        poly.append(random.randint(0, q - 1))
    return poly


def eval_polynomial(poly: List[int], x: int, q: int) -> int:
    """
    Evaluate the polynomial poly at x (mod q).
    poly = [F_0, F_1, ..., F_d]
    """
    result = 0
    power_of_x = 1
    for coeff in poly:
        term = (coeff * power_of_x) % q
        result = (result + term) % q
        power_of_x = (power_of_x * x) % q
    return result


#
# 4. Dealer: Distribute Shares
#
@dataclasses.dataclass
class Dealer:
    """
    The Dealer who holds the global context and wants to share a secret s
    among n participants with threshold k.
    """
    context: Context
    n: int  # number of participants
    k: int  # threshold

    def distribute(self, s: int) -> Tuple[Commitment, List[int], List[int], List[int], List[int]]:
        """
        1) Pick random t in Z_q
        2) Commit to s: E0 = g^s * h^t (mod p)
        3) Construct polynomials F, G of degree (k-1):
           - F(0) = s, G(0) = t
        4) Commit to polynomial coefficients (F_i, G_i) for i=1..k-1
        5) Return:
           (E0, F_coeffs, G_coeffs, all_shares_s, all_shares_t)
        """
        q = self.context.q
        p = self.context.p

        # 1) Pick random t
        t = random.randint(0, q - 1)

        # 2) Commit to s
        E0 = pedersen_commit(self.context, s, t)

        # 3) Construct polynomials F, G of degree (k-1)
        F_poly = make_random_polynomial(self.k - 1, s, q)  # F(0) = s
        G_poly = make_random_polynomial(self.k - 1, t, q)  # G(0) = t

        # 4) Create commitments to each polynomial coefficient (except F_0, G_0 which are known by def.)
        #    If k=1, no additional coefficients are needed, so handle that gracefully.
        for i in range(1, self.k):
            F_i = F_poly[i]
            G_i = G_poly[i]
            # Create a Pedersen commitment to (F_i, G_i)
            # In a real protocol, we'd broadcast E_i = g^F_i * h^G_i
            Ei = pedersen_commit(self.context, F_i, G_i)
            print(f"Coefficient commit for i={i}: E(F_{i}, G_{i}) = {Ei.c}")

        # 5) Distribute shares: for i=1..n => (s_i, t_i)
        all_s = []
        all_t = []
        for i in range(1, self.n + 1):
            s_i = eval_polynomial(F_poly, i, q)
            t_i = eval_polynomial(G_poly, i, q)
            all_s.append(s_i)
            all_t.append(t_i)

        return (E0, F_poly, G_poly, all_s, all_t)

#
# 5. Reconstruct the Secret from k Shares
#
def reconstruct_secret(context: Context,
                       indices: List[int],
                       shares_s: List[int],
                       shares_t: List[int]) -> Tuple[int, int]:
    """
    Given k distinct participants' indices and their shares (s_i, t_i),
    reconstruct the polynomials F'(x), G'(x) of degree at most k-1,
    and thereby recover the secret s' = F'(0) and t' = G'(0).

    - indices: the participant indices used, e.g., [1,2,3]
    - shares_s[i], shares_t[i]: the share values for each participant in indices.

    Uses standard polynomial interpolation over Z_q.
    Returns (s_reconstructed, t_reconstructed).
    """
    # Lagrange interpolation in Z_q
    q = context.q
    k = len(indices)

    # Build F'(0) and G'(0) using Lagrange interpolation formula.
    # F'(0) = sum( s_i * lambda_i(0) ) (mod q)
    # G'(0) = sum( t_i * lambda_i(0) ) (mod q)
    #
    # where lambda_i(0) = product( (0 - x_m)/(x_i - x_m) ) for m != i, all mod q.
    # But for 0, that simply becomes product( -x_m / (x_i - x_m ) ) etc.
    #
    # We'll define a helper function for Lagrange basis at x=0.

    def lagrange_basis_x0(i_idx: int, all_indices: List[int], mod_q: int) -> int:
        """
        Compute Lagrange basis polynomial at x=0 for the i-th index.
        The i-th index is x_i, the set of other indices is x_m.
        """
        x_i = all_indices[i_idx]
        num = 1
        den = 1
        for m_idx, x_m in enumerate(all_indices):
            if m_idx == i_idx:
                continue
            # (0 - x_m) = -x_m
            num = (num * (-x_m % mod_q)) % mod_q
            # (x_i - x_m)
            diff = (x_i - x_m) % mod_q
            den = (den * diff) % mod_q

        # Multiply num * den^{-1} mod q
        den_inv = pow(den, -1, mod_q)  # modular inverse
        return (num * den_inv) % mod_q

    s_reconstructed = 0
    t_reconstructed = 0

    for i_idx in range(k):
        # s_i and t_i from the i-th index
        s_i = shares_s[i_idx]
        t_i = shares_t[i_idx]
        # compute Lagrange basis for x=0
        L_i0 = lagrange_basis_x0(i_idx, indices, q)

        s_reconstructed = (s_reconstructed + s_i * L_i0) % q
        t_reconstructed = (t_reconstructed + t_i * L_i0) % q

    return s_reconstructed, t_reconstructed


#
# 6. Demonstration / Main
#
def main():
    # Small example parameters (insecure!)
    context = Context(p=23, q=11, g=2, h=4)

    # Suppose we want to share a secret s=5 among n=5 participants with threshold k=3
    dealer = Dealer(context=context, n=5, k=3)
    secret_s = 5

    print("\n=== Dealer Distributes the Secret ===")
    E0, F_poly, G_poly, all_s, all_t = dealer.distribute(secret_s)
    print(f"\nDealer published E0 = {E0.c} as commitment to s={secret_s}.")

    # Show each participant's share
    print("\nShares distributed to each participant P_i:")
    for i in range(1, dealer.n + 1):
        print(f"  P_{i} got (s_{i}, t_{i}) = ({all_s[i-1]}, {all_t[i-1]})")

    # Let's pick a subset S of k=3 participants, e.g., {1, 3, 5}
    print("\n=== Reconstruction by 3 Participants ===")
    subset_indices = [1, 3, 5]
    # Adjust indexing since all_s, all_t are 0-based
    subset_shares_s = [all_s[i-1] for i in subset_indices]
    subset_shares_t = [all_t[i-1] for i in subset_indices]

    # Reconstruct (s', t') using polynomial interpolation
    s_recon, t_recon = reconstruct_secret(context, subset_indices, subset_shares_s, subset_shares_t)
    print(f"Subset {subset_indices} reconstructed s'={s_recon}, t'={t_recon} (mod q).")

    # Verify that E0 = g^s' * h^t' mod p
    # (If shares are consistent and threshold is met, this should match the original commitment E0.)
    recon_commit = pedersen_commit(context, s_recon, t_recon)
    print(f"Reconstructed commitment => {recon_commit.c}, original => {E0.c}")

    # Check if they match
    if recon_commit.c == E0.c:
        print("Success! The reconstructed secret opens the same commitment E0.")
    else:
        print("Reconstruction mismatch. Possibly inconsistent shares or cheating dealer.")

    # Also demonstrate that any subset of size < k learns nothing about s in an info-theoretic sense.
    # (Not shown explicitly in code—this is a proven property from the polynomial-based secret sharing.)


if __name__ == "__main__":
    main()
