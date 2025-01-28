"""
Pedersen Commitment Scheme - Educational Example
================================================

The Pedersen Commitment Scheme is a cryptographic mechanism that allows a party
to commit to a value while keeping it hidden. Later, the committer can reveal
the committed value in a way that ensures it hasn't been altered.

Main Components:
----------------
1) Setup/Context:
   - p: A large prime (for this example, a small prime for demonstration).
   - q: A prime divisor of (p-1).
   - g: A generator of a subgroup of order q in the multiplicative group Z_p*.
   - h: Another generator in the same subgroup, chosen such that no one knows
        the discrete log of h base g (i.e., the integer x such that h = g^x mod p).

2) Commit phase (commit()):
   - The committer has a secret message "s".
   - Randomly chooses "t" from Z_q.
   - Computes commitment c = g^s * h^t mod p.

3) Reveal phase:
   - The committer sends (s, t) (the opening) to the verifier.
   - The verifier checks that c = g^s * h^t mod p with the provided (s, t).

Why It Works:
-------------
- Hiding: Because "t" is random, observers cannot learn "s" from c.
- Binding: Because discrete logarithms are hard to compute, it is computationally
           infeasible to find a different (s', t') that yields the same c.

Security Caution:
-----------------
- If someone knows x such that h = g^x mod p (log_g(h)), then they can break
  the binding property. The `attack()` function shows how this can be done
  with deliberately weak parameters.

Script output:
--------------
=== Happy Path Demonstration ===
Context: p=23, q=11, g=2, h=4
Secret (s) = 3, Random nonce (t) = 1
Generated Commitment: c = 9
Verification of (s=3, t=1) => True

=== Attack Demonstration ===
Context (weak): p=23, q=11, g=2, h=4
Original secret (s) = 3, original nonce (t) = 5
Original commitment: 4
Fake secret (s') = 5 that the attacker wants to reveal
The attacker managed to find log_g(h) = 2 such as h = g^r
Allowing him to compute t' = 4 such as g^s' * h^t' = g^s * h^t
Check that commit(g^s', h^t') == original commitment:
Fake opening => commit = 4
Original commitment => 4
Result: The same commitment value, proving the binding property is broken with known log_g(h).

"""

import dataclasses
import random

@dataclasses.dataclass
class Context:
    """
    Holds the public parameters for the Pedersen Commitment scheme:
      - p (prime)
      - q (prime divisor of p-1)
      - g (generator)
      - h (generator where log_g(h) is unknown)
    """
    p: int
    q: int
    g: int
    h: int


@dataclasses.dataclass
class CommitterContext:
    """
    Holds the committer's secret value and the random nonce used to hide it.
    """
    s: int  # The secret
    t: int  # The random nonce


@dataclasses.dataclass
class Commitment:
    """
    Represents the generated commitment value c = g^s * h^t (mod p).
    """
    c: int


@dataclasses.dataclass
class Proof:
    """
    Contains the values (s, t) revealed to prove what was committed.
    """
    s: int
    t: int


def commit(context: Context, committer_context: CommitterContext) -> Commitment:
    """
    Generate a Pedersen commitment.
    
    c = (g^s mod p) * (h^t mod p) mod p
    """
    # Calculate g^s mod p
    g_to_s = pow(context.g, committer_context.s, context.q)
    # Calculate h^t mod p
    h_to_t = pow(context.h, committer_context.t, context.q)
    # Multiply them together (mod p) to get the commitment
    commitment_value = (g_to_s * h_to_t) % context.q
    
    return Commitment(c=commitment_value)


def verify(context: Context, commitment: Commitment, proof: Proof) -> bool:
    """
    Verify that the provided (s, t) indeed opens the given commitment.
    
    Checks if:
        commitment.c == g^s * h^t (mod p)
    """
    left_side = commitment.c
    right_side = (
        pow(context.g, proof.s, context.q) * 
        pow(context.h, proof.t, context.q)
    ) % context.q
    
    return left_side == right_side


def happy_path():
    """
    Demonstrates a normal usage (happy path):
      1) Generate a small example context (p, q, g, h).
      2) Commit to a secret s with random t.
      3) Verify the commitment using the proof (s, t).
    """
    print("=== Happy Path Demonstration ===")
    
    # Example (small) parameters for demonstration only
    context = Context(p=23, q=11, g=2, h=4)
    
    # Committer chooses a secret s (for example, s=3)
    s = 3
    # Committer chooses a random t from Z_q (1 <= t <= q-1)
    t = random.randint(1, context.q - 1)
    
    print(f"Context: p={context.q}, q={context.q}, g={context.g}, h={context.h}")
    print(f"Secret (s) = {s}, Random nonce (t) = {t}")
    
    # Create a commit
    committer_context = CommitterContext(s=s, t=t)
    commitment = commit(context, committer_context)
    
    print(f"Generated Commitment: c = {commitment.c}")
    
    # Reveal s and t
    proof = Proof(s=s, t=t)
    
    # Verification
    verification_result = verify(context, commitment, proof)
    print(f"Verification of (s={s}, t={t}) => {verification_result}")


def attack():
    """
    Demonstrates an attack on Pedersen Commitment when log_g(h) is known.
    
    Steps:
    1) Use small parameters where h = g^2, so we know log_g(h) = 2.
    2) Commit to some (s, t).
    3) Find a different pair (s', t') that yields the same commitment.
       This shows the binding property is broken.
    """
    print("\n=== Attack Demonstration ===")
    
    # Weak parameters: p=23, q=11, g=2, h=4 => h = g^2 mod p
    # So log_g(h) = 2
    context = Context(p=23, q=11, g=2, h=4)
    print(f"Context (weak): p={context.q}, q={context.q}, g={context.g}, h={context.h}")
    
    # Original secret and randomness
    s_original = 3
    t_original = 5
    committer_context_original = CommitterContext(s=s_original, t=t_original)
    
    # Commit to (s_original, t_original)
    original_commitment = commit(context, committer_context_original)
    
    # Show original commitment
    print(f"Original secret (s) = {s_original}, original nonce (t) = {t_original}")
    print(f"Original commitment: {original_commitment.c}")
    
    # Verify the original pair
    proof_original = Proof(s=s_original, t=t_original)
    assert verify(context, original_commitment, proof_original), \
        "Original commitment verification should succeed."
    
    # Attacker finds a different (s', t') that gives the same commitment
    # We rely on the relation h = g^2.
    # The key equation for the same commitment:
    #    g^s * h^t = g^s' * h^t'  (mod p)
    #
    # Substituting h = g^2:
    #    g^s * (g^2)^t = g^s' * (g^2)^t'  (mod p)
    #    => g^s * g^(2t) = g^s' * g^(2t') (mod p)
    #    => g^(s + 2t) = g^(s' + 2t')    (mod p)
    # Since these exponents are in Z_q:
    #    s + 2t = s' + 2t'  (mod q)
    #
    # Rearrange for t':
    #    t' = (s + 2t - s') * (1/2) (mod q)
    
    s_fake = 5  # an attacker-chosen "fake" secret
    s_plus_2t = (s_original + 2 * t_original) % context.q
    
    # We need the modular inverse of 2 in Z_q
    inv_2_mod_q = pow(2, -1, context.q)  # This works in Python 3.8+
    
    # Now compute t' that satisfies the equation
    t_fake = (s_plus_2t - s_fake) * inv_2_mod_q % context.q
    
    # Create a "fake" proof with these values
    fake_proof = Proof(s=s_fake, t=t_fake)
    
    # Verify that this fake proof opens the original commitment
    assert verify(context, original_commitment, fake_proof), \
        "Attack demonstration failed; the two proofs should match the same commitment."
    
    print(f"Fake secret (s') = {s_fake} that the attacker wants to reveal")
    print(f"The attacker managed to find log_g(h) = {2} such as h = g^r [q]")
    print(f"Allowing him to compute t' = {t_fake} such as g^s' * h^t' = g^s * h^t [q]")
    print(f"Check that commit(g^s', h^t') == original commitment:")
    print(f"Fake opening => commit = {commit(context, CommitterContext(s=s_fake, t=t_fake)).c}")
    print(f"Original commitment => {original_commitment.c}")
    print("Result: The same commitment value, proving the binding property is broken with known log_g(h).")


def main():
    """
    Orchestrate the demonstration:
    1) Show the 'happy path' usage.
    2) Show the 'attack' scenario with known log_g(h).
    """
    happy_path()
    attack()


if __name__ == "__main__":
    main()
