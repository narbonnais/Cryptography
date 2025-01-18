"""
Dynamic key management system for consortium blockchain using threshold signatures.
Handles member joining/leaving while maintaining a shared signing key.
"""

import random
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from functools import reduce
from typing import List, Tuple


class Polynomial:
    def __init__(self, coefficients: List[int], prime: int):
        self.coefficients = coefficients
        self.prime = prime

    def evaluate(self, x: int) -> int:
        """Evaluate polynomial at point x"""
        result = 0
        power = 1

        for coeff in self.coefficients:
            result = (result + coeff * power) % self.prime
            power = (power * x) % self.prime

        return result

    @staticmethod
    def interpolate(points: List[Tuple[int, int]], prime: int) -> 'Polynomial':
        """Lagrange interpolation to reconstruct polynomial"""
        result = [0]  # Start with constant term

        for i, (x_i, y_i) in enumerate(points):
            numerator = [1]
            denominator = 1

            for j, (x_j, _) in enumerate(points):
                if i == j:
                    continue

                numerator = Polynomial.multiply_terms(
                    numerator, [-x_j, 1], prime)
                denominator = (denominator * (x_i - x_j)) % prime

            inv_denominator = pow(denominator, -1, prime)
            scaled_numerator = Polynomial.scalar_multiply(
                numerator, (y_i * inv_denominator) % prime, prime)
            result = Polynomial.add_polynomials(
                result, scaled_numerator, prime)

        return Polynomial(result, prime)

    @staticmethod
    def multiply_terms(p1: List[int], p2: List[int], prime: int) -> List[int]:
        """Multiply two polynomials"""
        result = [0] * (len(p1) + len(p2) - 1)

        for i, a in enumerate(p1):
            for j, b in enumerate(p2):
                result[i + j] = (result[i + j] + a * b) % prime

        return result

    @staticmethod
    def scalar_multiply(poly: List[int], scalar: int, prime: int) -> List[int]:
        """Multiply polynomial by scalar"""
        return [(coeff * scalar) % prime for coeff in poly]

    @staticmethod
    def add_polynomials(p1: List[int], p2: List[int], prime: int) -> List[int]:
        """Add two polynomials"""
        max_len = max(len(p1), len(p2))
        result = []

        for i in range(max_len):
            a = p1[i] if i < len(p1) else 0
            b = p2[i] if i < len(p2) else 0
            result.append((a + b) % prime)

        return result


@dataclass
class Member:
    id: int
    share: int
    public_key: int
    is_active: bool = True


class ConsortiumKeyManager:
    def __init__(self, threshold: int, initial_members: int):
        """
        Initialize consortium with threshold t and n initial members
        threshold: minimum signatures needed (t)
        initial_members: total initial members (n)
        """
        if threshold > initial_members:
            raise ValueError(
                "Threshold must be less than or equal to initial members")

        self.threshold = threshold
        # Large prime for field arithmetic
        self.prime = generate_safe_prime(256)
        self.members: Dict[int, Member] = {}
        self.active_member_count = 0

        # Generate initial shared secret and distribute shares
        self.setup_initial_shares(initial_members)

    def setup_initial_shares(self, n: int):
        """Initialize the sharing scheme with n members"""
        # Generate random secret key
        self.master_secret = random.randrange(2, self.prime)

        # Create polynomial for secret sharing
        coefficients = [self.master_secret]
        coefficients.extend(
            random.randrange(2, self.prime) for _ in range(self.threshold - 1)
        )
        poly = Polynomial(coefficients, self.prime)

        # Generate shares for initial members
        for i in range(1, n + 1):
            share = poly.evaluate(i)
            # Simple public key derivation
            public_key = pow(share, 2, self.prime)
            self.members[i] = Member(i, share, public_key)
            self.active_member_count += 1

    def add_member(self, new_member_id: int) -> Optional[Member]:
        """Add a new member to the consortium"""
        if new_member_id in self.members:
            return None

        # Collect enough shares to reconstruct secret
        shares = self.collect_threshold_shares()
        if not shares:
            return None

        # Reconstruct polynomial
        poly = Polynomial.interpolate(shares, self.prime)

        # Generate new share for new member
        share = poly.evaluate(new_member_id)
        public_key = pow(share, 2, self.prime)

        # Add new member
        member = Member(new_member_id, share, public_key)
        self.members[new_member_id] = member
        self.active_member_count += 1

        return member

    def remove_member(self, member_id: int) -> bool:
        """Remove a member and redistribute shares"""
        if member_id not in self.members or not self.members[member_id].is_active:
            return False

        # Collect threshold shares excluding leaving member
        shares = self.collect_threshold_shares(exclude={member_id})
        if not shares:
            return False

        # Generate new polynomial with same secret
        poly = Polynomial.interpolate(shares, self.prime)
        new_coefficients = [poly.coefficients[0]]  # Keep same secret
        new_coefficients.extend(
            random.randrange(2, self.prime) for _ in range(self.threshold - 1)
        )
        new_poly = Polynomial(new_coefficients, self.prime)

        # Redistribute new shares to remaining active members
        for member in self.members.values():
            if member.id != member_id and member.is_active:
                member.share = new_poly.evaluate(member.id)
                member.public_key = pow(member.share, 2, self.prime)

        # Deactivate leaving member
        self.members[member_id].is_active = False
        self.active_member_count -= 1

        return True

    def collect_threshold_shares(self, exclude: Set[int] = None) -> Optional[List[Tuple[int, int]]]:
        """Collect threshold number of shares from active members"""
        if exclude is None:
            exclude = set()

        shares = []
        for member in self.members.values():
            if member.is_active and member.id not in exclude:
                shares.append((member.id, member.share))
                if len(shares) >= self.threshold:
                    break

        return shares if len(shares) >= self.threshold else None

    def sign_message(self, message: str, signers: List[int]) -> Optional[int]:
        """Create threshold signature with t signers"""
        if len(signers) < self.threshold:
            return None

        # Hash message
        msg_hash = int.from_bytes(hashlib.sha256(
            message.encode()).digest(), 'big')

        # Collect shares from signers
        shares = []
        for signer_id in signers[:self.threshold]:
            if signer_id in self.members and self.members[signer_id].is_active:
                shares.append((signer_id, self.members[signer_id].share))

        if len(shares) < self.threshold:
            return None

        # Reconstruct secret and sign
        poly = Polynomial.interpolate(shares, self.prime)
        secret = poly.coefficients[0]
        signature = pow(msg_hash, secret, self.prime)

        return signature

    def verify_signature(self, message: str, signature: int) -> bool:
        """Verify a threshold signature"""
        msg_hash = int.from_bytes(hashlib.sha256(
            message.encode()).digest(), 'big')

        # Verify using public information
        expected = pow(msg_hash, self.master_secret, self.prime)
        return signature == expected


def generate_safe_prime(bits: int) -> int:
    """Generate a safe prime (p where (p-1)/2 is also prime)"""
    while True:
        p = random.getrandbits(bits) | 1
        if is_prime(p) and is_prime((p - 1) // 2):
            return p


def is_prime(n: int, k: int = 5) -> bool:
    """Miller-Rabin primality test"""
    if n <= 3:
        return n > 1
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def main():
    # Example usage
    print("Initializing consortium with 5 members and threshold 3...")
    manager = ConsortiumKeyManager(threshold=3, initial_members=5)

    # Sign a message with initial setup
    message = "Block #1000 checkpoint"
    signers = [1, 2, 3]  # First three members sign
    signature = manager.sign_message(message, signers)
    print(f"Initial signature valid: {
          manager.verify_signature(message, signature)}")

    # Add a new member
    print("\nAdding new member (ID: 6)...")
    new_member = manager.add_member(6)
    print(f"New member added: {new_member is not None}")

    # Sign with new member
    signers = [1, 2, 3, 4]  # Including new member
    signature = manager.sign_message(message, signers)
    print(f"Signature with new member valid: {
          manager.verify_signature(message, signature)}")

    # Remove a member
    print("\nRemoving member (ID: 1)...")
    success = manager.remove_member(1)
    print(f"Member removed: {success}")

    # Try to sign with removed member
    signers = [1, 2, 3]  # Including removed member
    signature = manager.sign_message(message, signers)
    print(f"Signature with removed member: {
          'Valid' if signature else 'Failed'}")

    # Sign with remaining active members
    signers = [2, 3, 4]  # Active members only
    signature = manager.sign_message(message, signers)
    print(f"Signature with remaining members valid: {
          manager.verify_signature(message, signature)}")


if __name__ == "__main__":
    main()
