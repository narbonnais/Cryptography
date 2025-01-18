"""
Shamir Secret Sharing implementation for private key backup.
Allows splitting a private key into n shares where any t shares can reconstruct it.
"""

import random
import hashlib
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class Share:
    """Represents a single secret share"""
    index: int
    value: int


class ShamirSecretSharing:
    def __init__(self, prime_bits: int = 256):
        """Initialize with a prime field size"""
        self.prime = self._generate_safe_prime(prime_bits)

    def split_secret(self, secret: int, threshold: int, total_shares: int) -> List[Share]:
        """
        Split a secret into n shares where any t shares can reconstruct it

        Args:
            secret: The secret to split (must be less than prime)
            threshold: Number of shares needed to reconstruct (t)
            total_shares: Total number of shares to generate (n)
        """
        if threshold > total_shares:
            raise ValueError("Threshold cannot be greater than total shares")
        if secret >= self.prime:
            raise ValueError("Secret must be less than the prime")

        # Generate random coefficients for polynomial
        coefficients = [secret]  # a0 = secret
        coefficients.extend(
            random.randrange(1, self.prime)
            for _ in range(threshold - 1)
        )

        # Generate shares by evaluating polynomial at different points
        shares = []
        for i in range(1, total_shares + 1):
            value = self._evaluate_polynomial(coefficients, i)
            shares.append(Share(i, value))

        return shares

    def reconstruct_secret(self, shares: List[Share]) -> int:
        """
        Reconstruct the secret from t or more shares using Lagrange interpolation
        """
        if not shares:
            raise ValueError("No shares provided")

        # Convert shares to points for interpolation
        points = [(share.index, share.value) for share in shares]

        # Use Lagrange interpolation to reconstruct the secret (coefficient a0)
        secret = 0
        for i, (x_i, y_i) in enumerate(points):
            numerator = 1
            denominator = 1

            for j, (x_j, _) in enumerate(points):
                if i == j:
                    continue

                numerator = (numerator * (-x_j)) % self.prime
                denominator = (denominator * (x_i - x_j)) % self.prime

            # Calculate contribution of this point
            inv_denominator = pow(denominator, -1, self.prime)
            term = (y_i * numerator * inv_denominator) % self.prime
            secret = (secret + term) % self.prime

        return secret

    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x"""
        result = 0
        power = 1

        for coeff in coefficients:
            result = (result + coeff * power) % self.prime
            power = (power * x) % self.prime

        return result

    def _generate_safe_prime(self, bits: int) -> int:
        """Generate a safe prime (p where (p-1)/2 is also prime)"""
        while True:
            p = random.getrandbits(bits) | 1
            if self._is_prime(p) and self._is_prime((p - 1) // 2):
                return p

    def _is_prime(self, n: int, k: int = 5) -> bool:
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
    print("Shamir Secret Sharing for Private Key Backup")
    print("-" * 50)

    # Create instance with 256-bit prime field
    sss = ShamirSecretSharing(prime_bits=256)

    # Example private key (for demonstration)
    private_key = random.getrandbits(128)
    print(f"Original private key: {private_key}")

    # Split into 5 shares, need 3 to reconstruct
    threshold = 3
    total_shares = 5
    print(f"\nSplitting into {
          total_shares} shares (need {threshold} to reconstruct)")

    shares = sss.split_secret(private_key, threshold, total_shares)
    print("\nGenerated shares:")
    for share in shares:
        print(f"Share {share.index}: {share.value}")

    # Demonstrate reconstruction with different combinations
    print("\nReconstructing with different share combinations:")

    # Try with minimum shares (t=3)
    min_shares = shares[:threshold]
    reconstructed = sss.reconstruct_secret(min_shares)
    print(f"\nUsing shares 1,2,3:")
    print(f"Reconstructed key: {reconstructed}")
    print(f"Success: {reconstructed == private_key}")

    # Try with different combination
    diff_shares = [shares[0], shares[2], shares[4]]
    reconstructed = sss.reconstruct_secret(diff_shares)
    print(f"\nUsing shares 1,3,5:")
    print(f"Reconstructed key: {reconstructed}")
    print(f"Success: {reconstructed == private_key}")

    # Try with all shares
    reconstructed = sss.reconstruct_secret(shares)
    print(f"\nUsing all shares:")
    print(f"Reconstructed key: {reconstructed}")
    print(f"Success: {reconstructed == private_key}")


if __name__ == "__main__":
    main()

"""
Shamir Secret Sharing for Private Key Backup
--------------------------------------------------
Original private key: 330779604684658476061177665885667352193

Splitting into 5 shares (need 3 to reconstruct)

Generated shares:
Share 1: 12652671363180133160925872118327024120233179619759773335156008711483410519782
Share 2: 80253912380992202349572694401447498468129968832841618855174208835142080495910
Share 3: 18177687147043046558170381346242944235889839049320740493181470747516697143763
Share 4: 11050031567725826794489018455831840231644098463806592792112101737952240600155
Share 5: 58870945643040543058528605730214186455392747076299175751966101806448710865086

Reconstructing with different share combinations:

Using shares 1,2,3:
Reconstructed key: 330779604684658476061177665885667352193
Success: True

Using shares 1,3,5:
Reconstructed key: 330779604684658476061177665885667352193
Success: True

Using all shares:
Reconstructed key: 330779604684658476061177665885667352193
Success: True
"""