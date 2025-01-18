"""
This is a simple implementation of the Paillier cryptosystem.
"""

import random
from math import gcd
from typing import Tuple

def is_prime(n: int, k: int = 5) -> bool:
    """Simple Miller-Rabin primality test"""
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

def generate_prime(bits: int = 8) -> int:
    """Generate a prime number with specified bit length"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Make odd and ensure bit length
        if is_prime(n):
            return n

def lcm(a: int, b: int) -> int:
    """Compute least common multiple"""
    return abs(a * b) // gcd(a, b)

def generate_keypair(key_bits: int = 8) -> Tuple[Tuple[int, int], Tuple[int, int, int]]:
    """Generate public and private keypair
    Returns ((n, g), (lambda_n, mu, n))"""
    # Generate two distinct primes
    p = generate_prime(key_bits)
    while True:
        q = generate_prime(key_bits)
        if q != p:
            break
    
    # Compute n = pq and λ(n)
    n = p * q
    n_squared = n * n
    lambda_n = lcm(p - 1, q - 1)
    
    # Generate generator g (using n + 1 as a simple valid choice)
    g = n + 1
    
    # Compute modular multiplicative inverse of L(g^λ mod n^2) mod n
    # where L(x) = (x-1)/n
    x = pow(g, lambda_n, n_squared)
    L = (x - 1) // n
    mu = pow(L, -1, n)
    
    public_key = (n, g)
    private_key = (lambda_n, mu, n)
    
    return public_key, private_key

def encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """Encrypt a message using Paillier cryptosystem"""
    n, g = public_key
    n_squared = n * n
    
    # Generate random r coprime to n
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            break
    
    # Compute ciphertext: c = g^m * r^n mod n^2
    c = (pow(g, message, n_squared) * pow(r, n, n_squared)) % n_squared
    return c

def decrypt(ciphertext: int, private_key: Tuple[int, int, int]) -> int:
    """Decrypt a ciphertext using Paillier cryptosystem"""
    lambda_n, mu, n = private_key
    n_squared = n * n
    
    # Compute plaintext: m = L(c^λ mod n^2) * μ mod n
    x = pow(ciphertext, lambda_n, n_squared)
    L = (x - 1) // n
    plaintext = (L * mu) % n
    return plaintext

def homomorphic_add(c1: int, c2: int, public_key: Tuple[int, int]) -> int:
    """Add two encrypted values homomorphically"""
    n, _ = public_key
    n_squared = n * n
    return (c1 * c2) % n_squared

def homomorphic_add_constant(ciphertext: int, constant: int, public_key: Tuple[int, int]) -> int:
    """Add a plaintext constant to an encrypted value"""
    n, g = public_key
    n_squared = n * n
    return (ciphertext * pow(g, constant, n_squared)) % n_squared

def homomorphic_multiply_constant(ciphertext: int, constant: int, public_key: Tuple[int, int]) -> int:
    """Multiply an encrypted value by a plaintext constant"""
    n, _ = public_key
    n_squared = n * n
    return pow(ciphertext, constant, n_squared)

def main():
    # Generate keypair (using small keys for demonstration)
    print("Generating keypair...")
    public_key, private_key = generate_keypair(key_bits=8)
    
    # Example messages
    m1 = 15
    m2 = 20
    print(f"\nOriginal messages: {m1} and {m2}")
    
    # Encrypt messages
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"Encrypted values:\nc1 = {c1}\nc2 = {c2}")
    
    # Demonstrate homomorphic addition
    c_sum = homomorphic_add(c1, c2, public_key)
    decrypted_sum = decrypt(c_sum, private_key)
    print(f"\nDecrypted sum: {decrypted_sum}")
    print(f"Actual sum: {m1 + m2}")
    print(f"Homomorphic addition worked: {decrypted_sum == m1 + m2}")
    
    # Demonstrate addition with constant
    constant = 5
    c_add_const = homomorphic_add_constant(c1, constant, public_key)
    decrypted_add_const = decrypt(c_add_const, private_key)
    print(f"\nAdding constant {constant} to {m1}: {decrypted_add_const}")
    print(f"Constant addition worked: {decrypted_add_const == m1 + constant}")
    
    # Demonstrate multiplication by constant
    c_mul_const = homomorphic_multiply_constant(c1, constant, public_key)
    decrypted_mul_const = decrypt(c_mul_const, private_key)
    print(f"\nMultiplying {m1} by {constant}: {decrypted_mul_const}")
    print(f"Constant multiplication worked: {decrypted_mul_const == m1 * constant}")

if __name__ == "__main__":
    main() 