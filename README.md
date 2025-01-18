# Cryptography Learning Repository

This repository contains implementations of various cryptographic algorithms and protocols, organized from foundational concepts to advanced applications. The code is meant for learning purposes and should not be used in production environments.

## 🔑 Foundational Cryptography

### RSA (Rivest-Shamir-Adleman)
- Digital signature scheme using public-key cryptography
- Based on the difficulty of factoring large numbers
- Implementation demonstrates key generation, signing, and verification
- [View Implementation](rsa.py)

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- Digital signature scheme using elliptic curve cryptography
- More efficient than RSA with smaller key sizes
- Uses the secp192r1 curve for demonstrations
- [View Implementation](ecdsa.py)

### Schnorr Signatures
- Simple and efficient signature scheme
- Provides native multi-signature support
- Linear signature verification
- [View Implementation](schnorr.py)

## 🚀 Advanced Cryptography

### Paillier Cryptosystem
- Homomorphic encryption scheme
- Allows computation on encrypted data
- Supports addition of encrypted values
- [View Implementation](paillier.py)

### MuSig (Multi-Signature Scheme)
- Advanced multi-signature scheme using Schnorr signatures
- More efficient than individual signatures
- Non-interactive signature aggregation
- [View Implementation](musig.py)

## 💫 Multi-Party Computation (MPC) Applications

### IoT Temperature Averaging
- Privacy-preserving temperature aggregation
- Uses Paillier homomorphic encryption
- Demonstrates practical MPC use case
- [View Implementation](iot_temperature_average_mpc.py)

### Dynamic Consortium Key Management
- Threshold signature scheme for consortiums
- Handles dynamic member joining/leaving
- Maintains shared signing capabilities
- [View Implementation](dynamic_consortium_keys.py)

## 🎯 Learning Objectives

1. Understand basic cryptographic primitives
2. Learn about different signature schemes
3. Explore homomorphic encryption
4. Study multi-party computation protocols
5. Implement practical privacy-preserving applications

## 📚 Key Concepts Covered

- Public-key cryptography
- Digital signatures
- Elliptic curve cryptography
- Homomorphic encryption
- Threshold signatures
- Secret sharing
- Multi-party computation
- Privacy-preserving computation

## ⚠️ Important Note

This code is for educational purposes only. The implementations are simplified and may not include all security measures required for production use. For real-world applications, always use well-audited cryptographic libraries.

## 🔧 Dependencies

- Python 3.8+
- tinyec (for elliptic curve operations)
- hashlib (included in Python standard library)
- random (included in Python standard library)

## 📖 Usage

Each implementation includes a `main()` function with example usage. Run any file directly to see demonstrations:

```
bash
python rsa.py
python ecdsa.py
python schnorr.py
python paillier.py
python musig.py
python iot_temperature_average_mpc.py
python dynamic_consortium_keys.py
```