# qBTC: A Post-Quantum Bitcoin Protocol

**Version 0.2.0-hardened | April 2025**

---

## Abstract

qBTC is a complete reimplementation of the Bitcoin protocol engineered for the post-quantum era. It replaces all Shor-vulnerable cryptographic primitives (ECDSA/secp256k1) with NIST-standardized post-quantum algorithms — ML-DSA-65 (FIPS 204) for digital signatures, SLH-DSA-SHA2-256f (FIPS 205) as a hash-based fallback, and ML-KEM-1024 (FIPS 203) for key encapsulation — while replacing SHA-256 with SHA3-256 for Grover-resistant hashing. The protocol introduces a three-phase hybrid consensus mechanism transitioning from Quantum Proof-of-Work (QPoW) to hybrid QPoW+PoS to pure Proof-of-Stake, with a 64-bit mining nonce that neutralizes Grover's quadratic speedup. Bitcoin's monetary policy (21M supply cap, halving schedule, UTXO model) is preserved exactly.

---

## 1. Introduction

Bitcoin's cryptographic foundations — ECDSA signatures on secp256k1 and SHA-256 hashing — face existential threats from quantum computing. Shor's algorithm (1994) can factor integers and compute discrete logarithms in polynomial time, breaking ECDSA entirely. Grover's algorithm (1996) provides a quadratic speedup for brute-force search, halving the effective security of hash functions and mining nonce search.

qBTC addresses both threats:
- **Shor resistance**: All public-key operations use lattice-based (ML-DSA, ML-KEM) or hash-based (SLH-DSA) algorithms standardized by NIST in August 2024.
- **Grover resistance**: SHA3-256 (Keccak sponge) provides 128-bit post-quantum preimage security. The 64-bit mining nonce ensures Grover's algorithm requires 2^32 operations — matching Bitcoin's classical security.

---

## 2. Cryptographic Primitives

### 2.1 Digital Signatures — ML-DSA-65 (FIPS 204)

The primary signature scheme is ML-DSA-65 (formerly CRYSTALS-Dilithium), a module-lattice-based digital signature algorithm at NIST Security Level 3.

| Parameter | Value |
|-----------|-------|
| Public key | 1,952 bytes |
| Secret key | 4,032 bytes |
| Signature | 3,309 bytes |
| Security level | NIST Level 3 (comparable to AES-192) |
| Hardness assumption | Module-LWE + Module-SIS |
| Security model | SUF-CMA |

### 2.2 Fallback Signatures — SLH-DSA-SHA2-256f (FIPS 205)

If lattice assumptions are ever broken, qBTC provides SLH-DSA as a fallback. SLH-DSA relies solely on hash function security — no algebraic structure to attack.

| Parameter | Value |
|-----------|-------|
| Public key | 64 bytes |
| Secret key | 128 bytes |
| Signature | 49,856 bytes |
| Security level | NIST Level 5 (comparable to AES-256) |
| Hardness assumption | Hash preimage resistance only |
| Security model | EUF-CMA |

### 2.3 Key Encapsulation — ML-KEM-1024 (FIPS 203)

P2P channel encryption uses ML-KEM-1024 to establish shared secrets.

| Parameter | Value |
|-----------|-------|
| Encapsulation key | 1,568 bytes |
| Decapsulation key | 3,168 bytes |
| Ciphertext | 1,568 bytes |
| Shared secret | 32 bytes |
| Security level | NIST Level 5 |

### 2.4 Hash Functions — SHA3-256

All consensus-critical hashing uses SHA3-256 (Keccak sponge construction).

- **SHA3-256d(x)** = SHA3-256(SHA3-256(x)) for block hashing and transaction IDs
- **SHAKE-256** for variable-length outputs (address derivation, KDF, entropy mixing)
- Classical preimage: 2^256 operations
- Quantum preimage (Grover): 2^128 operations → NIST PQ Level 3
- Length-extension immune (sponge, not Merkle-Damgård)

---

## 3. Block Structure

### 3.1 Block Header (122 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | version | Protocol version |
| 4 | 32 | prev_block_hash | SHA3-256d of previous header |
| 36 | 32 | merkle_root | SHA3-256d Merkle tree root |
| 68 | 4 | timestamp | Unix epoch seconds |
| 72 | 4 | bits | Compact difficulty target (nBits) |
| 76 | 8 | nonce | 64-bit PoW nonce (Grover-resistant) |
| 84 | 4 | height | Explicit height for SPV proofs |
| 88 | 32 | stake_hash | PoS kernel hash (zeros in pure PoW) |
| 120 | 2 | consensus_flags | 0=PoW, 1=hybrid, 2=PoS |

The 64-bit nonce (vs Bitcoin's 32-bit) is the key Grover defense. A quantum miner using Grover's algorithm on a 32-bit nonce needs only sqrt(2^32) = 2^16 ≈ 65,536 operations (trivial). On a 64-bit nonce, Grover requires sqrt(2^64) = 2^32 ≈ 4.3 billion operations — matching Bitcoin's classical security.

### 3.2 Transactions

Each input carries a full ML-DSA-65 public key (1,952 bytes) and signature (3,309 bytes). A 1-input/2-output transaction is approximately 5,374 bytes (vs Bitcoin's ~225 bytes).

A signature weight discount of 0.25x is applied in block weight calculation, analogous to SegWit's witness discount, preventing signature bloat from dominating block capacity.

---

## 4. Consensus Mechanism

### 4.1 Three-Phase Design

**Phase 0 (blocks 0 → 10,000): Pure Quantum Proof-of-Work**
- SHA3-256d(header) ≤ target
- 64-bit nonce search space
- Difficulty retarget every 1,008 blocks (~1.4 days at 120s/block)

**Phase 1 (blocks 10,001 → 1,000,000): Hybrid QPoW + PoS**
- Block requires BOTH valid PoW AND valid stake kernel proof
- Chain score = pow_work × 0.6 + stake_score × 0.4
- 2/3 stake-weighted finality required
- Slashing for equivocation (double-voting)

**Phase 2 (blocks 1,000,001+): Pure PoS (governance-activated)**
- Validators bonded with ML-DSA-65 signed stake proofs
- PoW fallback if PoS stalls (>30 min no block)

### 4.2 Monetary Policy

Identical to Bitcoin:
- Maximum supply: 21,000,000 qBTC
- Initial block reward: 50 qBTC
- Halving interval: 210,000 blocks
- Smallest unit: 1 quantum-satoshi (10^-8 qBTC)

---

## 5. Quantum Decoherence Entropy (QDE) Framework

qBTC introduces the QDE framework for defense-in-depth randomness:

1. **Entropy mixing**: SHAKE-256(os_entropy ‖ qrng_entropy ‖ chain_entropy)
2. **Nonce randomization**: Starting nonce derived from miner key + prev_hash + timestamp, preventing quantum amplitude estimation
3. **Quantum sterilization**: Secret key intermediates zeroized via ctypes.memset after use

---

## 6. Scalability Analysis

ML-DSA-65 signatures at 3,309 bytes create a ~46x bloat factor vs ECDSA's ~72 bytes. Mitigations:

1. **Signature weight discount** (0.25x): Signature bytes count as 0.25 weight units
2. **4 MB max block size** (vs Bitcoin's 1 MB base)
3. **Estimated capacity**: ~750 transactions per block (1-in/2-out)
4. **Future**: Lattice signature aggregation (Chipmunk, ePrint 2023/1820)

---

## 7. Network

- Async TCP P2P with message framing: [4B magic][1B type][4B length][payload][4B SHA3 checksum]
- ML-KEM-1024 encrypted channels (future)
- Bitcoin-compatible INV/GETDATA relay protocol
- Bech32m addresses with HRP "qbtc" (mainnet) / "tqbtc" (testnet)

---

## 8. References

1. NIST FIPS 203 — ML-KEM. DOI: 10.6028/NIST.FIPS.203
2. NIST FIPS 204 — ML-DSA. DOI: 10.6028/NIST.FIPS.204
3. NIST FIPS 205 — SLH-DSA. DOI: 10.6028/NIST.FIPS.205
4. NIST SP 800-227 — KEM Recommendations (Sep 2025)
5. Nakamoto, S. (2008). "Bitcoin: A Peer-to-Peer Electronic Cash System"
6. Grover, L. (1996). "A fast quantum mechanical algorithm for database search"
7. Shor, P. (1994). "Algorithms for quantum computation"
8. El Bansarkhani et al. (2023). "Chipmunk: Better Synchronized Multi-Signatures from Lattices"
9. Bentov et al. (2016). "Snow White: Robustly Reconfigurable Consensus"