# ⚛️ qBTC — Quantum Bitcoin Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

**A complete reimplementation of Bitcoin for the post-quantum era.**

qBTC replaces every Shor-vulnerable primitive with NIST-standardized post-quantum algorithms and every Grover-vulnerable hash with SHA3-256, while preserving Bitcoin's 21M supply cap, halving schedule, and UTXO model.

---

## 🔐 Post-Quantum Cryptography Stack

| Layer | Bitcoin (Vulnerable) | qBTC (Quantum-Resistant) | NIST Standard |
|-------|---------------------|-------------------------|---------------|
| **Signatures** | ECDSA / secp256k1 | ML-DSA-65 (Dilithium) | FIPS 204 |
| **Fallback Sigs** | — | SLH-DSA (SPHINCS+) | FIPS 205 |
| **Key Exchange** | ECDH | ML-KEM-1024 (Kyber) | FIPS 203 |
| **Block Hashing** | SHA-256d | SHA3-256d | — |
| **Nonce Space** | 32-bit | 64-bit | — |
| **Addresses** | Base58/Bech32 | Bech32m + SHAKE-256 | — |

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/qbtc-protocol/qbtc
cd qbtc

# Install (basic — no liboqs, uses fallback crypto)
pip install -e .

# Install (full — with post-quantum crypto)
pip install -e ".[full]"

# Run tests
pip install -e ".[dev]"
pytest test_qbtc.py -v

# Run a mining node
qbtc-node --mine --port 19333 --rpc-port 19332

# Docker
docker build -t qbtc-node .
docker run -p 19333:19333 -p 19332:19332 qbtc-node --mine