# qBTC Architecture Reference

## System Diagram


┌─────────────────────────────────────────────────────────────────┐ │ qBTC Full Node │ │ │ │ ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌────────────┐ │ │ │ CLI │──▸│ Node │──▸│ JSON-RPC │◂──│ External │ │ │ │ (args) │ │ (orch) │ │ Server │ │ Clients │ │ │ └─────────┘ └────┬─────┘ └───────────┘ └────────────┘ │ │ │ │ │ ┌────────────┼────────────┬──────────────┐ │ │ ▼ ▼ ▼ ▼ │ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │ │Blockchain│ │ Mempool │ │Consensus │ │ P2P │ │ │ │ chain │ │ pool │ │ engine │ │ network │ │ │ │ UTXO │ │ fee-sort │ │ QPoW+PoS │ │ ML-KEM │ │ │ │ index │ │ validate │ │ validate │ │ gossip │ │ │ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │ │ │ │ │ │ │ │ └─────────────┴────────────┴──────────────┘ │ │ │ │ │ ┌──────┴──────┐ │ │ │ Crypto │ │ │ │ ML-DSA-65 │ │ │ │ SLH-DSA │ │ │ │ ML-KEM │ │ │ │ SHA3-256d │ │ │ │ SHAKE-256 │ │ │ └──────┬──────┘ │ │ │ │ │ ┌──────┴──────┐ │ │ │ liboqs │ │ │ │ (C / OQS) │ │ │ └─────────────┘ │ │ │ │ ┌──────────┐ ┌──────────┐ │ │ │ Wallet │ │ Miner │ │ │ │ HD keys │ │ SHA3-256 │ │ │ │ Bech32m │ │ 64b nonce│ │ │ │ sign/txn │ │ template │ │ │ └──────────┘ └──────────┘ │ └─────────────────────────────────────────────────────────────────┘


## Data Flow

### Block Reception (from P2P)
Peer → read_message() → BLOCK payload → Block.deserialize() → ConsensusEngine.validate_pow() → ConsensusEngine.validate_stake() (if hybrid) → Blockchain.add_block() → validate_structure() → _validate_utxos() → _accept_block() → _apply_block_to_utxos() → Mempool.remove_confirmed() → P2PNode.broadcast_block() (relay)


### Transaction Reception (from P2P / RPC)
Source → Transaction.deserialize() → Mempool.add_transaction() → Check not duplicate → Check not coinbase → Check size limits → Verify all inputs exist in UTXO set → Verify PK hashes match UTXOs → Verify output amounts (no dust, no overflow) → Verify fee rate ≥ minimum → Verify all ML-DSA-65 signatures → P2PNode.broadcast_tx() (relay INV)


### Mining Loop
Miner._mining_thread():

_assemble_candidate() → Select mempool TXs (highest fee-rate first) → Create coinbase TX (reward + fees → miner pk_hash) → Compute Merkle root → Set header fields (prev_hash, bits, timestamp, height)
QDE nonce randomization → start_nonce = SHAKE-256(miner_key ‖ prev_hash ‖ timestamp)
Mine → For nonce = start → 2^64 (wrapping): hash = SHA3-256d(header_bytes) If hash ≤ target → BLOCK FOUND! Every 100K hashes: log hashrate, check for new tip
On success: → Blockchain.add_block() → Mempool.remove_confirmed() → P2PNode.broadcast_block()

## File Map

| File | Domain | Description |
|------|--------|-------------|
| `crypto/hashing.py` | Crypto | SHA3-256d, SHAKE-256, Merkle trees, target encoding, QDE entropy mixing, sterilization |
| `crypto/keys.py` | Crypto | ML-DSA-65, SLH-DSA, ML-KEM-1024, deterministic keygen, key serialization |
| `core/constants.py` | Config | All protocol constants, NIST params, QDE framework, consensus phases, scalability analysis |
| `core/transaction.py` | Core | TX model, inputs/outputs, varint, signing digest, signature verification |
| `core/block.py` | Core | 122-byte header, Merkle root, PoW validation, genesis block, reward schedule |
| `core/chain.py` | Core | Blockchain state, UTXO set, difficulty retarget, median time past, orphan processing |
| `core/mempool.py` | Core | Fee-prioritized TX pool, RBF, eviction, ancestor limits, block assembly |
| `core/node.py` | Orchestrator | Full node: wires all subsystems, JSON-RPC 2.0, event handling |
| `core/cli.py` | CLI | Argparse, signal handling, ASCII banner, version info |
| `consensus/consensus.py` | Consensus | Three-phase hybrid engine, staking, voting, slashing, chain scoring |
| `consensus/miner.py` | Consensus | SHA3-256d mining, QDE nonce randomization, multi-thread, stats |
| `network/p2p_protocol.py` | Network | Wire format, message types, Peer model, version handshake |
| `network/p2p_node.py` | Network | Async TCP server/client, message dispatch, relay, maintenance |
| `wallet/wallet.py` | Wallet | HD key derivation, Bech32m addresses, coin selection, TX building, persistence |
| `test_qbtc.py` | Testing | 40+ unit tests with inline stubs (no liboqs required) |
| `Dockerfile` | DevOps | Multi-stage build: liboqs → Python → minimal runtime |

## Quick Start

```bash
# Install
pip install -e .

# Run tests (no liboqs needed)
pip install pytest
pytest test_qbtc.py -v

# Run a mining node
qbtc-node --mine --port 19333

# Run with peers
qbtc-node --seed-peer 10.0.0.1:19333 --mine

# Docker
docker build -t qbtc-node .
docker run -p 19333:19333 -p 19332:19332 qbtc-node --mine

# RPC queries
echo '{"jsonrpc":"2.0","method":"getblockchaininfo","id":1}' | nc localhost 19332
echo '{"jsonrpc":"2.0","method":"getmempoolinfo","id":1}' | nc localhost 19332
echo '{"jsonrpc":"2.0","method":"getnewaddress","params":{"label":"test"},"id":1}' | nc localhost 19332

---


