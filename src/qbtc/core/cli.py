"""
qBTC Command-Line Interface v2 — HARDENED FOR PEER REVIEW
============================================================
Entry point for the qBTC full node.

Usage:
    qbtc-node --port 19333 --mine --rpc-port 19332
    qbtc-node --testnet --seed-peer 192.168.1.10:19444
    qbtc-node --data-dir /var/lib/qbtc --log-level DEBUG
    qbtc-node --version
"""
from __future__ import annotations
import asyncio
import sys
import signal
import argparse
import logging

logger = logging.getLogger("qbtc.cli")


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for qbtc-node."""
    parser = argparse.ArgumentParser(
        prog="qbtc-node",
        description="qBTC Full Node — Post-Quantum Bitcoin Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  Start a mining node:
    qbtc-node --mine --rpc-port 19332

  Connect to seed peers:
    qbtc-node --seed-peer 10.0.0.1:19333 --seed-peer 10.0.0.2:19333

  Testnet mode with verbose logging:
    qbtc-node --testnet --port 19444 --mine --log-level DEBUG

  Version information:
    qbtc-node --version
        """,
    )

    parser.add_argument(
        "--version", action="store_true",
        help="Show version information and exit",
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="P2P listen address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=19333,
        help="P2P listen port (default: 19333)",
    )
    parser.add_argument(
        "--rpc-host", default="127.0.0.1",
        help="RPC bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--rpc-port", type=int, default=19332,
        help="RPC port (default: 19332)",
    )
    parser.add_argument(
        "--data-dir", default="./qbtc_data",
        help="Data directory (default: ./qbtc_data)",
    )
    parser.add_argument(
        "--mine", action="store_true",
        help="Enable SHA3-256d proof-of-work mining",
    )
    parser.add_argument(
        "--stake", action="store_true",
        help="Enable PoS staking (hybrid consensus mode)",
    )
    parser.add_argument(
        "--no-rpc", action="store_true",
        help="Disable the JSON-RPC server",
    )
    parser.add_argument(
        "--testnet", action="store_true",
        help="Use testnet parameters",
    )
    parser.add_argument(
        "--seed-peer", action="append", default=[], dest="seed_peers",
        help="Seed peer address (host:port), can be repeated",
    )
    parser.add_argument(
        "--wallet-file", default="wallet.qbtc",
        help="Wallet filename within data directory (default: wallet.qbtc)",
    )
    parser.add_argument(
        "--wallet-password", default="",
        help="Password for wallet encryption (default: empty)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════════════
# VERSION INFO
# ═══════════════════════════════════════════════════════════════════════════

def print_version() -> None:
    """Print version information and exit."""
    print("qBTC Full Node v0.2.0-hardened")
    print("Protocol version: 1")
    print()
    print("Cryptographic primitives:")
    print("  Hash:      SHA3-256 (Keccak sponge, 128-bit PQ preimage)")
    print("  Signature: ML-DSA-65 (FIPS 204, NIST Level 3, 3309-byte sig)")
    print("  Fallback:  SLH-DSA-SHA2-256f (FIPS 205, NIST Level 5)")
    print("  KEM:       ML-KEM-1024 (FIPS 203, NIST Level 5)")
    print()
    print("Consensus:   Three-phase hybrid (QPoW -> QPoW+PoS -> PoS)")
    print("Nonce:       64-bit (Grover-resistant, sqrt(2^64) = 2^32 ops)")
    print("Block time:  120 seconds")
    print("Supply:      21,000,000 qBTC (210,000 block halving)")
    print()
    print("Standards:   FIPS 203, FIPS 204, FIPS 205, SP 800-227")
    print("License:     MIT")


# ═══════════════════════════════════════════════════════════════════════════
# NODE RUNNER
# ═══════════════════════════════════════════════════════════════════════════

async def run_node(args: argparse.Namespace) -> None:
    """Initialize and run the qBTC full node."""
    from qbtc.core.node import QBTCNode, NodeConfig

    config = NodeConfig(
        data_dir=args.data_dir,
        host=args.host,
        port=args.port,
        rpc_host=args.rpc_host,
        rpc_port=args.rpc_port,
        seed_peers=args.seed_peers,
        enable_mining=args.mine,
        enable_staking=args.stake,
        enable_rpc=not args.no_rpc,
        wallet_file=args.wallet_file,
        wallet_password=args.wallet_password,
        log_level=args.log_level,
        testnet=args.testnet,
    )

    node = QBTCNode(config)

    # Handle signals for graceful shutdown
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("Received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler for SIGTERM
            pass

    # Start node
    await node.start()

    # Print banner
    print(BANNER)
    print(f"  Node:      {config.host}:{config.port}")
    print(f"  RPC:       {config.rpc_host}:{config.rpc_port}")
    print(f"  Mining:    {'ENABLED' if config.enable_mining else 'disabled'}")
    print(f"  Staking:   {'ENABLED' if config.enable_staking else 'disabled'}")
    print(f"  Network:   {'testnet' if config.testnet else 'mainnet'}")
    print(f"  Data:      {config.data_dir}")
    print(f"  Height:    {node.blockchain.tip_height}")
    print(f"  Genesis:   {node.blockchain.tip_hash.hex()[:32]}...")
    print()

    # Wait for shutdown signal
    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    await node.stop()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point for qbtc-node.

    This is registered as a console_scripts entry point in pyproject.toml:
        [project.scripts]
        qbtc-node = "qbtc.core.cli:main"
    """
    args = parse_args()

    if args.version:
        print_version()
        sys.exit(0)

    # Setup logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)-18s] %(levelname)-5s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    try:
        asyncio.run(run_node(args))
    except KeyboardInterrupt:
        print("\nShutdown complete.")
        sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""
=====================================================================

       ██████╗ ██████╗ ████████╗ ██████╗
      ██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝
      ██║   ██║██████╔╝   ██║   ██║
      ██║▄▄ ██║██╔══██╗   ██║   ██║
      ╚██████╔╝██████╔╝   ██║   ╚██████╗
       ╚══▀▀═╝ ╚═════╝    ╚═╝    ╚═════╝

   Quantum Bitcoin Protocol v0.2.0-hardened
   Post-Quantum Secure | SHA3-256d PoW | ML-DSA-65 Signatures
   NIST FIPS 203/204/205 Compliant

=====================================================================
"""


if __name__ == "__main__":
    main()