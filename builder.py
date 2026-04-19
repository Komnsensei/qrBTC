#!/usr/bin/env python3
"""qBTC Project Builder — Creates the full directory tree and placeholders."""

import os
import sys
from pathlib import Path

ROOT = Path.home() / "qbtc-protocol"

DIRECTORIES = [
    ROOT / "src" / "qbtc" / "crypto",
    ROOT / "src" / "qbtc" / "core",
    ROOT / "src" / "qbtc" / "consensus",
    ROOT / "src" / "qbtc" / "network",
    ROOT / "src" / "qbtc" / "wallet",
    ROOT / "docs",
    ROOT / "tests",
]

INIT_FILES = {
    ROOT / "src" / "qbtc" / "__init__.py": '"""qBTC - Post-Quantum Bitcoin Protocol"""\n__version__ = "0.2.0"\n',
    ROOT / "src" / "qbtc" / "crypto" / "__init__.py": "",
    ROOT / "src" / "qbtc" / "core" / "__init__.py": "",
    ROOT / "src" / "qbtc" / "consensus" / "__init__.py": "",
    ROOT / "src" / "qbtc" / "network" / "__init__.py": "",
    ROOT / "src" / "qbtc" / "wallet" / "__init__.py": "",
}

PYPROJECT = """[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "qbtc"
version = "0.2.0"
description = "qBTC - Post-Quantum Bitcoin Protocol"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.12"
keywords = ["post-quantum", "bitcoin", "blockchain", "ML-DSA", "SHA3"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security :: Cryptography",
]
dependencies = []

[project.optional-dependencies]
pqc = ["liboqs-python>=0.11.0"]
full = [
    "liboqs-python>=0.11.0",
    "cryptography>=42.0.0",
    "rich>=13.7.0",
    "click>=8.1.7",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "mypy>=1.8",
    "ruff>=0.2",
]

[project.scripts]
qbtc-node = "qbtc.core.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.mypy]
python_version = "3.12"
strict = true

[tool.pytest.ini_options]
testpaths = [".", "tests"]
python_files = ["test_*.py"]
"""

GITIGNORE = """__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.env
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
qbtc_data/
*.qbtc
.DS_Store
Thumbs.db
"""

FILE_MANIFEST = [
    ("constants.py",            "src/qbtc/core/constants.py"),
    ("hashing.py",              "src/qbtc/crypto/hashing.py"),
    ("keys.py",                 "src/qbtc/crypto/keys.py"),
    ("transaction.py",          "src/qbtc/core/transaction.py"),
    ("block.py",                "src/qbtc/core/block.py"),
    ("chain.py",                "src/qbtc/core/chain.py"),
    ("mempool.py",              "src/qbtc/core/mempool.py"),
    ("node.py",                 "src/qbtc/core/node.py"),
    ("cli.py",                  "src/qbtc/core/cli.py"),
    ("consensus.py",            "src/qbtc/consensus/consensus.py"),
    ("miner.py",                "src/qbtc/consensus/miner.py"),
    ("p2p_protocol.py",         "src/qbtc/network/p2p_protocol.py"),
    ("p2p_node.py",             "src/qbtc/network/p2p_node.py"),
    ("wallet.py",               "src/qbtc/wallet/wallet.py"),
    ("test_qbtc.py",            "test_qbtc.py"),
    ("Dockerfile",              "Dockerfile"),
    (".zenodo.json",            ".zenodo.json"),
    ("CITATION.cff",            "CITATION.cff"),
    ("LICENSE",                 "LICENSE"),
    ("README.md",               "README.md"),
    ("qBTC_Whitepaper_v1.md",   "docs/WHITEPAPER.md"),
    ("ARCHITECTURE.md",         "docs/ARCHITECTURE.md"),
    ("ZENODO_PUBLISH_GUIDE.md", "docs/ZENODO_PUBLISH_GUIDE.md"),
]


def main():
    print()
    print("=" * 60)
    print("  qBTC PROJECT BUILDER v0.2.0")
    print("=" * 60)
    print()
    print(f"  Target: {ROOT}")
    print()

    # 1. Directories
    print("[1/5] Creating directories...")
    for d in DIRECTORIES:
        d.mkdir(parents=True, exist_ok=True)
        print(f"       {d}")

    # 2. __init__.py
    print()
    print("[2/5] Writing __init__.py files...")
    for path, content in INIT_FILES.items():
        path.write_text(content, encoding="utf-8")
        print(f"       {path.relative_to(ROOT)}")

    # 3. pyproject.toml
    print()
    print("[3/5] Writing pyproject.toml...")
    (ROOT / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")

    # 4. .gitignore
    print("[4/5] Writing .gitignore...")
    (ROOT / ".gitignore").write_text(GITIGNORE, encoding="utf-8")

    # 5. Placeholders
    print()
    print("[5/5] Creating file placeholders...")
    for doc_name, rel_path in FILE_MANIFEST:
        full_path = ROOT / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        if not full_path.exists():
            placeholder = (
                f"# PLACEHOLDER\n"
                f"# Copy from Nexus chat. Ask Brain:\n"
                f"#   print {doc_name}\n"
                f"# Then paste into this file.\n"
            )
            full_path.write_text(placeholder, encoding="utf-8")
        print(f"       {rel_path:50s}  <-- print {doc_name}")

    # Done
    print()
    print("=" * 60)
    print("  DONE! Project skeleton created.")
    print("=" * 60)
    print()
    print("  NEXT: Go to the Nexus chat and say:")
    print()
    print('    print constants.py')
    print()
    print("  Copy the output into:")
    print(f"    {ROOT / 'src' / 'qbtc' / 'core' / 'constants.py'}")
    print()
    print("  Repeat for all 23 files listed above.")
    print()
    print("  When done:")
    print(f"    cd {ROOT}")
    print('    pip install -e ".[dev]"')
    print("    pytest test_qbtc.py -v")
    print()


if __name__ == "__main__":
    main()