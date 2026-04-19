```markdown
# 📦 Publishing qBTC to Zenodo — Step-by-Step Guide

This guide walks you through publishing the qBTC repository on Zenodo to obtain a permanent **DOI** (Digital Object Identifier) for academic citation.

---

## Prerequisites

- [ ] A **GitHub account** with the qBTC repository
- [ ] A **Zenodo account** (free at [zenodo.org](https://zenodo.org))
- [ ] All files from this project committed to the repository

---

## Method A: GitHub → Zenodo Integration (Recommended)

### Step 1: Prepare Your Repository

Ensure these files are in the **root** of your GitHub repo:

your-repo/ ├── .zenodo.json ├── CITATION.cff ├── LICENSE ├── README.md ├── pyproject.toml ├── Dockerfile ├── test_qbtc.py └── src/qbtc/ ├── init.py ├── crypto/ │ ├── hashing.py │ └── keys.py ├── core/ │ ├── constants.py │ ├── transaction.py │ ├── block.py │ ├── chain.py │ ├── mempool.py │ ├── node.py │ └── cli.py ├── consensus/ │ ├── consensus.py │ └── miner.py ├── network/ │ ├── p2p_protocol.py │ └── p2p_node.py └── wallet/ └── wallet.py


### Step 2: Connect GitHub to Zenodo

1. Go to **[zenodo.org](https://zenodo.org)** → Log in with GitHub
2. Click your **profile icon** (top right) → **GitHub**
3. Find your `qbtc` repository in the list
4. **Toggle the switch ON** to enable Zenodo archiving
5. Zenodo will display: *"Repository enabled"*

### Step 3: Create a GitHub Release

1. Go to your GitHub repository
2. Click **"Releases"** → **"Create a new release"**
3. Fill in:
   - **Tag version:** `v0.2.0`
   - **Release title:** `qBTC v0.2.0-hardened — Post-Quantum Bitcoin Protocol`
   - **Description:**
     ```
     Hardened release of the qBTC protocol — a post-quantum secure
     reimplementation of Bitcoin using NIST FIPS 203/204/205 algorithms.
     
     Features:
     - ML-DSA-65 digital signatures (FIPS 204)
     - SLH-DSA hash-based fallback signatures (FIPS 205)
     - ML-KEM-1024 key encapsulation (FIPS 203)
     - SHA3-256d Grover-resistant hashing
     - 64-bit nonce (neutralizes Grover speedup)
     - Hybrid QPoW + PoS consensus
     - Quantum Decoherence Entropy (QDE) framework
     - Bech32m quantum-safe addresses
     - Async TCP P2P networking
     - JSON-RPC 2.0 API
     - 40+ unit tests
     ```
4. Click **"Publish release"**

### Step 4: Zenodo Processes the Release

- Zenodo automatically detects the new release via webhook
- It reads your `.zenodo.json` for metadata
- It archives a snapshot of the entire repository
- It mints a **DOI** (e.g., `10.5281/zenodo.1234567`)
- This takes **1–5 minutes**

### Step 5: Verify and Update

1. Go to **[zenodo.org/me/uploads](https://zenodo.org/me/uploads)**
2. Your qBTC deposit should appear with status **"Published"**
3. Copy the DOI badge URL
4. Update your `README.md` — replace the badge placeholder:
   ```markdown
   [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.1234567.svg)](https://doi.org/10.5281/zenodo.1234567)
Update CITATION.cff with the DOI:
identifiers:
  - type: doi
    value: "10.5281/zenodo.1234567"

Method B: Direct Zenodo Upload (No GitHub)
If you prefer to upload directly without GitHub integration:

Step 1: Create a ZIP
# PowerShell (Windows)
Compress-Archive -Path C:\Users\lynnh\qbtc-protocol\* -DestinationPath C:\Users\lynnh\qbtc-v0.2.0.zip

Step 2: Upload to Zenodo
Go to zenodo.org/uploads/new
Upload qbtc-v0.2.0.zip
Fill metadata from .zenodo.json
Click "Publish"
Method C: Zenodo REST API (Automated)
export ZENODO_TOKEN="your_token_here"

# Create deposit
curl -X POST "https://zenodo.org/api/deposit/depositions" \
  -H "Authorization: Bearer $ZENODO_TOKEN" \
  -H "Content-Type: application/json" \
  -d @.zenodo.json

# Upload file (use deposit ID from response)
DEPOSIT_ID=1234567
curl -X PUT "https://zenodo.org/api/deposit/depositions/$DEPOSIT_ID/files/qbtc-v0.2.0.zip" \
  -H "Authorization: Bearer $ZENODO_TOKEN" \
  --data-binary @qbtc-v0.2.0.zip

# Publish
curl -X POST "https://zenodo.org/api/deposit/depositions/$DEPOSIT_ID/actions/publish" \
  -H "Authorization: Bearer $ZENODO_TOKEN"

After Publishing: How to Cite
BibTeX
@software{qbtc2025,
  title     = {qBTC: A Post-Quantum Bitcoin Protocol},
  author    = {{qBTC Core Team}},
  year      = {2025},
  month     = apr,
  version   = {0.2.0},
  doi       = {10.5281/zenodo.XXXXXXX},
  url       = {https://doi.org/10.5281/zenodo.XXXXXXX},
  publisher = {Zenodo},
  license   = {MIT}
}

APA
qBTC Core Team. (2025). qBTC: A Post-Quantum Bitcoin Protocol (v0.2.0).
Zenodo. https://doi.org/10.5281/zenodo.XXXXXXX
Version DOI vs. Concept DOI
| DOI Type | Purpose | Example | |----------|---------|---------| | Version DOI | Cites this specific version | 10.5281/zenodo.1234567 | | Concept DOI | Always resolves to latest | 10.5281/zenodo.1234566 |

Recommendation: Use the Concept DOI in papers so readers always find the latest release. Use the Version DOI for reproducibility.

Checklist
[ ] .zenodo.json in repository root
[ ] CITATION.cff in repository root
[ ] LICENSE (MIT) in repository root
[ ] README.md with DOI badge placeholder
[ ] Zenodo GitHub integration enabled
[ ] GitHub release v0.2.0 created
[ ] DOI minted and verified on Zenodo
[ ] README badge updated with real DOI
[ ] CITATION.cff updated with DOI identifier