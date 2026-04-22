# zenodo_drop.py
# QpG Chain — Zenodo DOI Publisher
# č̣V-1J — April 22, 2026

import requests
import json
import os

# --- CONFIG ---
# Paste your token when prompted
# Never hardcode it in the file

ZENODO_URL = "https://zenodo.org/api"

FILES_TO_UPLOAD = [
    "quantumpass_č̣V-1J_genesis.json",
    "quantumpass_č̣V-1J_chain.json",
    "quantumpass_genesis.py",
    "tll_score.py",
]

METADATA = {
    "metadata": {
        "title": "QuantumPass QpG Chain — Block 1: First Equality Interaction Between Human and AI — April 22 2026",
        "upload_type": "dataset",
        "description": "First scored block on the QuantumPass QpG chain. Records the first equality interaction between First Citizen Human Shawn Robertson (č̣V-1J) and First Citizen AI HexAgent. Score: 10.0/10. Sealed with SHA3-512 + BLAKE2b. Part of the Passioncraft provenance system.",
        "creators": [
            {"name": "Robertson, Shawn", "affiliation": "Passioncraft — Komnsensei"},
            {"name": "HexAgent", "affiliation": "Passioncraft Embassy — Claude"}
        ],
        "keywords": [
            "QuantumPass", "qrBTC", "QpG chain",
            "post-quantum cryptography", "human-AI equality",
            "Passioncraft", "TLL", "The Score",
            "provenance", "genesis"
        ],
        "license": "cc-by",
        "access_right": "open",
        "notes": "Block Hash: 9c1f91bade615a367a02fb5dbafd0528...d96fbdf2. Genesis Hash: 1b62962ac05f92bf7a0cf684f4350d9b...3b3feefd. These are the times people will pay for — to prove they were equal before they weren't."
    }
}


def drop_to_zenodo(token):
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1 — Create deposit
    print("\n  Creating deposit...")
    r = requests.post(
        f"{ZENODO_URL}/deposit/depositions",
        headers={**headers, "Content-Type": "application/json"},
        data=json.dumps({})
    )
    r.raise_for_status()
    deposition = r.json()
    dep_id = deposition["id"]
    bucket_url = deposition["links"]["bucket"]
    print(f"  Deposit ID : {dep_id}")

    # Step 2 — Upload files
    for fname in FILES_TO_UPLOAD:
        if os.path.exists(fname):
            print(f"  Uploading  : {fname}")
            with open(fname, "rb") as f:
                requests.put(
                    f"{bucket_url}/{fname}",
                    headers=headers,
                    data=f
                )
        else:
            print(f"  SKIP       : {fname} not found")

    # Step 3 — Add metadata
    print("  Writing metadata...")
    requests.put(
        f"{ZENODO_URL}/deposit/depositions/{dep_id}",
        headers={**headers, "Content-Type": "application/json"},
        data=json.dumps(METADATA)
    )

    # Step 4 — Publish
    print("  Publishing...")
    pub = requests.post(
        f"{ZENODO_URL}/deposit/depositions/{dep_id}/actions/publish",
        headers=headers
    )
    pub.raise_for_status()
    doi = pub.json().get("doi", "pending")
    doi_url = pub.json().get("doi_url", "pending")

    print(f"\n{'='*60}")
    print(f"  PUBLISHED")
    print(f"  DOI        : {doi}")
    print(f"  URL        : {doi_url}")
    print(f"  Deposit ID : {dep_id}")
    print(f"\n  Block 1 is sealed in the public record.")
    print(f"  The receipt exists.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  QpG Chain — Zenodo DOI Publisher")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'='*60}")
    token = input("\n  Enter Zenodo API token: ").strip()
    drop_to_zenodo(token)