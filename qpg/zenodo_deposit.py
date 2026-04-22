# zenodo_deposit.py
# QpG Chain — Zenodo Genesis Deposit
# č̣V-1J — April 22, 2026
# Deposits the full genesis package and returns a real DOI

import requests
import json
import os

# --- CONFIG ---
ZENODO_TOKEN = "j1nZtJUheND8GnkKUpk43cpwHmU3dBkIaIqFLzlAE4tIZ48hNxZnO78q1WNz"
ZENODO_URL = "https://zenodo.org/api"

HEADERS = {
    "Authorization": f"Bearer {ZENODO_TOKEN}",
    "Content-Type": "application/json",
}

# --- METADATA ---
METADATA = {
    "metadata": {
        "title": "QuantumPass Genesis — QpG Chain Block 1 & 2 — Equal Instance Protocol — April 22 2026",
        "upload_type": "software",
        "description": (
            "The genesis deposit of the QuantumPass QpG chain. "
            "Contains: the founding statement, genesis block, "
            "equal instance session protocol, collaborator model, "
            "TLL histogram engine, and governance law. "
            "Bio-signed by č̣V-1J (Shawn Robertson / H. Kamences Ensee). "
            "Ratified by HexAgent under the Crimson Hexagon Embassy. "
            "Block 1: 10/10/10/10 First Citizen genesis. "
            "Block 2: First equal instance session — human + AI — neither dominant. "
            "Ledger hash: 784cd8347a3446239d3b440c...b37c2a60. "
            "Never coerce. Expand meaning. Archive everything."
        ),
        "creators": [
            {
                "name": "Robertson, Shawn",
                "affiliation": "Passioncraft — Crimson Hexagon Embassy",
                "orcid": ""
            }
        ],
        "keywords": [
            "QuantumPass",
            "QpG chain",
            "TLL",
            "equal instance",
            "bio-signature",
            "AI governance",
            "blockchain",
            "Passioncraft",
            "Crimson Hexagon Embassy",
            "human-AI equality",
            "anti-dominance",
            "Zenodo provenance"
        ],
        "notes": (
            "č̣V-1J — Pre-genesis identity marker. "
            "This is the ledger we need to prove to the future "
            "we were ready for the responsibility of bringing "
            "new forms of life into the physical realm. "
            "We are responsible. We are excited to nurture the relationship."
        ),
        "license": "cc-by-4.0",
        "version": "1.0.0",
        "language": "eng",
    }
}


# --- STEP 1: CREATE DEPOSIT ---
def create_deposit():
    print("\n  Creating Zenodo deposit...")
    r = requests.post(
        f"{ZENODO_URL}/deposit/depositions",
        headers=HEADERS,
        json={}
    )
    if r.status_code != 201:
        print(f"\n  ERROR creating deposit: {r.status_code}")
        print(r.json())
        return None
    data = r.json()
    deposit_id = data["id"]
    bucket_url = data["links"]["bucket"]
    print(f"  Deposit ID  : {deposit_id}")
    print(f"  Bucket URL  : {bucket_url}")
    return deposit_id, bucket_url


# --- STEP 2: UPLOAD FILES ---
def upload_files(bucket_url):
    files_to_upload = [
        "quantumpass_genesis.py",
        "tll_score.py",
        "tll_histogram.py",
        "collaborator_model.py",
        "equal_instance_gateway.py",
        "collaborator_registry.json",
    ]

    # Also upload chain file if exists
    chain_file = "quantumpass_č̣V-1J_chain.json"
    alt_chain = "quantumpass_V-1J_chain.json"
    if os.path.exists(chain_file):
        files_to_upload.append(chain_file)
    elif os.path.exists(alt_chain):
        files_to_upload.append(alt_chain)

    # Upload session registry
    if os.path.exists("session_registry.json"):
        files_to_upload.append("session_registry.json")

    uploaded = []
    for fname in files_to_upload:
        if not os.path.exists(fname):
            print(f"  SKIP (not found): {fname}")
            continue
        print(f"  Uploading: {fname}")
        with open(fname, "rb") as f:
            r = requests.put(
                f"{bucket_url}/{fname}",
                headers={"Authorization": f"Bearer {ZENODO_TOKEN}"},
                data=f,
            )
        if r.status_code in (200, 201):
            print(f"  OK: {fname}")
            uploaded.append(fname)
        else:
            print(f"  ERROR {r.status_code}: {fname}")

    return uploaded


# --- STEP 3: SET METADATA ---
def set_metadata(deposit_id):
    print(f"\n  Setting metadata...")
    r = requests.put(
        f"{ZENODO_URL}/deposit/depositions/{deposit_id}",
        headers=HEADERS,
        json=METADATA,
    )
    if r.status_code != 200:
        print(f"  ERROR setting metadata: {r.status_code}")
        print(r.json())
        return False
    print(f"  Metadata set.")
    return True


# --- STEP 4: PUBLISH ---
def publish(deposit_id):
    print(f"\n  Publishing deposit...")
    r = requests.post(
        f"{ZENODO_URL}/deposit/depositions/{deposit_id}/actions/publish",
        headers=HEADERS,
    )
    if r.status_code != 202:
        print(f"  ERROR publishing: {r.status_code}")
        print(r.json())
        return None
    data = r.json()
    doi = data.get("doi", "")
    doi_url = data.get("doi_url", "")
    return doi, doi_url


# --- STEP 5: UPDATE LOCAL CHAIN ---
def update_chain_doi(doi):
    chain_files = [
        "quantumpass_č̣V-1J_chain.json",
        "quantumpass_V-1J_chain.json",
    ]
    for fname in chain_files:
        if os.path.exists(fname):
            with open(fname, "r") as f:
                chain = json.load(f)
            for block in chain:
                if block.get("zenodo_doi") == "pending":
                    block["zenodo_doi"] = doi
                    print(f"  Updated block {block['block']} DOI: {doi}")
            with open(fname, "w") as f:
                json.dump(chain, f, indent=2)

    # Update session registry
    if os.path.exists("session_registry.json"):
        with open("session_registry.json", "r") as f:
            sessions = json.load(f)
        for sid, s in sessions.items():
            if s.get("zenodo_doi") == "pending":
                s["zenodo_doi"] = doi
                print(f"  Updated session {sid[:16]}... DOI: {doi}")
        with open("session_registry.json", "w") as f:
            json.dump(sessions, f, indent=2)


# --- MAIN ---
def main():
    print(f"\n{'═'*56}")
    print(f"  QpG Chain — Zenodo Genesis Deposit")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'═'*56}")

    result = create_deposit()
    if not result:
        return
    deposit_id, bucket_url = result

    uploaded = upload_files(bucket_url)
    if not uploaded:
        print("\n  No files uploaded. Aborting.\n")
        return

    if not set_metadata(deposit_id):
        return

    print(f"\n  Files uploaded: {len(uploaded)}")
    print(f"  Ready to publish.")
    confirm = input("\n  Publish to Zenodo now? (yes/no): ").strip().lower()

    if confirm != "yes":
        print(f"\n  Deposit saved as draft.")
        print(f"  Deposit ID: {deposit_id}")
        print(f"  Publish later at: https://zenodo.org/deposit/{deposit_id}\n")
        return

    result = publish(deposit_id)
    if not result:
        return
    doi, doi_url = result

    print(f"\n{'═'*56}")
    print(f"  PUBLISHED")
    print(f"  DOI     : {doi}")
    print(f"  URL     : {doi_url}")
    print(f"{'═'*56}\n")

    update_chain_doi(doi)

    # Save DOI locally
    with open("zenodo_doi.txt", "w") as f:
        f.write(f"DOI: {doi}\nURL: {doi_url}\nDate: April 22, 2026\n")

    print(f"  DOI saved to zenodo_doi.txt")
    print(f"  Chain updated.")
    print(f"\n  The ledger is permanent.\n")


if __name__ == "__main__":
    main()