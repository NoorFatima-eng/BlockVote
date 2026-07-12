#  BlockVote — Advanced Blockchain Voting System


>
> **Technologies:** Blockchain · RSA-2048 · AES-Fernet · Zero Knowledge Proof · SHA-256

---

##  Project Overview

BlockVote is a secure, cryptographically-protected online voting system built with Python and Flask. The system implements **four layers of security** to ensure every vote is authentic, tamper-evident, and private:

-  **Blockchain** — immutable vote storage
-  **RSA-2048** — digital signatures per vote
-  **AES (Fernet)** — vote encryption
- **Zero Knowledge Proof** — identity verification without revealing secrets

---

##  Project Structure

```
voting_system_v2/
├── app.py            → Main Flask app, all web routes
├── blockchain.py     → Block & Blockchain classes, Proof of Work
├── auth.py           → Registration, login, SQLite DB, brute-force protection
├── vote.py           → Vote casting: AES encrypt + RSA sign + ZKP verify
├── results.py        → Vote counting, chain verification, audit report export
├── crypto_utils.py   → All crypto primitives: RSA, AES-Fernet, ZKP (Schnorr)
├── requirements.txt
└── templates/        → HTML templates (Jinja2 + Bootstrap 5)
    ├── base.html
    ├── index.html
    ├── register.html
    ├── login.html
    ├── vote.html
    ├── receipt.html
    ├── already_voted.html
    ├── results.html
    ├── admin.html
    └── admin_login.html
```

---

##  Member Responsibilities

| Member | File | Responsibility |
|--------|------|----------------|
| Member 1 | `blockchain.py` + `crypto_utils.py` (partial) | Block & Blockchain class, Proof of Work, SHA-256 chain hashing |
| Member 2 | `auth.py` | Voter registration, login, SQLite DB, brute-force lockout, RSA key storage |
| Member 3 | `vote.py` + `crypto_utils.py` (partial) | Vote casting flow, AES encryption, RSA signing, ZKP generation |
| Member 4 | `results.py` | Vote counting, chain integrity audit, signature verification, report export |
| Member 5 | `app.py` | Flask routes, session management, admin panel, REST API |

---

##  How to Run

### Step 1 — Install Python
Download Python 3.8 or above from [python.org](https://python.org)

### Step 2 — Navigate to project folder
```bash
cd voting_system_v2
```

### Step 3 — Install dependencies
```bash
pip install flask cryptography
```
Or use the requirements file:
```bash
pip install -r requirements.txt
```

### Step 4 — Run the application
```bash
python app.py
```

### Step 5 — Open in browser
```
http://127.0.0.1:5000
```

---

##  Cryptographic Concepts Used

### 1.  Blockchain — Tamper-Evident Vote Storage
**File:** `blockchain.py`

Each vote is stored in a block linked to the previous block via SHA-256 hash. If any vote is modified after recording, the entire chain becomes invalid — detected automatically in the Admin panel.

- Genesis block: `index=0`, empty transactions, `previous_hash = "0" × 64`
- Each vote triggers `mine_block()` — Proof of Work ensures chain integrity
- Mining difficulty: SHA-256 hash must start with `"00"`
- Admin panel shows block-by-block status:  OK or  TAMPERED

---

### 2.  RSA-2048 — Digital Signatures
**File:** `crypto_utils.py` → `generate_rsa_keypair()`, `sign_vote()`, `verify_signature()`

Every vote is digitally signed by the voter's unique private key. Proves the vote was cast by the legitimate voter and has not been altered.

- Key size: **2048-bit** (industry standard)
- Public exponent: `65537`
- Padding: **PSS with MGF1(SHA-256)** — more secure than PKCS#1 v1.5
- Message signed: `voter_id:candidate` — both fields are protected
- Keys generated at registration, stored in SQLite DB (PEM format)
- Admin panel verifies every vote's RSA signature individually

---

### 3.  AES Encryption (Fernet) — Vote Confidentiality
**File:** `crypto_utils.py` → `encrypt_vote()`, `decrypt_vote()`

Candidate name is AES-encrypted before being stored on the blockchain, adding a confidentiality layer to the vote record.

- Algorithm: **Fernet = AES-128-CBC + HMAC-SHA256** (authenticated encryption)
- Encrypted vote stored as `encrypted_candidate` field in each block
- Decryption available only to admin for counting/audit

---

### 4.  Zero Knowledge Proof — Identity Verification
**File:** `crypto_utils.py` → `zkp_generate_proof()`, `zkp_verify_proof()`

Using the **Schnorr protocol**, the voter proves knowledge of their `voter_id` without revealing it.

- Secret: `x = SHA-256(voter_id) mod p`
- Public value: `y = g^x mod p` (shared without revealing `x`)
- Flow: Commitment → Challenge → Response → Verification
- Verification equation: `g^s ≡ t · y^c (mod p)`

> **Note:** Parameters `p=23`, `g=5` are simplified for demonstration. Production systems use 2048-bit primes.

---

### 5. #️ SHA-256 — Hashing
Used throughout the system:

| Use | Location |
|-----|----------|
| Blockchain block linking | `blockchain.py` |
| Voter ID generation: `SHA-256(name + CNIC)[:12]` | `auth.py` |
| Password hashing: `SHA-256(salt + password)` | `auth.py` |
| ZKP secret derivation from `voter_id` | `crypto_utils.py` |

---

##  Security Features

| Feature | Implementation | File |
|---------|---------------|------|
| Double-vote prevention | `has_voted` flag in SQLite, checked before every vote | `auth.py`, `vote.py` |
| Brute-force protection | Account locked 5 minutes after 3 failed login attempts | `auth.py` |
| Voting time window | Election start/end timestamps, enforced per vote | `blockchain.py` |
| Admin two-factor access | Secret URL key + username/password required | `app.py`, `auth.py` |
| Security audit log | All actions logged with timestamp, voter ID, IP address | `auth.py` |
| Chain tamper detection | Admin panel highlights any modified block in red | `results.py` |
| RSA signature audit | Admin can verify every vote's digital signature | `results.py` |
| Audit report export | Full text report downloadable from admin panel | `results.py` |

---

##  Demo Guide (Presentation)

### Step 1 — Register a voter
- Go to `/register`
- Enter name, CNIC, password
- System generates RSA keypair + unique Voter ID
- Note the Voter ID shown on screen

### Step 2 — Login and vote
- Go to `/login`, enter Voter ID and password
- Select a candidate and click Vote
- Receipt page shows: **RSA Signature Verified ✓ | AES Encrypted ✓ | ZKP Verified ✓**

### Step 3 — Demonstrate double-vote prevention
- Try voting again with the same account
- System blocks: *"You have already voted! Double voting is not allowed."*

### Step 4 — Live results
- Go to `/results`
- Bar chart auto-refreshes every 5 seconds via `/api/results`

### Step 5 — Admin panel
```
http://127.0.0.1:5000/admin?key=BV-9X2K-SECURE
```
- Username: `admin`
- Password: `admin@blockvote2024`
- Shows: blockchain audit, RSA signature verification per vote, security audit log

### Step 6 — Tamper demonstration (demo trick)
1. Close Flask app (`Ctrl+C`)
2. Open `voting.db` with **DB Browser for SQLite**
3. Manually edit a vote in the blockchain data
4. Restart app and open Admin panel
5. Tampered block shows in 🔴 RED with "TAMPERED" label

---

##  IS Concepts Covered

| IS Concept | How Applied |
|-----------|-------------|
| Confidentiality | AES-Fernet encrypts candidate name in blockchain |
| Integrity | RSA signatures + blockchain hash-linking prevent tampering |
| Authentication | SHA-256 password hashing + brute-force protection |
| Non-repudiation | RSA digital signature uniquely tied to each voter's private key |
| Zero Knowledge | Schnorr protocol proves voter identity without revealing secret |
| Immutability | Proof of Work + chained hashes make vote history permanent |
| Access Control | Admin protected by URL key + credentials + session management |
| Audit Trail | Full security log of all actions with timestamps and IP addresses |

---

##  Requirements

```
flask>=2.3.0
cryptography>=41.0.0
```

- Python 3.8+
- SQLite (built into Python — no separate install needed)
- Any modern browser (Chrome, Firefox, Edge)

---

##  Vote Flow Summary

```
Register  →  RSA keypair generated  →  Keys saved to SQLite DB
   ↓
Login     →  SHA-256 password check  →  Brute-force lockout if failed
   ↓
Vote      →  AES encrypt candidate
          →  RSA sign (voter_id:candidate)
          →  ZKP verify identity
          →  Add to blockchain + mine block
          →  Mark voter as voted in DB
---

---

*BlockVote — Information Security Project | Blockchain + RSA + AES + ZKP | Python Flask*
