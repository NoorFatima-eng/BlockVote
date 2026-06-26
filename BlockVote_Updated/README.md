# BlockVote — Blockchain Voting System
Information Security Project | 5 Members | 3 Days

## Project Structure
```
voting_system/
├── app.py          → Member 5: Main Flask app, all routes
├── blockchain.py   → Member 1: Block and Blockchain classes
├── auth.py         → Member 2: Register, login, voter database
├── vote.py         → Member 3: Cast vote, double-vote prevention
├── results.py      → Member 4: Count votes, chain verification
├── requirements.txt
└── templates/
    ├── base.html
    ├── index.html
    ├── register.html
    ├── login.html
    ├── vote.html
    ├── receipt.html
    ├── already_voted.html
    ├── results.html
    └── admin.html
```

## How to Run

### Step 1 — Install Python (3.8 or above)
Download from https://python.org

### Step 2 — Install Flask
Open terminal / command prompt in the project folder:
```
pip install flask
```

### Step 3 — Run the app
```
python app.py
```

### Step 4 — Open in browser
Go to: http://127.0.0.1:5000

## How to Demo (Day 3)

1. Register a voter → note the Voter ID
2. Login → cast a vote
3. Try voting again → see "Double Voting Blocked"
4. Open Results page → see live bar chart
5. Open Admin page → see all blocks verified as valid
6. (DEMO TRICK) Open voting.db with DB Browser for SQLite,
   manually change a vote in the blockchain.json or voters table,
   then refresh Admin → watch the chain show TAMPERED in red!

## IS Concepts Covered
- SHA-256 hashing (blockchain + voter ID generation)
- Blockchain data structure (immutable, chained blocks)
- Proof of Work (mining)
- Password hashing (authentication)
- Session management (Flask sessions)
- Tamper detection (chain integrity verification)
- Double-spend prevention (applied to double-voting)
