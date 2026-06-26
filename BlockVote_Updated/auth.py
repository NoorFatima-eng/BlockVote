"""
auth.py — Authentication + Brute Force Protection + RSA Key Storage
 Private key is NOT saved in DB — only public key is stored
 Candidates are stored in DB — admin can add/remove them
 Default candidates include PTI / Imran Khan
"""
import hashlib
import sqlite3
from time import time
from crypto_utils import generate_rsa_keypair

DB_PATH = "voting.db"
MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 300  # 5 minute


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS voters (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_id        TEXT UNIQUE NOT NULL,
            name            TEXT NOT NULL,
            password        TEXT NOT NULL,
            has_voted       INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until    REAL DEFAULT 0,
            public_key      TEXT
        );

        CREATE TABLE IF NOT EXISTS candidates (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT UNIQUE NOT NULL,
            party   TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL NOT NULL,
            voter_id    TEXT,
            action      TEXT NOT NULL,
            detail      TEXT,
            ip_address  TEXT
        );
    """)
    # Default candidates — can be changed later via admin panel
    default_candidates = [
        ("Imran Khan (PTI)", "Pakistan Tehreek-e-Insaf"),
        ("Shehbaz Sharif (PMLN)", "Pakistan Muslim League-N"),
        ("Bilawal Bhutto (PPP)", "Pakistan Peoples Party"),
    ]
    for name, party in default_candidates:
        conn.execute(
            "INSERT OR IGNORE INTO candidates (name, party) VALUES (?, ?)",
            (name, party)
        )
    conn.commit()
    conn.close()


def hash_password(password):
    salt = "blockvote_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def generate_voter_id(name, national_id):
    raw = f"{name.lower().strip()}{national_id.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


def log_action(voter_id, action, detail="", ip="unknown"):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (timestamp, voter_id, action, detail, ip_address) VALUES (?,?,?,?,?)",
        (time(), voter_id, action, detail, ip)
    )
    conn.commit()
    conn.close()


def register_voter(name, national_id, password):
    voter_id = generate_voter_id(name, national_id)
  
    private_key, public_key = generate_rsa_keypair()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO voters (voter_id, name, password, public_key) VALUES (?,?,?,?)",
            (voter_id, name, hash_password(password), public_key)
        )
        conn.commit()
        log_action(voter_id, "REGISTER", f"Voter '{name}' registered")
        # Return private key to caller — store it in the session
        return True, voter_id, private_key
    except sqlite3.IntegrityError:
        return False, "Voter already registered.", None
    finally:
        conn.close()

#-----------------BRUTE FORCE PROTECTION---------------- 
def login_voter(voter_id, password, ip="unknown"):
    conn = get_db()
    voter = conn.execute(
        "SELECT * FROM voters WHERE voter_id = ?", (voter_id,)
    ).fetchone()
    conn.close()

    if not voter:
        log_action(voter_id, "LOGIN_FAIL", "Voter ID not found", ip)
        return None, "Invalid Voter ID or password."

    voter = dict(voter)

    if voter["locked_until"] and time() < voter["locked_until"]:
        remaining = int(voter["locked_until"] - time())
        log_action(voter_id, "LOGIN_BLOCKED", f"Account locked, {remaining}s remaining", ip)
        return None, f"Account locked. Try again in {remaining} seconds."

    if voter["password"] != hash_password(password):
        attempts = voter["failed_attempts"] + 1
        conn = get_db()
        if attempts >= MAX_ATTEMPTS:
            lock_time = time() + LOCKOUT_SECONDS
            conn.execute(
                "UPDATE voters SET failed_attempts=?, locked_until=? WHERE voter_id=?",
                (attempts, lock_time, voter_id)
            )
            conn.commit()
            conn.close()
            log_action(voter_id, "ACCOUNT_LOCKED", f"Locked after {attempts} failed attempts", ip)
            return None, f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS//60} minutes."
        else:
            conn.execute(
                "UPDATE voters SET failed_attempts=? WHERE voter_id=?",
                (attempts, voter_id)
            )
            conn.commit()
            conn.close()
            log_action(voter_id, "LOGIN_FAIL", f"Wrong password attempt {attempts}/{MAX_ATTEMPTS}", ip)
            return None, f"Wrong password. {MAX_ATTEMPTS - attempts} attempts remaining."

    conn = get_db()
    conn.execute(
        "UPDATE voters SET failed_attempts=0, locked_until=0 WHERE voter_id=?",
        (voter_id,)
    )
    conn.commit()
    conn.close()
    log_action(voter_id, "LOGIN_SUCCESS", "Successful login", ip)
    return voter, "Login successful."


def get_voter(voter_id):
    conn = get_db()
    v = conn.execute("SELECT * FROM voters WHERE voter_id=?", (voter_id,)).fetchone()
    conn.close()
    return dict(v) if v else None


def mark_voted(voter_id):
    conn = get_db()
    conn.execute("UPDATE voters SET has_voted=1 WHERE voter_id=?", (voter_id,))
    conn.commit()
    conn.close()


def has_voted(voter_id):
    v = get_voter(voter_id)
    return v and v["has_voted"] == 1


def get_candidates():
    conn = get_db()
    rows = conn.execute("SELECT name FROM candidates ORDER BY id").fetchall()
    conn.close()
    return [r["name"] for r in rows]


def get_candidates_full():
    """Returns id, name, party for admin panel."""
    conn = get_db()
    rows = conn.execute("SELECT id, name, party FROM candidates ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_candidate(name, party=""):
    """Admin: Add a new candidate."""
    name = name.strip()
    party = party.strip()
    if not name:
        return False, "Candidate name required."
    conn = get_db()
    try:
        conn.execute("INSERT INTO candidates (name, party) VALUES (?, ?)", (name, party))
        conn.commit()
        return True, f"Candidate '{name}' added."
    except sqlite3.IntegrityError:
        return False, "Candidate already exists."
    finally:
        conn.close()


def remove_candidate(candidate_id):
    """Admin: Remove a candidate by ID."""
    conn = get_db()
    conn.execute("DELETE FROM candidates WHERE id=?", (candidate_id,))
    conn.commit()
    conn.close()
    return True, "Candidate removed."


def get_audit_log(limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Admin Authentication ──────────────────────────────────────────────

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = hashlib.sha256("admin@blockvote2024".encode()).hexdigest()
ADMIN_SECRET_KEY = "BV-9X2K-SECURE"


def verify_admin(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return username == ADMIN_USERNAME and hashed == ADMIN_PASSWORD


def verify_admin_key(key):
    return key == ADMIN_SECRET_KEY
