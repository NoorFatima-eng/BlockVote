"""
crypto_utils.py — RSA Digital Signatures, AES-Fernet Encryption, ZKP
FIX 1: AES key is now persistent (saved in aes_key.key file) — restart safe
FIX 2: Private key is only used during cast_vote, never stored in DB
"""
import hashlib
import json
import random
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

AES_KEY_FILE = "aes_election.key"


def _load_or_create_aes_key():
    """
    FIX: AES key is generated once and saved to file.
    The same key is reused after restarts — old votes can still be decrypted.
    """
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, "rb") as f:
            key = f.read().strip()
        return key
    else:
        key = Fernet.generate_key()
        with open(AES_KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[AES] New election key generated and saved to {AES_KEY_FILE}")
        return key


# Load persistent AES key at startup
AES_KEY = _load_or_create_aes_key()
_fernet = Fernet(AES_KEY)


def encrypt_vote(candidate_name: str) -> str:
    encrypted = _fernet.encrypt(candidate_name.encode())
    return encrypted.decode()


def decrypt_vote(encrypted: str) -> str:
    return _fernet.decrypt(encrypted.encode()).decode()


# ─── RSA Digital Signatures ───────────────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generate RSA 2048-bit key pair.
    Returns (private_key_pem, public_key_pem) as strings.
    NOTE: Private key is given to voter only — DO NOT save to DB.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem


def sign_vote(private_key_pem: str, voter_id: str, candidate: str) -> str:
    """
    Sign a vote using RSA private key.
    Message = voter_id:candidate
    Returns base64-encoded signature.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    message = f"{voter_id}:{candidate}".encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(public_key_pem: str, voter_id: str, candidate: str, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        message = f"{voter_id}:{candidate}".encode()
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─── Zero Knowledge Proof (Schnorr Protocol) ─────────────────────────────────

ZKP_P = 23
ZKP_G = 5


def zkp_generate_proof(voter_id: str) -> dict:
    secret = int(hashlib.sha256(voter_id.encode()).hexdigest(), 16) % (ZKP_P - 1) + 1
    public_value = pow(ZKP_G, secret, ZKP_P)
    r = random.randint(1, ZKP_P - 2)
    commitment = pow(ZKP_G, r, ZKP_P)
    challenge_input = f"{ZKP_G}{public_value}{commitment}".encode()
    challenge = int(hashlib.sha256(challenge_input).hexdigest(), 16) % ZKP_P
    response = (r + challenge * secret) % (ZKP_P - 1)
    return {
        "commitment": commitment,
        "challenge": challenge,
        "response": response,
        "public_value": public_value
    }


def zkp_verify_proof(proof: dict) -> bool:
    try:
        t = proof["commitment"]
        c = proof["challenge"]
        s = proof["response"]
        y = proof["public_value"]
        lhs = pow(ZKP_G, s, ZKP_P)
        rhs = (t * pow(y, c, ZKP_P)) % ZKP_P
        return lhs == rhs
    except Exception:
        return False
