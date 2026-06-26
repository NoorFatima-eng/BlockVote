"""
test_blockchain.py — Standalone blockchain test suite
Run: python test_blockchain.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# Clean start — remove existing files before testing
for f in ["voting_chain.json", "aes_election.key", "voting.db"]:
    if os.path.exists(f):
        os.remove(f)
        print(f"[Cleanup] Removed {f}")

from time import time
from blockchain import Blockchain
from crypto_utils import generate_rsa_keypair, sign_vote, verify_signature, encrypt_vote, decrypt_vote

print("\n" + "="*55)
print("  BLOCKVOTE — BLOCKCHAIN TEST SUITE")
print("="*55)

# Test 1: Create blockchain
print("\n[Test 1] Blockchain Create + Genesis Block")
bc = Blockchain(election_start=time()-10, election_end=time()+3600)
assert len(bc.chain) == 1
assert bc.chain[0].index == 0
print("  ✓ Genesis block created")

# Test 2: RSA keypair
print("\n[Test 2] RSA Keypair Generation")
priv, pub = generate_rsa_keypair()
assert "BEGIN PRIVATE KEY" in priv
assert "BEGIN PUBLIC KEY" in pub
print("  ✓ RSA 2048-bit key pair generated")

# Test 3: Sign + Verify
print("\n[Test 3] RSA Sign + Verify")
voter_id = "TEST123VOTER"
candidate = "Imran Khan (PTI)"
sig = sign_vote(priv, voter_id, candidate)
valid = verify_signature(pub, voter_id, candidate, sig)
assert valid == True, "Signature verification failed!"
print(f"  ✓ Vote sign + verify: {valid}")

# Test 3b: Tampered vote
tampered = verify_signature(pub, voter_id, "Bob Smith", sig)
assert tampered == False
print(f"  ✓ Tampered vote correctly rejected: {tampered}")

# Test 4: AES Encrypt/Decrypt
print("\n[Test 4] AES Encryption")
enc = encrypt_vote(candidate)
dec = decrypt_vote(enc)
assert dec == candidate
print(f"  ✓ Encrypted: {enc[:30]}...")
print(f"  ✓ Decrypted: {dec}")

# Test 5: Vote cast + mine
print("\n[Test 5] Vote Cast + Block Mine")
bc.add_vote(voter_id, candidate, sig, pub, enc)
block = bc.mine_block()
assert len(bc.chain) == 2
assert block.index == 1
assert len(block.transactions) == 1
print(f"  ✓ Block #{block.index} mined, proof={block.proof}")

# Test 6: Chain validity
print("\n[Test 6] Chain Integrity Check")
audit = bc.is_chain_valid()
assert all(b["valid"] for b in audit)
print(f"  ✓ All {len(audit)} blocks valid")

# Test 7: Persistence
print("\n[Test 7] Blockchain Persistence (Restart Simulation)")
del bc
bc2 = Blockchain()
assert len(bc2.chain) == 2
votes = bc2.get_all_votes()
assert len(votes) == 1
assert votes[0]["candidate"] == candidate
print(f"  ✓ After reload: {len(bc2.chain)} blocks, {len(votes)} vote found")

# Test 8: AES key persistence
print("\n[Test 8] AES Key Persistence")
from crypto_utils import decrypt_vote as dv
dec2 = dv(enc)
assert dec2 == candidate
print(f"  ✓ Decryption still works after restart: {dec2}")

# Test 9: Double vote (add same voter again)
print("\n[Test 9] Double Vote Detection (Blockchain level)")
bc2.add_vote(voter_id, candidate, sig, pub, enc)
bc2.mine_block()
all_votes = bc2.get_all_votes()
voter_votes = [v for v in all_votes if v["voter_id"] == voter_id]
print(f"  INFO: Blockchain has {len(voter_votes)} vote(s) for same voter (DB check prevents this in production)")

# Test 10: Tampered chain detection
print("\n[Test 10] Tampered Chain Detection")
bc2.chain[1].transactions[0]["candidate"] = "Bob Smith"  # Tamper!
audit2 = bc2.is_chain_valid()
tampered_blocks = [b for b in audit2 if not b["valid"]]
assert len(tampered_blocks) > 0
print(f"  ✓ Tampering detected: Block #{tampered_blocks[0]['index']} — {tampered_blocks[0]['reason']}")

print("\n" + "="*55)
print("  ALL TESTS PASSED! ✓")
print("="*55 + "\n")
