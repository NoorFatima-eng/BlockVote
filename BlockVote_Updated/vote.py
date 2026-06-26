"""
vote.py — Vote casting with AES encryption + RSA signature + ZKP
Private key  comes from session (not stored in DB)
"""
from auth import has_voted, mark_voted, get_candidates, get_voter, log_action
from crypto_utils import encrypt_vote, sign_vote, zkp_generate_proof, zkp_verify_proof


def cast_vote(blockchain, voter_id, candidate, private_key_pem):
    """
    Cast a vote.
    private_key_pem: voter's private key stored in session
    """
    # 1. Voting window check
    if not blockchain.is_voting_open():
        status = blockchain.get_time_status()
        log_action(voter_id, "VOTE_FAIL", f"Voting closed: {status}")
        return False, "Voting is currently closed."

    # 2. Validate candidate
    if candidate not in get_candidates():
        log_action(voter_id, "VOTE_FAIL", "Invalid candidate")
        return False, "Invalid candidate."

    # 3. Double-vote check
    if has_voted(voter_id):
        log_action(voter_id, "DOUBLE_VOTE_ATTEMPT", f"Tried to vote for {candidate}")
        return False, "You have already voted! Double voting is not allowed."

    # 4. Private key check (from session)
    if not private_key_pem:
        log_action(voter_id, "VOTE_FAIL", "Private key not in session — re-register needed")
        return False, "Signing key not found. Please log in again."

    # 5. Get public key from DB
    voter = get_voter(voter_id)
    if not voter or not voter.get("public_key"):
        return False, "Voter record not found."

    # 6. AES encrypt candidate name
    encrypted_candidate = encrypt_vote(candidate)

    # 7. RSA sign the vote
    try:
        signature = sign_vote(private_key_pem, voter_id, candidate)
    except Exception as e:
        log_action(voter_id, "VOTE_FAIL", f"Signature failed: {e}")
        return False, "Error signing your vote."

    # 8. ZKP proof
    zkp_proof = zkp_generate_proof(voter_id)
    if not zkp_verify_proof(zkp_proof):
        log_action(voter_id, "VOTE_FAIL", "ZKP verification failed")
        return False, "Zero Knowledge Proof verification failed."

    # 9. Record on blockchain
    blockchain.add_vote(
        voter_id=voter_id,
        candidate=candidate,
        signature=signature,
        public_key=voter["public_key"],
        encrypted_candidate=encrypted_candidate
    )
    blockchain.mine_block()

    # 10. Mark as voted in DB
    mark_voted(voter_id)
    log_action(voter_id, "VOTE_CAST", f"Voted for {candidate} — signed + encrypted + ZKP verified")

    return True, f"Vote for '{candidate}' recorded successfully! ✓ Signed ✓ Encrypted ✓ ZKP Verified"


def verify_vote_signature(blockchain, voter_id):
    from crypto_utils import verify_signature
    for vote in blockchain.get_all_votes():
        if vote["voter_id"] == voter_id:
            valid = verify_signature(
                vote["public_key"],
                voter_id,
                vote["candidate"],
                vote["signature"]
            )
            return {"found": True, "valid": valid, "candidate": vote["candidate"]}
    return {"found": False}


def get_voter_receipt(blockchain, voter_id):
    for vote in blockchain.get_all_votes():
        if vote["voter_id"] == voter_id:
            return {
                "found": True,
                "candidate": vote["candidate"],
                "timestamp": vote["timestamp"],
                "encrypted": vote.get("encrypted_candidate", "N/A")
            }
    return {"found": False}
