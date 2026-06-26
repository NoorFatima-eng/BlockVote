"""
 Results + Chain Verification + Signature Audit + Report Export
"""
from auth import get_candidates, get_audit_log
from crypto_utils import verify_signature, decrypt_vote
from collections import Counter
from time import time
import json


def get_results(blockchain):
    candidates = get_candidates()
    counts = {c: 0 for c in candidates}
    for vote in blockchain.get_all_votes():
        if vote.get("candidate") in counts:
            counts[vote["candidate"]] += 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def get_winner(blockchain):
    results = get_results(blockchain)
    if not results or max(results.values()) == 0:
        return None
    winner = max(results, key=results.get)
    return {"name": winner, "votes": results[winner]}


def get_total_votes(blockchain):
    return len(blockchain.get_all_votes())


def verify_chain(blockchain):
    audit = blockchain.is_chain_valid()
    is_valid = all(b["valid"] for b in audit)
    return {
        "is_valid": is_valid,
        "blocks": audit,
        "total_blocks": len(blockchain.chain),
        "message": "Chain intact." if is_valid else "WARNING: Chain tampered!"
    }


def verify_all_signatures(blockchain):
    """
    Verify RSA digital signature of every vote on the blockchain.
    Returns per-vote verification results.
    """
    results = []
    for vote in blockchain.get_all_votes():
        valid = verify_signature(
            vote.get("public_key", ""),
            vote.get("voter_id", ""),
            vote.get("candidate", ""),
            vote.get("signature", "")
        )
        results.append({
            "voter_id": vote["voter_id"][:8] + "...",
            "candidate": vote["candidate"],
            "signature_valid": valid
        })
    return results


def get_chain_data(blockchain):
    blocks = []
    for block in blockchain.chain:
        blocks.append({
            "index": block.index,
            "timestamp": block.timestamp,
            "transactions": block.transactions,
            "previous_hash": block.previous_hash[:20] + "...",
            "proof": block.proof,
            "hash": blockchain.hash_block(block)[:20] + "..."
        })
    return blocks


def generate_audit_report(blockchain):
    """
    Generate a full text audit report for download.
    Covers: chain integrity, vote count, signature verification, audit log.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("   BLOCKVOTE — ELECTION AUDIT REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Chain integrity
    chain_status = verify_chain(blockchain)
    lines.append("── BLOCKCHAIN INTEGRITY ──────────────────────────────")
    lines.append(f"Status  : {'✓ VALID' if chain_status['is_valid'] else '✗ TAMPERED'}")
    lines.append(f"Blocks  : {chain_status['total_blocks']}")
    for b in chain_status["blocks"]:
        status = "OK" if b["valid"] else f"TAMPERED — {b['reason']}"
        lines.append(f"  Block #{b['index']}: {status}")
    lines.append("")

    # Vote results
    lines.append("── VOTE RESULTS ──────────────────────────────────────")
    results = get_results(blockchain)
    total = get_total_votes(blockchain)
    for candidate, count in results.items():
        pct = round(count / total * 100, 1) if total > 0 else 0
        lines.append(f"  {candidate:<20} {count} votes  ({pct}%)")
    lines.append(f"  Total votes: {total}")
    lines.append("")

    # Signature verification
    lines.append("── DIGITAL SIGNATURE VERIFICATION ───────────────────")
    sig_results = verify_all_signatures(blockchain)
    for r in sig_results:
        status = "✓ VALID" if r["signature_valid"] else "✗ INVALID"
        lines.append(f"  Voter {r['voter_id']} → {r['candidate']}: {status}")
    lines.append("")

    # Audit log
    lines.append("── SECURITY AUDIT LOG (last 20 events) ──────────────")
    for entry in get_audit_log(20):
        import datetime
        ts = datetime.datetime.fromtimestamp(entry["timestamp"]).strftime("%H:%M:%S")
        lines.append(f"  [{ts}] {entry['action']:<20} voter={entry['voter_id'] or 'N/A'} — {entry['detail']}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)
