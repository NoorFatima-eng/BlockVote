"""
Persistent Blockchain with JSON file storage
Blockchain will no longer reset on server restart.
     Chain is saved to voting.chain.json
"""
import hashlib
import json
import os
from time import time

CHAIN_FILE = "voting_chain.json"


class Block:
    def __init__(self, index, transactions, previous_hash, proof, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.proof = proof

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "proof": self.proof,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            index=d["index"],
            transactions=d["transactions"],
            previous_hash=d["previous_hash"],
            proof=d["proof"],
            timestamp=d["timestamp"]
        )


class Blockchain:
    def __init__(self, election_start=None, election_end=None):
        self.pending_transactions = []
        self.election_start = election_start or time()
        self.election_end = election_end or (time() + 86400)

        #  Load from file if exists, otherwise create fresh chain
        if os.path.exists(CHAIN_FILE):
            self.chain = self._load_chain()
            print(f"[Blockchain] Loaded {len(self.chain)} blocks from {CHAIN_FILE}")
        else:
            self.chain = []
            self._create_genesis_block()
            self._save_chain()
            print(f"[Blockchain] New chain created with genesis block")

    def _create_genesis_block(self):
        genesis = Block(indwex=0, transactions=[], previous_hash="0" * 64, proof=0)
        self.chain.append(genesis)

    def _save_chain(self):
        """Save chain to JSON file after every block."""
        data = {
            "election_start": self.election_start,
            "election_end": self.election_end,
            "chain": [b.to_dict() for b in self.chain]
        }
        with open(CHAIN_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def _load_chain(self):
        """Load chain from JSON file."""
        with open(CHAIN_FILE, "r") as f:
            data = json.load(f)
        # Restore election window if saved
        if "election_start" in data:
            self.election_start = data["election_start"]
        if "election_end" in data:
            self.election_end = data["election_end"]
        return [Block.from_dict(b) for b in data["chain"]]

    def reset_chain(self):
        """Admin only: Reset blockchain and delete saved file."""
        self.chain = []
        self.pending_transactions = []
        self._create_genesis_block()
        self._save_chain()

    @property
    def last_block(self):
        return self.chain[-1]

    def is_voting_open(self):
        now = time()
        return self.election_start <= now <= self.election_end

    def get_time_status(self):
        now = time()
        if now < self.election_start:
            return "not_started"
        elif now > self.election_end:
            return "ended"
        else:
            remaining = int(self.election_end - now)
            hours = remaining // 3600
            minutes = (remaining % 3600) // 60
            return f"open:{hours}h {minutes}m remaining"

    def add_vote(self, voter_id, candidate, signature, public_key, encrypted_candidate):
        if not self.is_voting_open():
            raise ValueError("Voting is closed.")
        self.pending_transactions.append({
            "voter_id": voter_id,
            "candidate": candidate,
            "encrypted_candidate": encrypted_candidate,
            "signature": signature,
            "public_key": public_key,
            "timestamp": time()
        })

    def mine_block(self):
        last = self.last_block
        proof = self._proof_of_work(last.proof)
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.hash_block(last),
            proof=proof
        )
        self.pending_transactions = []
        self.chain.append(new_block)
        self._save_chain()  
        return new_block

    @staticmethod
    def hash_block(block):
        block_string = json.dumps(block.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def _proof_of_work(self, last_proof):
        proof = 0
        while not self._valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def _valid_proof(last_proof, proof):
        guess = f"{last_proof}{proof}".encode()
        return hashlib.sha256(guess).hexdigest()[:2] == "00"

    def is_chain_valid(self):
        results = []
        for i, block in enumerate(self.chain):
            if i == 0:
                results.append({"index": i, "valid": True, "reason": "Genesis block"})
                continue
            prev_block = self.chain[i - 1]
            if block.previous_hash != self.hash_block(prev_block):
                results.append({"index": i, "valid": False, "reason": "Hash mismatch — TAMPERED!"})
            elif not self._valid_proof(prev_block.proof, block.proof):
                results.append({"index": i, "valid": False, "reason": "Invalid proof of work"})
            else:
                results.append({"index": i, "valid": True, "reason": "OK"})
        return results

    def get_all_votes(self):
        votes = []
        for block in self.chain:
            votes.extend(block.transactions)
        return votes

    def to_json(self):
        return [b.to_dict() for b in self.chain]
    
    def save_to_file(self):
        import json, os
        payload = {
            "election_start": self.election_start,
            "election_end":   self.election_end,
            "chain": [block.to_dict() for block in self.chain],
        }
        with open("chain.json", "w") as f:
            json.dump(payload, f, indent=2)

    @classmethod
    def load_from_file(cls):
        import json, os
        if not os.path.exists("chain.json"):
            return cls(election_start=time(), election_end=time() + 86400)
        with open("chain.json", "r") as f:
            payload = json.load(f)
        instance = cls.__new__(cls)
        instance.pending_transactions = []
        instance.election_start = payload["election_start"]
        instance.election_end   = payload["election_end"]
        instance.chain = []
        for bd in payload["chain"]:
            block = Block(
                index=bd["index"],
                transactions=bd["transactions"],
                previous_hash=bd["previous_hash"],
                proof=bd["proof"],
            )
            block.timestamp = bd["timestamp"]
            instance.chain.append(block)
        return instance
