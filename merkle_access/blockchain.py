import time
import json
from typing import List, Dict, Any, Optional
from .crypto import sha256_hex, load_public_key_from_pem, sign_data, verify_signature

def compute_block_hash(
    index: int,
    timestamp: float,
    previous_hash: str,
    merkle_root: str,
    transactions: List[Dict[str, Any]],
    leaves: List[Dict[str, Any]],
    signer_admin_id: str
) -> str:
    """Computes a canonical SHA-256 hash of the block contents."""
    payload = {
        "index": index,
        "timestamp": timestamp,
        "previous_hash": previous_hash,
        "merkle_root": merkle_root,
        "transactions": transactions,
        "leaves": leaves,
        "signer_admin_id": signer_admin_id
    }
    canonical_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    return sha256_hex(canonical_bytes)


class Block:
    """
    Represents a single block in the permission ledger.
    """
    def __init__(
        self,
        index: int,
        timestamp: float,
        previous_hash: str,
        merkle_root: str,
        transactions: List[Dict[str, Any]],
        leaves: List[Dict[str, Any]],
        signer_admin_id: str,
        signature: str = "",
        hash_val: str = ""
    ):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.transactions = transactions
        self.leaves = leaves  # List of dicts representing PermissionLeaf
        self.signer_admin_id = signer_admin_id  # Public key PEM of the signing admin
        
        # Calculate block hash if not provided
        self.hash = hash_val if hash_val else self.calculate_hash()
        self.signature = signature

    def calculate_hash(self) -> str:
        """Recalculates the block hash."""
        return compute_block_hash(
            self.index,
            self.timestamp,
            self.previous_hash,
            self.merkle_root,
            self.transactions,
            self.leaves,
            self.signer_admin_id
        )

    def sign(self, admin_private_key_bytes: bytes) -> None:
        """Signs the block hash using the administrator's private key PEM."""
        from .crypto import load_private_key_from_pem, sign_data
        priv_key = load_private_key_from_pem(admin_private_key_bytes)
        sig_bytes = sign_data(priv_key, self.hash.encode('utf-8'))
        self.signature = sig_bytes.hex()

    def verify(self) -> bool:
        """
        Verifies that the block hash is correct and that the admin's signature is valid.
        """
        if self.calculate_hash() != self.hash:
            return False
        
        if not self.signature:
            return False

        try:
            admin_public_key = load_public_key_from_pem(self.signer_admin_id.encode('utf-8'))
            sig_bytes = bytes.fromhex(self.signature)
            return verify_signature(admin_public_key, self.hash.encode('utf-8'), sig_bytes)
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the block to a dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "transactions": self.transactions,
            "leaves": self.leaves,
            "signer_admin_id": self.signer_admin_id,
            "hash": self.hash,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Deserializes a block from a dictionary."""
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            previous_hash=data["previous_hash"],
            merkle_root=data["merkle_root"],
            transactions=data["transactions"],
            leaves=data["leaves"],
            signer_admin_id=data["signer_admin_id"],
            signature=data["signature"],
            hash_val=data["hash"]
        )


class Blockchain:
    """
    Manages a list of blocks and enforces integrity validation.
    """
    def __init__(self, authorized_admins: List[str]):
        """
        Initializes a blockchain with a list of authorized admin public key PEMs.
        """
        self.chain: List[Block] = []
        self.authorized_admins = authorized_admins  # PEM string list

    def add_genesis_block(self, admin_private_key_bytes: bytes, admin_public_key_pem: str) -> None:
        """
        Creates and appends the genesis block to start the chain.
        """
        if self.chain:
            raise ValueError("Genesis block already exists")
        
        # Genesis root is root of empty leaves list
        from .merkle import MerkleTree
        genesis_tree = MerkleTree([])
        
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            previous_hash="0" * 64,
            merkle_root=genesis_tree.get_root(),
            transactions=[{"type": "genesis", "info": "Initial Block"}],
            leaves=[],
            signer_admin_id=admin_public_key_pem
        )
        genesis_block.sign(admin_private_key_bytes)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Returns the latest block in the chain."""
        if not self.chain:
            raise ValueError("Chain is empty. Genesis block is missing.")
        return self.chain[-1]

    def add_block(self, block: Block) -> None:
        """
        Adds a pre-signed block to the chain after verifying its validity.
        """
        latest_block = self.get_latest_block()
        if block.index != latest_block.index + 1:
            raise ValueError(f"Invalid block index: expected {latest_block.index + 1}, got {block.index}")
        
        if block.previous_hash != latest_block.hash:
            raise ValueError("Invalid previous hash reference")
        
        if block.signer_admin_id not in self.authorized_admins:
            raise ValueError("Block signer is not an authorized administrator")
        
        if not block.verify():
            raise ValueError("Block signature or hash validation failed")

        self.chain.append(block)

    def validate_chain(self) -> bool:
        """
        Validates the entire blockchain for tamper detection and structural integrity.
        """
        if not self.chain:
            return False

        # Verify genesis block structure
        genesis = self.chain[0]
        if genesis.index != 0:
            return False
        if genesis.previous_hash != "0" * 64:
            return False
        if genesis.signer_admin_id not in self.authorized_admins:
            return False
        if not genesis.verify():
            return False

        # Validate subsequent blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            if current.index != i:
                return False
            if current.previous_hash != prev.hash:
                return False
            if current.signer_admin_id not in self.authorized_admins:
                return False
            if not current.verify():
                return False

        return True

    def to_list(self) -> List[Dict[str, Any]]:
        """Converts the chain into a list of block dictionaries."""
        return [block.to_dict() for block in self.chain]

    @classmethod
    def from_list(cls, block_list: List[Dict[str, Any]], authorized_admins: List[str]) -> 'Blockchain':
        """Constructs a Blockchain from a list of serialized blocks."""
        blockchain = cls(authorized_admins)
        for block_dict in block_list:
            block = Block.from_dict(block_dict)
            blockchain.chain.append(block)
        return blockchain
