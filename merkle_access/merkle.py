import json
from typing import List, Dict, Any
from .crypto import sha256

class PermissionLeaf:
    """
    Represents an access permission grant stored in the Merkle Tree.
    """
    def __init__(self, user_id: str, path: str, permission_type: str, encrypted_key: str):
        self.user_id = user_id  # Username or PEM-serialized public key
        self.path = path        # Resource/file path being authorized
        self.permission_type = permission_type  # e.g., 'read', 'write', 'admin'
        self.encrypted_key = encrypted_key      # Base64-encoded encrypted file key

    def to_dict(self) -> Dict[str, str]:
        """Converts leaf data to a dict, sorted for deterministic JSON serialization."""
        return {
            "user_id": self.user_id,
            "path": self.path,
            "permission_type": self.permission_type,
            "encrypted_key": self.encrypted_key
        }

    def to_bytes(self) -> bytes:
        """Serializes the leaf properties into a canonical bytes format."""
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'PermissionLeaf':
        """Constructs a PermissionLeaf from a dictionary representation."""
        return cls(
            user_id=data["user_id"],
            path=data["path"],
            permission_type=data["permission_type"],
            encrypted_key=data["encrypted_key"]
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PermissionLeaf):
            return False
        return (self.user_id == other.user_id and
                self.path == other.path and
                self.permission_type == other.permission_type and
                self.encrypted_key == other.encrypted_key)


class MerkleTree:
    """
    Implements a Merkle Tree accumulator for PermissionLeaf instances.
    """
    def __init__(self, leaves: List[PermissionLeaf]):
        self.leaves = leaves
        self.levels: List[List[bytes]] = []
        self.root_hash = ""
        self.build_tree()

    def build_tree(self) -> None:
        """
        Builds the Merkle Tree level by level using the leaf hashes.
        Uses b'\x00' prefix for leaves and b'\x01' prefix for internal nodes
        to defend against second-preimage attacks.
        """
        if not self.leaves:
            # Default empty root hash
            empty_hash = sha256(b'\x00')
            self.root_hash = empty_hash.hex()
            self.levels = [[empty_hash]]
            return

        # Hash each leaf
        current_level = [sha256(b'\x00' + leaf.to_bytes()) for leaf in self.leaves]
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last element if odd number of nodes in level
                    right = left
                parent = sha256(b'\x01' + left + right)
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

        self.root_hash = self.levels[-1][0].hex()

    def get_root(self) -> str:
        """Returns the hex-encoded root hash of the Merkle Tree."""
        return self.root_hash

    def get_proof(self, index: int) -> List[Dict[str, Any]]:
        """
        Generates a Merkle Proof for the leaf at the specified index.
        Returns a list of sibling nodes, each as a dict: {'hash': hex_string, 'is_left': bool}
        """
        if index < 0 or index >= len(self.leaves):
            raise ValueError(f"Leaf index {index} is out of bounds (0-{len(self.leaves)-1})")

        proof = []
        curr_idx = index
        # Traverse from leaf level up to (but not including) the root level
        for level in self.levels[:-1]:
            if curr_idx % 2 == 1:
                # Sibling is on the left
                sibling_idx = curr_idx - 1
                is_left = True
            else:
                # Sibling is on the right
                sibling_idx = curr_idx + 1
                if sibling_idx >= len(level):
                    sibling_idx = curr_idx  # Sibling is self (duplicate case)
                is_left = False

            sibling_hash = level[sibling_idx].hex()
            proof.append({'hash': sibling_hash, 'is_left': is_left})
            curr_idx //= 2

        return proof


def verify_proof(leaf: PermissionLeaf, proof: List[Dict[str, Any]], root_hash: str) -> bool:
    """
    Verifies if a given PermissionLeaf belongs to the Merkle Tree with the specified root_hash
    using the provided proof.
    """
    # Recompute leaf hash
    curr_hash = sha256(b'\x00' + leaf.to_bytes())

    for step in proof:
        sibling_bytes = bytes.fromhex(step['hash'])
        is_left = step['is_left']

        if is_left:
            # Sibling is on the left, current hash is on the right
            curr_hash = sha256(b'\x01' + sibling_bytes + curr_hash)
        else:
            # Sibling is on the right, current hash is on the left
            curr_hash = sha256(b'\x01' + curr_hash + sibling_bytes)

    return curr_hash.hex() == root_hash
