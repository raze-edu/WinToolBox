import base64
import json
import time
from typing import Tuple, List, Dict, Any, Optional
from .crypto import (
    load_public_key_from_pem,
    load_private_key_from_pem,
    rsa_encrypt,
    rsa_decrypt,
    generate_rsa_key_pair,
    private_key_to_pem,
    public_key_to_pem
)
from .merkle import PermissionLeaf, MerkleTree, verify_proof
from .blockchain import Block, Blockchain


class User:
    """
    Represents a user in the system with their RSA key pair.
    """
    def __init__(self, user_id: str, public_key_pem: str, private_key_pem: Optional[str] = None):
        self.user_id = user_id
        self.public_key_pem = public_key_pem
        self.private_key_pem = private_key_pem

    @classmethod
    def generate(cls, user_id: str) -> 'User':
        """Generates a new user with a fresh RSA key pair."""
        priv, pub = generate_rsa_key_pair()
        return cls(
            user_id=user_id,
            public_key_pem=public_key_to_pem(pub).decode('utf-8'),
            private_key_pem=private_key_to_pem(priv).decode('utf-8')
        )


class Admin:
    """
    Represents an administrator who has authorization to sign block state changes.
    """
    def __init__(self, admin_id: str, public_key_pem: str, private_key_pem: Optional[bytes] = None):
        self.admin_id = admin_id
        self.public_key_pem = public_key_pem
        self.private_key_pem = private_key_pem  # Kept as bytes

    @classmethod
    def generate(cls, admin_id: str) -> 'Admin':
        """Generates a new admin with a fresh RSA key pair."""
        priv, pub = generate_rsa_key_pair()
        return cls(
            admin_id=admin_id,
            public_key_pem=public_key_to_pem(pub).decode('utf-8'),
            private_key_pem=private_key_to_pem(priv)
        )


class AccessManager:
    """
    The administrative manager coordinates the blockchain, Merkle accumulator,
    and user access verification.
    """
    def __init__(self, authorized_admin_pems: List[str]):
        self.blockchain = Blockchain(authorized_admins=authorized_admin_pems)
        self.authorized_admin_pems = authorized_admin_pems

    def initialize_chain(self, admin_private_key_bytes: bytes, admin_public_key_pem: str) -> None:
        """
        Initializes the blockchain with a Genesis block signed by the initial administrator.
        """
        self.blockchain.add_genesis_block(admin_private_key_bytes, admin_public_key_pem)

    def get_active_leaves(self) -> List[PermissionLeaf]:
        """
        Retrieves the active permission leaves from the latest block.
        """
        if not self.blockchain.chain:
            return []
        latest_block = self.blockchain.get_latest_block()
        return [PermissionLeaf.from_dict(d) for d in latest_block.leaves]

    def grant_access(
        self,
        admin_private_key_bytes: bytes,
        admin_public_key_pem: str,
        user_id: str,
        user_public_key_pem: str,
        path: str,
        permission_type: str,
        file_key: bytes
    ) -> Block:
        """
        Grants a user access to a file/path by encrypting the file key using the user's RSA public key,
        appending the leaf, rebuilding the Merkle Tree, and committing a signed block to the chain.
        """
        if admin_public_key_pem not in self.authorized_admin_pems:
            raise ValueError("Admin public key is not in the authorized admins list")

        # 1. Fetch current active leaves
        active_leaves = self.get_active_leaves()

        # Check if identical permission already exists to avoid duplication
        # Load user public key
        pub_key = load_public_key_from_pem(user_public_key_pem.encode('utf-8'))
        
        # 2. Encrypt the file key with the user's public key
        enc_key_bytes = rsa_encrypt(pub_key, file_key)
        enc_key_b64 = base64.b64encode(enc_key_bytes).decode('utf-8')

        # 3. Create the new leaf
        new_leaf = PermissionLeaf(
            user_id=user_id,
            path=path,
            permission_type=permission_type,
            encrypted_key=enc_key_b64
        )
        
        # Add new leaf to active set
        active_leaves.append(new_leaf)

        # 4. Rebuild the Merkle tree to get the new root
        new_tree = MerkleTree(active_leaves)
        new_root = new_tree.get_root()

        # 5. Build transaction details
        tx = {
            "type": "grant",
            "user_id": user_id,
            "path": path,
            "permission_type": permission_type
        }

        # 6. Create and append the new block
        latest_block = self.blockchain.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            previous_hash=latest_block.hash,
            merkle_root=new_root,
            transactions=[tx],
            leaves=[leaf.to_dict() for leaf in active_leaves],
            signer_admin_id=admin_public_key_pem
        )
        new_block.sign(admin_private_key_bytes)
        
        self.blockchain.add_block(new_block)
        return new_block

    def revoke_access(
        self,
        admin_private_key_bytes: bytes,
        admin_public_key_pem: str,
        user_id: str,
        path: str,
        permission_type: Optional[str] = None
    ) -> Block:
        """
        Revokes a user's access from a file/path. Rebuilds the Merkle tree and commits a signed block.
        """
        if admin_public_key_pem not in self.authorized_admin_pems:
            raise ValueError("Admin public key is not in the authorized admins list")

        # 1. Fetch current active leaves
        active_leaves = self.get_active_leaves()

        # 2. Filter out revoked permissions
        original_count = len(active_leaves)
        
        def matches(leaf: PermissionLeaf) -> bool:
            user_match = (leaf.user_id == user_id)
            path_match = (leaf.path == path)
            perm_match = (permission_type is None or leaf.permission_type == permission_type)
            return user_match and path_match and perm_match

        filtered_leaves = [leaf for leaf in active_leaves if not matches(leaf)]

        if len(filtered_leaves) == original_count:
            raise ValueError(f"No matching permission found to revoke for user '{user_id}' on path '{path}'")

        # 3. Rebuild the Merkle tree to get the new root
        new_tree = MerkleTree(filtered_leaves)
        new_root = new_tree.get_root()

        # 4. Build transaction details
        tx = {
            "type": "revoke",
            "user_id": user_id,
            "path": path,
            "permission_type": permission_type if permission_type else "all"
        }

        # 5. Create and append the new block
        latest_block = self.blockchain.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            previous_hash=latest_block.hash,
            merkle_root=new_root,
            transactions=[tx],
            leaves=[leaf.to_dict() for leaf in filtered_leaves],
            signer_admin_id=admin_public_key_pem
        )
        new_block.sign(admin_private_key_bytes)
        
        self.blockchain.add_block(new_block)
        return new_block

    def get_access_proof(self, user_id: str, path: str) -> Tuple[PermissionLeaf, List[Dict[str, Any]], str]:
        """
        Generates a Merkle membership proof for a specific user and path based on the latest blockchain state.
        Returns:
            Tuple containing:
            - The PermissionLeaf instance
            - The Merkle Proof (list of sibling hashes)
            - The root hash of the latest block
        """
        if not self.blockchain.chain:
            raise ValueError("Blockchain is empty")

        latest_block = self.blockchain.get_latest_block()
        active_leaves = self.get_active_leaves()

        # Find the leaf matching the user and path
        target_index = -1
        target_leaf = None
        for i, leaf in enumerate(active_leaves):
            if leaf.user_id == user_id and leaf.path == path:
                target_index = i
                target_leaf = leaf
                break

        if target_index == -1 or target_leaf is None:
            raise ValueError(f"Access permission for user '{user_id}' on path '{path}' does not exist in the active set.")

        # Reconstruct tree to obtain proof
        tree = MerkleTree(active_leaves)
        proof = tree.get_proof(target_index)

        return target_leaf, proof, latest_block.merkle_root

    @staticmethod
    def verify_and_decrypt_key(
        user_private_key_bytes: bytes,
        leaf: PermissionLeaf,
        proof: List[Dict[str, Any]],
        latest_merkle_root: str
    ) -> bytes:
        """
        Allows a user to cryptographically verify their permission leaf against the latest root hash,
        and then decrypt the file key using their private key.
        """
        # 1. Verify Merkle accumulator proof
        if not verify_proof(leaf, proof, latest_merkle_root):
            raise ValueError("Merkle accumulator proof verification failed")

        # 2. Decrypt the symmetric key using RSA private key
        priv_key = load_private_key_from_pem(user_private_key_bytes)
        enc_key_bytes = base64.b64decode(leaf.encrypted_key.encode('utf-8'))
        return rsa_decrypt(priv_key, enc_key_bytes)

    def to_json(self) -> str:
        """Serializes the entire AccessManager state (blockchain and admin list) to JSON."""
        state = {
            "authorized_admin_pems": self.authorized_admin_pems,
            "blockchain": self.blockchain.to_list()
        }
        return json.dumps(state, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'AccessManager':
        """Deserializes and reconstructs the AccessManager from JSON."""
        state = json.loads(json_str)
        admin_pems = state["authorized_admin_pems"]
        manager = cls(authorized_admin_pems=admin_pems)
        manager.blockchain = Blockchain.from_list(state["blockchain"], authorized_admins=admin_pems)
        return manager
