import os
import sys
import unittest
import base64
from pathlib import Path

# Add project root to path so we can import merkle_access
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from merkle_access import (
    generate_rsa_key_pair,
    private_key_to_pem,
    public_key_to_pem,
    load_private_key_from_pem,
    load_public_key_from_pem,
    sign_data,
    verify_signature,
    rsa_encrypt,
    rsa_decrypt,
    generate_symmetric_key,
    encrypt_symmetric,
    decrypt_symmetric,
    PermissionLeaf,
    MerkleTree,
    verify_proof,
    Block,
    Blockchain,
    User,
    Admin,
    AccessManager
)

class TestCryptoPrimitives(unittest.TestCase):
    def test_rsa_key_lifecycle_and_signatures(self):
        # Generate keys
        priv, pub = generate_rsa_key_pair()
        
        # Serialize to PEM
        priv_pem = private_key_to_pem(priv)
        pub_pem = public_key_to_pem(pub)
        
        self.assertTrue(priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))
        
        # Reload keys
        priv_reloaded = load_private_key_from_pem(priv_pem)
        pub_reloaded = load_public_key_from_pem(pub_pem)
        
        # Test signing and verification
        message = b"Cryptographic verification payload"
        signature = sign_data(priv_reloaded, message)
        
        self.assertTrue(verify_signature(pub_reloaded, message, signature))
        
        # Verify tampered message fails signature check
        self.assertFalse(verify_signature(pub_reloaded, message + b"tamper", signature))

    def test_rsa_asymmetric_encryption(self):
        priv, pub = generate_rsa_key_pair()
        secret_key = b"super_secret_symmetric_key_12345"
        
        # Encrypt with public key
        encrypted = rsa_encrypt(pub, secret_key)
        self.assertNotEqual(secret_key, encrypted)
        
        # Decrypt with private key
        decrypted = rsa_decrypt(priv, encrypted)
        self.assertEqual(secret_key, decrypted)

    def test_symmetric_encryption(self):
        key = generate_symmetric_key()
        plaintext = b"Highly confidential file contents."
        
        ciphertext = encrypt_symmetric(key, plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        
        decrypted = decrypt_symmetric(key, ciphertext)
        self.assertEqual(plaintext, decrypted)


class TestMerkleTree(unittest.TestCase):
    def setUp(self):
        self.leaf1 = PermissionLeaf("alice", "keys/db", "read", "enckey1")
        self.leaf2 = PermissionLeaf("bob", "keys/db", "write", "enckey2")
        self.leaf3 = PermissionLeaf("charlie", "keys/backup", "admin", "enckey3")
        self.leaf4 = PermissionLeaf("dave", "keys/db", "read", "enckey4")
        self.leaf5 = PermissionLeaf("eve", "keys/docs", "read", "enckey5")

    def test_empty_tree(self):
        tree = MerkleTree([])
        self.assertEqual(len(tree.get_root()), 64)
        
    def test_single_leaf_tree(self):
        leaves = [self.leaf1]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        
        proof = tree.get_proof(0)
        # Sibling proof of a single leaf tree is empty (or matches its own level-dependent duplication)
        # Here: current_level starts with [hash1]. While len > 1 is False.
        # So levels is [[hash1]]. get_proof(0) goes over levels[:-1] which is empty!
        self.assertEqual(len(proof), 0)
        self.assertTrue(verify_proof(self.leaf1, proof, root))

    def test_multi_leaves_tree(self):
        leaves = [self.leaf1, self.leaf2, self.leaf3, self.leaf4, self.leaf5]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        
        # Verify all leaves can be proven and verified
        for i, leaf in enumerate(leaves):
            proof = tree.get_proof(i)
            self.assertTrue(verify_proof(leaf, proof, root), f"Failed for leaf {i}")
            
        # Verify a tampered leaf fails proof verification
        tampered_leaf = PermissionLeaf("alice", "keys/db", "write", "enckey1")
        proof = tree.get_proof(0)
        self.assertFalse(verify_proof(tampered_leaf, proof, root))


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.admin = Admin.generate("primary-admin")
        self.admin_pub_pem = self.admin.public_key_pem
        self.admin_priv_bytes = self.admin.private_key_pem
        
        self.blockchain = Blockchain([self.admin_pub_pem])

    def test_blockchain_genesis_and_validation(self):
        self.blockchain.add_genesis_block(self.admin_priv_bytes, self.admin_pub_pem)
        
        self.assertTrue(self.blockchain.validate_chain())
        
        latest = self.blockchain.get_latest_block()
        self.assertEqual(latest.index, 0)
        self.assertEqual(latest.previous_hash, "0" * 64)
        self.assertTrue(latest.verify())

    def test_adding_valid_and_invalid_blocks(self):
        self.blockchain.add_genesis_block(self.admin_priv_bytes, self.admin_pub_pem)
        latest = self.blockchain.get_latest_block()
        
        # Create a valid block
        new_block = Block(
            index=1,
            timestamp=latest.timestamp + 10,
            previous_hash=latest.hash,
            merkle_root="dummy_root_hash",
            transactions=[{"type": "grant", "user": "alice"}],
            leaves=[],
            signer_admin_id=self.admin_pub_pem
        )
        new_block.sign(self.admin_priv_bytes)
        
        self.blockchain.add_block(new_block)
        self.assertEqual(self.blockchain.get_latest_block().index, 1)
        self.assertTrue(self.blockchain.validate_chain())

        # Test index mismatch
        bad_index_block = Block(
            index=3,  # Should be 2
            timestamp=new_block.timestamp + 10,
            previous_hash=new_block.hash,
            merkle_root="root",
            transactions=[],
            leaves=[],
            signer_admin_id=self.admin_pub_pem
        )
        bad_index_block.sign(self.admin_priv_bytes)
        with self.assertRaises(ValueError):
            self.blockchain.add_block(bad_index_block)

        # Test previous hash mismatch
        bad_prev_hash_block = Block(
            index=2,
            timestamp=new_block.timestamp + 10,
            previous_hash="wrong_hash_val",
            merkle_root="root",
            transactions=[],
            leaves=[],
            signer_admin_id=self.admin_pub_pem
        )
        bad_prev_hash_block.sign(self.admin_priv_bytes)
        with self.assertRaises(ValueError):
            self.blockchain.add_block(bad_prev_hash_block)

        # Test unauthorized admin signer
        rogue_admin = Admin.generate("rogue-admin")
        bad_signer_block = Block(
            index=2,
            timestamp=new_block.timestamp + 10,
            previous_hash=new_block.hash,
            merkle_root="root",
            transactions=[],
            leaves=[],
            signer_admin_id=rogue_admin.public_key_pem
        )
        bad_signer_block.sign(rogue_admin.private_key_pem)
        with self.assertRaises(ValueError):
            self.blockchain.add_block(bad_signer_block)


class TestAccessManagerFlow(unittest.TestCase):
    def setUp(self):
        self.admin = Admin.generate("master-admin")
        self.alice = User.generate("alice-user")
        self.bob = User.generate("bob-user")
        
        self.manager = AccessManager(authorized_admin_pems=[self.admin.public_key_pem])
        self.manager.initialize_chain(self.admin.private_key_pem, self.admin.public_key_pem)

    def test_grant_and_verify_access_flow(self):
        path = "keys/database_password"
        raw_symmetric_key = b"extremely_secure_key_bytes_1289"

        # 1. Admin grants access to Alice
        self.manager.grant_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.alice.user_id,
            user_public_key_pem=self.alice.public_key_pem,
            path=path,
            permission_type="read",
            file_key=raw_symmetric_key
        )

        # 2. Alice requests access proof
        leaf, proof, latest_root = self.manager.get_access_proof(self.alice.user_id, path)
        
        # 3. Alice verifies proof and decrypts the symmetric file key
        decrypted_key = AccessManager.verify_and_decrypt_key(
            user_private_key_bytes=self.alice.private_key_pem.encode('utf-8'),
            leaf=leaf,
            proof=proof,
            latest_merkle_root=latest_root
        )
        
        self.assertEqual(decrypted_key, raw_symmetric_key)

    def test_unauthorized_user_rejection(self):
        path = "keys/confidential_file"
        raw_symmetric_key = b"secret_key"

        # Admin grants access to Alice
        self.manager.grant_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.alice.user_id,
            user_public_key_pem=self.alice.public_key_pem,
            path=path,
            permission_type="read",
            file_key=raw_symmetric_key
        )

        # Bob attempts to fetch proof for this path -> should fail because Bob has no permission leaf
        with self.assertRaises(ValueError):
            self.manager.get_access_proof(self.bob.user_id, path)

    def test_revocation_flow(self):
        path = "keys/top_secret"
        raw_symmetric_key = b"top_secret_key"

        # 1. Admin grants access to Alice
        self.manager.grant_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.alice.user_id,
            user_public_key_pem=self.alice.public_key_pem,
            path=path,
            permission_type="read",
            file_key=raw_symmetric_key
        )

        # Alice has access
        leaf, proof, root_before = self.manager.get_access_proof(self.alice.user_id, path)
        self.assertTrue(verify_proof(leaf, proof, root_before))

        # 2. Admin revokes Alice's access
        self.manager.revoke_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.alice.user_id,
            path=path
        )

        # 3. Alice requests access proof again -> should raise ValueError (not found)
        with self.assertRaises(ValueError):
            self.manager.get_access_proof(self.alice.user_id, path)

        # 4. If Alice attempts to use the old proof against the new root hash, it should fail
        latest_root = self.manager.blockchain.get_latest_block().merkle_root
        self.assertNotEqual(root_before, latest_root)
        
        # Verify the proof validation fails with new root hash
        self.assertFalse(verify_proof(leaf, proof, latest_root))

    def test_serialization_lifecycle(self):
        path1 = "docs/engineering"
        path2 = "docs/finance"
        key1 = b"eng_key"
        key2 = b"fin_key"

        # Add some permissions
        self.manager.grant_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.alice.user_id,
            user_public_key_pem=self.alice.public_key_pem,
            path=path1,
            permission_type="read",
            file_key=key1
        )
        self.manager.grant_access(
            admin_private_key_bytes=self.admin.private_key_pem,
            admin_public_key_pem=self.admin.public_key_pem,
            user_id=self.bob.user_id,
            user_public_key_pem=self.bob.public_key_pem,
            path=path2,
            permission_type="write",
            file_key=key2
        )

        # Serialize state
        serialized_json = self.manager.to_json()
        
        # Reconstruct state from JSON
        new_manager = AccessManager.from_json(serialized_json)
        
        # Verify blockchain is valid and intact
        self.assertTrue(new_manager.blockchain.validate_chain())
        self.assertEqual(len(new_manager.blockchain.chain), 3)  # Genesis + 2 grants
        
        # Alice requests access proof using new manager
        leaf, proof, latest_root = new_manager.get_access_proof(self.alice.user_id, path1)
        decrypted_key = AccessManager.verify_and_decrypt_key(
            user_private_key_bytes=self.alice.private_key_pem.encode('utf-8'),
            leaf=leaf,
            proof=proof,
            latest_merkle_root=latest_root
        )
        self.assertEqual(decrypted_key, key1)


if __name__ == "__main__":
    unittest.main()
