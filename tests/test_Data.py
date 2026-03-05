import os
import shutil
import unittest
from pathlib import Path
import sys

# Ensure project root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from OpSec.Data import Data

class TestDataArchive(unittest.TestCase):
    def setUp(self):
        self.archive_name = "test_archive.bin"
        self.archive_path = Path("test_data_dir")
        self.archive_path.mkdir(exist_ok=True)
        self.full_path = self.archive_path / self.archive_name
        
        if self.full_path.exists():
            os.remove(self.full_path)
            
        self.data_store = Data(
            archive_name=self.archive_name,
            archive_path=self.archive_path,
            n_slots=10,
            slot_size=64,
            n_users=5,
            name_length=16
        )

    def tearDown(self):
        if self.full_path.exists():
            os.remove(self.full_path)
        if self.archive_path.exists():
            shutil.rmtree(self.archive_path)

    def test_initialization(self):
        self.assertTrue(self.full_path.exists())
        
        # Check sizes
        # n_slots = 10 -> min 9, needs 4 bits -> 1 byte
        # n_users = 5 -> min 4, needs 3 bits. perm = 3 flags + 3 bits = 6 bits -> 1 byte
        # index_entry = 1 (id) + 16 (name) + 1 (type) + 4 * 1 (perms) = 22 bytes
        # index_block = 10 * 22 = 220 bytes
        # data_block = 10 * 64 = 640 bytes
        # total_size = 860 bytes
        
        self.assertEqual(self.data_store.id_bytes, 1)
        self.assertEqual(self.data_store.perm_bytes, 1)
        self.assertEqual(self.data_store.index_entry_size, 22)
        
        expected_size = 220 + 640
        self.assertEqual(os.path.getsize(self.full_path), expected_size)
        
    def test_write_read_delete(self):
        filename = "test.txt"
        content = b"Hello World! 123"
        
        self.data_store.write_file(filename, content)
        
        read_content = self.data_store.read_file(filename)
        self.assertIsNotNone(read_content)
        
        # The content should be padded to 64 bytes
        self.assertEqual(read_content[:len(content)], content)
        self.assertEqual(read_content[len(content):], b'\x00' * (64 - len(content)))
        
        self.assertIn(filename, self.data_store.list_files())
        
        # Update existing
        new_content = b"Updated Content!"
        self.data_store.write_file(filename, new_content)
        read_content = self.data_store.read_file(filename)
        self.assertEqual(read_content[:len(new_content)], new_content)
        
        # Delete
        self.data_store.delete_file(filename)
        self.assertNotIn(filename, self.data_store.list_files())
        self.assertIsNone(self.data_store.read_file(filename))

    def test_permissions(self):
        filename = "perm_test"
        # user_id 3, flags 101 (read and set_perm)
        # user_id << 3 | flags -> 3 << 3 | 5 = 24 | 5 = 29
        owner_perm = 29
        self.data_store.write_file(filename, b"test", perms=[owner_perm, 0, 0, 0])
        
        perms = self.data_store.get_user_permissions(filename, 3)
        self.assertIsNotNone(perms)
        self.assertTrue(perms['read'])
        self.assertFalse(perms['write'])
        self.assertTrue(perms['set_perm'])
        
        # Any other user should have 0/False
        perms2 = self.data_store.get_user_permissions(filename, 4)
        self.assertFalse(perms2['read'])
        self.assertFalse(perms2['write'])
        self.assertFalse(perms2['set_perm'])

if __name__ == "__main__":
    unittest.main()
