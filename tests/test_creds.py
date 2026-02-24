import os
import sys
import shutil
import unittest
from bitarray import bitarray as ba

# Add root to path so we can import OpSec
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from OpSec.Creds import Creds

class TestCreds(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_vault"
        self.creds = Creds(storage_dir=self.test_dir)
        self.username = "testuser"
        self.password = "P@ssw0rd123!"
        self.key = os.urandom(32)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_save_load_bytes_key(self):
        self.creds.save_creds(self.username, self.password, self.key)
        loaded_pass = self.creds.load_creds(self.username, self.key)
        self.assertEqual(self.password, loaded_pass)

    def test_save_load_bitarray_key(self):
        bit_key = ba()
        bit_key.frombytes(self.key)
        self.creds.save_creds(self.username, self.password, bit_key)
        loaded_pass = self.creds.load_creds(self.username, bit_key)
        self.assertEqual(self.password, loaded_pass)

    def test_wrong_key_fails(self):
        self.creds.save_creds(self.username, self.password, self.key)
        wrong_key = os.urandom(32)
        loaded_pass = self.creds.load_creds(self.username, wrong_key)
        self.assertIsNone(loaded_pass)

    def test_ps_credential_command(self):
        self.creds.save_creds(self.username, self.password, self.key)
        cmd = self.creds.get_ps_credential_command(self.username, self.key)
        self.assertIn(f"PSCredential('{self.username}'", cmd)
        self.assertIn(f"'{self.password}'", cmd)

if __name__ == '__main__':
    unittest.main()
