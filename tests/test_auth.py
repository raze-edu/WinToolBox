import os
import unittest
import base64
import time
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ADAdmin.Auth.auth import (
    encrypt_dpapi,
    decrypt_dpapi,
    get_totp_code,
    verify_totp,
    verify_yubikey_otp,
    ADAuthSession
)

class TestAuth(unittest.TestCase):
    def test_dpapi_roundtrip(self):
        """Test encryption and decryption roundtrip using DPAPI."""
        original = b"SuperSecretPassword123!"
        encrypted = encrypt_dpapi(original)
        self.assertNotEqual(original, encrypted)
        
        decrypted = decrypt_dpapi(encrypted)
        self.assertEqual(original, decrypted)

    def test_totp_calculation(self):
        """Test standard TOTP generation and validation."""
        # Simple test secret (Base32 encoded '12345678901234567890')
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        
        # Test code at specific timestamp
        t = 1234567890.0
        code = get_totp_code(secret, time_val=t)
        
        # Verification code should be a 6-digit string
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        
        # Verify valid TOTP window validation
        # The correct code at that precise time (t=1234567890) is verified
        self.assertEqual(code, "005924")

    def test_verify_totp_window(self):
        """Test TOTP validation with drift window."""
        secret = "MJKW243VMV2G6Z3B"
        code = get_totp_code(secret)
        
        # Matches current time
        self.assertTrue(verify_totp(secret, code))
        
        # Matches slightly shifted code
        self.assertFalse(verify_totp(secret, "000000"))

    def test_verify_yubikey_otp_format(self):
        """Test local parsing and validation of Yubikey OTP Modhex formats."""
        # A valid modhex format OTP (44 chars, starting with public ID)
        valid_otp = "cccgjgvcddhhrglljvetcdiikervcugigchffkhkcdli"
        public_id = "cccgjgvcddhh"
        
        # Invalid length
        self.assertFalse(verify_yubikey_otp("cccgjgvcddhh", public_id))
        
        # Invalid characters (not modhex)
        non_modhex_otp = "cccgjgvcddhhrglljvetcdiikervcugigchffkhkcdlx" # has x
        self.assertFalse(verify_yubikey_otp(non_modhex_otp, public_id))
        
        # Public ID mismatch
        self.assertFalse(verify_yubikey_otp(valid_otp, "differentid1"))

    def test_ad_auth_session(self):
        """Test ADAuthSession available users and validation bounds."""
        mock_credentials = {
            "admin-beck": {
                "username": "admin-beck",
                "domain": "wjwgmbh.local",
                "password": "SuperSecurePassword1!",
                "mfa_type": "totp",
                "mfa_secret": "2AIHZ75LUVKRWF5P"
            },
            "svc-backup": {
                "username": "svc-backup",
                "domain": "wjwgmbh.local",
                "password": "BackupPassword123!",
                "mfa_type": "yubikey",
                "mfa_secret": "cccgjgvcddhh"
            }
        }
        
        session = ADAuthSession(mock_credentials)
        users = session.get_available_users()
        
        self.assertEqual(len(users), 2)
        self.assertIn("admin-beck", users)
        self.assertIn("svc-backup", users)
        
        # Verify KeyError for non-existent users
        with self.assertRaises(KeyError):
            session.run_as("nonexistent", "cmd")


class TestIndependentEncryption(unittest.TestCase):
    def setUp(self):
        # Backup original paths
        import ADAdmin.Auth.auth as auth
        self.original_key_path = auth.KEY_PATH
        self.original_config_path = auth.CONFIG_PATH
        
        # Use temporary files in tests folder
        self.test_dir = Path(__file__).resolve().parent
        auth.KEY_PATH = str(self.test_dir / "test_key_temp.bin")
        auth.CONFIG_PATH = str(self.test_dir / "test_config_temp.bin")
        
        self.auth = auth
        self.auth._session_key = None

    def tearDown(self):
        # Restore original paths
        self.auth.KEY_PATH = self.original_key_path
        self.auth.CONFIG_PATH = self.original_config_path
        self.auth._session_key = None
        
        # Clean up temporary files
        for p in [Path(self.test_dir / "test_key_temp.bin"), Path(self.test_dir / "test_config_temp.bin")]:
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    def test_init_creates_files(self):
        """Test that do_init creates key.bin and config.bin with master MFA correctly."""
        from unittest.mock import patch
        
        # Simulate do_init with TOTP option
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
            
        self.assertTrue(Path(self.auth.KEY_PATH).exists())
        self.assertTrue(Path(self.auth.CONFIG_PATH).exists())
        
        # Check that config.bin is initialized with correct keys
        config = self.auth.load_config()
        self.assertEqual(config["master_mfa_type"], "totp")
        self.assertTrue(len(config["master_mfa_secret"]) > 0)
        self.assertEqual(config["credentials"], {})

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip using key-file Fernet."""
        from unittest.mock import patch
        # Initialize
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
        
        raw_data = b"SomeSecretUserConfigData"
        encrypted = self.auth.encrypt_config(raw_data)
        self.assertNotEqual(raw_data, encrypted)
        
        decrypted = self.auth.decrypt_config(encrypted)
        self.assertEqual(raw_data, decrypted)

    def test_verify_master_auth_totp(self):
        """Test that verify_master_auth successfully verifies TOTP."""
        from unittest.mock import patch
        # Initialize
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
            
        # Verify master auth (correct code)
        with patch('builtins.input', return_value='123456'), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.assertTrue(self.auth.verify_master_auth())

        # Verify master auth (incorrect code)
        with patch('builtins.input', return_value='123456'), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=False), \
             patch('builtins.print'):
            self.assertFalse(self.auth.verify_master_auth())

    def test_save_and_load_config(self):
        """Test saving and loading user credentials under nested credentials store."""
        from unittest.mock import patch
        # Initialize
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
        
        # Save a credential
        self.auth.save_config("Alice", "DOMAIN", "P@ssword1")
        
        # Load and verify
        config = self.auth.load_config()
        self.assertIn("alice", config["credentials"])
        self.assertEqual(config["credentials"]["alice"]["username"], "Alice")
        self.assertEqual(config["credentials"]["alice"]["domain"], "DOMAIN")
        self.assertEqual(config["credentials"]["alice"]["password"], "P@ssword1")

    def test_remove_credential(self):
        """Test removing credentials using do_remove with master authentication."""
        from unittest.mock import patch
        # Initialize
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
        
        # Save two credentials
        self.auth.save_config("Alice", "DOMAIN", "P@ssword1")
        self.auth.save_config("Bob", "DOMAIN", "P@ssword2")
        
        config_before = self.auth.load_config()
        self.assertEqual(len(config_before["credentials"]), 2)
        
        # Remove Bob (mock master auth and confirmation inputs)
        with patch('builtins.input', side_effect=['000000', 'y']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_remove("Bob")
            
        config_after = self.auth.load_config()
        self.assertEqual(len(config_after["credentials"]), 1)
        self.assertIn("alice", config_after["credentials"])
        self.assertNotIn("bob", config_after["credentials"])

    def test_error_handling_when_no_init(self):
        """Test that load/save/remove raise correct errors when not initialized."""
        with self.assertRaises(FileNotFoundError):
            self.auth.load_config()
            
        with self.assertRaises(FileNotFoundError):
            self.auth.save_config("Alice", "DOMAIN", "P@ssword1")

    def test_dpapi_protected_key_bin(self):
        """Test that the TOTP flow encrypts key.bin using DPAPI."""
        from unittest.mock import patch
        
        # Initialize
        with patch('builtins.input', side_effect=['1', '000000']), \
             patch('ADAdmin.Auth.auth.verify_totp', return_value=True), \
             patch('builtins.print'):
            self.auth.do_init()
            
        self.assertTrue(Path(self.auth.KEY_PATH).exists())
        
        # Read the raw file content of key.bin
        with open(self.auth.KEY_PATH, "rb") as f:
            encrypted_key_content = f.read().strip()
            
        # Verify it is indeed encrypted and different from the decrypted session key
        decrypted_key = self.auth.get_encryption_key()
        self.assertNotEqual(encrypted_key_content, decrypted_key)
        
        # Verify that decrypt_dpapi reconstructs it
        self.assertEqual(self.auth.decrypt_dpapi(encrypted_key_content), decrypted_key)

    def test_yubikey_setup_no_key_bin(self):
        """Test that Yubikey flow generates key, prompts to verify, and does NOT write key.bin."""
        from unittest.mock import patch
        from cryptography.fernet import Fernet
        valid_key = Fernet.generate_key()
        valid_key_str = valid_key.decode('utf-8')
        
        with patch('builtins.input', return_value='2'), \
             patch('getpass.getpass', return_value=valid_key_str), \
             patch('cryptography.fernet.Fernet.generate_key', return_value=valid_key), \
             patch('builtins.print'):
            self.auth.do_init()
            
        # Verify key.bin is NOT written
        self.assertFalse(Path(self.auth.KEY_PATH).exists())
        self.assertTrue(Path(self.auth.CONFIG_PATH).exists())
        
        # Verify config contents
        self.auth._session_key = None
        
        with patch('getpass.getpass', return_value=valid_key_str):
            config = self.auth.load_config()
            self.assertEqual(config["master_mfa_type"], "yubikey")
            self.assertEqual(config["master_mfa_secret"], "hardware_key")

    def test_yubikey_verify_master_auth_implicit(self):
        """Test that verify_master_auth is implicit for Yubikey flow (decryption success)."""
        from unittest.mock import patch
        from cryptography.fernet import Fernet
        valid_key = Fernet.generate_key()
        valid_key_str = valid_key.decode('utf-8')
        
        # Set up a Yubikey config manually
        payload = {
            "master_mfa_type": "yubikey",
            "master_mfa_secret": "hardware_key",
            "credentials": {}
        }
        import json
        fernet = Fernet(valid_key)
        encrypted_data = fernet.encrypt(json.dumps(payload).encode('utf-8'))
        
        with open(self.auth.CONFIG_PATH, "wb") as f:
            f.write(encrypted_data)
            
        self.auth._session_key = None
        
        # Test verify_master_auth
        with patch('getpass.getpass', return_value=valid_key_str), \
             patch('builtins.print'):
            self.assertTrue(self.auth.verify_master_auth())

    def test_yubikey_session_caching(self):
        """Test that Yubikey decryption key is cached, preventing double prompts."""
        from unittest.mock import patch
        from cryptography.fernet import Fernet
        valid_key = Fernet.generate_key()
        valid_key_str = valid_key.decode('utf-8')
        
        payload = {
            "master_mfa_type": "yubikey",
            "master_mfa_secret": "hardware_key",
            "credentials": {}
        }
        import json
        fernet = Fernet(valid_key)
        encrypted_data = fernet.encrypt(json.dumps(payload).encode('utf-8'))
        
        with open(self.auth.CONFIG_PATH, "wb") as f:
            f.write(encrypted_data)
            
        self.auth._session_key = None
        
        # Accessing config the first time should prompt
        with patch('getpass.getpass', return_value=valid_key_str) as mock_getpass:
            config1 = self.auth.load_config()
            self.assertEqual(mock_getpass.call_count, 1)
            
        # Accessing config the second time should NOT prompt because of session caching
        with patch('getpass.getpass', side_effect=Exception("Should not be called!")) as mock_getpass_fail:
            config2 = self.auth.load_config()
            # Successfully loaded without prompt!


if __name__ == "__main__":
    unittest.main()
