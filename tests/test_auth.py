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


if __name__ == "__main__":
    unittest.main()
