import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path so we can import WinVaultKey
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from WinVaultKey import (
    create_vault_key,
    get_vault_key,
    delete_vault_key,
    VaultKeyError,
    KeyNotFoundError,
    AccessDeniedError,
    AuthenticationError
)
from WinVaultKey.vault import _get_current_user_normalized, _usernames_match


class TestWinVaultKeyIntegration(unittest.TestCase):
    """
    Integration tests running against the actual Windows Vault for the current user.
    """
    def setUp(self):
        self.test_key_name = "integration_test_temp_key"
        self.test_key_value = "extremely_secret_token_123!"

    def tearDown(self):
        # Ensure cleanup after tests
        try:
            delete_vault_key(self.test_key_name)
        except KeyNotFoundError:
            pass

    def test_lifecycle_create_get_delete(self):
        # 1. Create a key in the Windows Vault
        create_vault_key(self.test_key_name, self.test_key_value)
        
        # 2. Retrieve the key again
        retrieved_value = get_vault_key(self.test_key_name)
        self.assertEqual(retrieved_value, self.test_key_value)
        
        # 3. Delete the key
        delete_vault_key(self.test_key_name)
        
        # 4. Try fetching again -> should raise KeyNotFoundError
        with self.assertRaises(KeyNotFoundError):
            get_vault_key(self.test_key_name)

    def test_delete_non_existent_key_raises_error(self):
        with self.assertRaises(KeyNotFoundError):
            delete_vault_key("some_completely_random_key_name_that_does_not_exist")


class TestWinVaultKeyAccessControl(unittest.TestCase):
    """
    Unit tests mocking Win32 APIs to verify credential validation and access control logic.
    """
    
    @patch('WinVaultKey.vault.win32cred.CredRead')
    def test_get_vault_key_access_denied_due_to_creator_mismatch(self, mock_cred_read):
        # Mock key creator as "domain\\other_user", while current user is something else
        mock_cred_read.return_value = {
            'UserName': 'domain\\other_user',
            'CredentialBlob': b'm\x00y\x00_\x00s\x00e\x00c\x00r\x00e\x00t\x00' # 'my_secret' in UTF-16LE
        }
        
        with patch('WinVaultKey.vault._get_current_user_normalized', return_value='domain\\current_user'):
            with self.assertRaises(AccessDeniedError):
                get_vault_key("test_key")

    @patch('WinVaultKey.vault.win32security.LogonUser')
    @patch('WinVaultKey.vault.win32security.ImpersonateLoggedOnUser')
    @patch('WinVaultKey.vault.win32security.RevertToSelf')
    @patch('WinVaultKey.vault.win32cred.CredRead')
    def test_get_vault_key_with_valid_explicit_credentials(
        self, mock_cred_read, mock_revert, mock_impersonate, mock_logon
    ):
        # Mock logon returning a token object
        mock_token = MagicMock()
        mock_logon.return_value = mock_token
        
        # Mock reading key under impersonated context
        mock_cred_read.return_value = {
            'UserName': 'domain\\creator_user',
            'CredentialBlob': 'secret_value'.encode('utf-16-le')
        }
        
        # Retrieve key with valid credentials matching the creator
        val = get_vault_key("test_key", username="domain\\creator_user", password="valid_password")
        
        self.assertEqual(val, "secret_value")
        mock_logon.assert_called_once_with(
            "creator_user", "domain", "valid_password", 2, 0 # LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT
        )
        mock_impersonate.assert_called_once_with(mock_token)
        mock_revert.assert_called_once()
        mock_token.Close.assert_called_once()

    @patch('WinVaultKey.vault.win32security.LogonUser')
    def test_get_vault_key_invalid_explicit_credentials_raises_error(self, mock_logon):
        import pywintypes
        # Mock LogonUser raising a logon failure
        mock_logon.side_effect = pywintypes.error(1326, 'LogonUser', 'Logon failure: unknown user name or bad password.')
        
        with self.assertRaises(AuthenticationError):
            get_vault_key("test_key", username="domain\\user", password="wrong_password")

    @patch('WinVaultKey.vault.win32security.LogonUser')
    @patch('WinVaultKey.vault.win32security.ImpersonateLoggedOnUser')
    @patch('WinVaultKey.vault.win32security.RevertToSelf')
    @patch('WinVaultKey.vault.win32cred.CredRead')
    def test_get_vault_key_explicit_credentials_user_mismatch_raises_error(
        self, mock_cred_read, mock_revert, mock_impersonate, mock_logon
    ):
        mock_token = MagicMock()
        mock_logon.return_value = mock_token
        
        # Key creator is 'domain\\actual_creator'
        mock_cred_read.return_value = {
            'UserName': 'domain\\actual_creator',
            'CredentialBlob': 'secret_value'.encode('utf-16-le')
        }
        
        # Authenticated as 'domain\\imposter', trying to read the key
        with self.assertRaises(AccessDeniedError):
            get_vault_key("test_key", username="domain\\imposter", password="valid_password")

    @patch('WinVaultKey.vault.input')
    @patch('WinVaultKey.vault.getpass.getpass')
    @patch('WinVaultKey.vault.win32security.LogonUser')
    @patch('WinVaultKey.vault.win32security.ImpersonateLoggedOnUser')
    @patch('WinVaultKey.vault.win32security.RevertToSelf')
    @patch('WinVaultKey.vault.win32cred.CredRead')
    def test_get_vault_key_interactive_prompt_on_fail(
        self, mock_cred_read, mock_revert, mock_impersonate, mock_logon, mock_getpass, mock_input
    ):
        import pywintypes
        
        # 1. First attempt to read under current context raises ERROR_NOT_FOUND (1168)
        mock_cred_read.side_effect = [
            pywintypes.error(1168, 'CredRead', 'Element not found.'),  # first call (current user)
            {
                'UserName': 'domain\\creator_user',
                'CredentialBlob': 'secret_value'.encode('utf-16-le')
            }  # second call (impersonated user)
        ]
        
        # Mock interactive inputs
        mock_input.return_value = "domain\\creator_user"
        mock_getpass.return_value = "prompted_password"
        
        mock_token = MagicMock()
        mock_logon.return_value = mock_token
        
        # Retrieve key with prompt_on_fail=True
        val = get_vault_key("test_key", prompt_on_fail=True)
        
        self.assertEqual(val, "secret_value")
        mock_input.assert_called_once()
        mock_getpass.assert_called_once()
        mock_logon.assert_called_once_with(
            "creator_user", "domain", "prompted_password", 2, 0
        )
        mock_impersonate.assert_called_once_with(mock_token)
        mock_revert.assert_called_once()


class TestUsernameMatching(unittest.TestCase):
    """
    Test cases for username matching helper logic.
    """
    def test_normalization_and_comparison(self):
        self.assertTrue(_usernames_match("domain\\user", "domain/user"))
        self.assertTrue(_usernames_match("domain\\user", "domain\\user"))
        self.assertTrue(_usernames_match("domain\\USER", "domain\\user"))
        self.assertTrue(_usernames_match(".\\user", "user"))
        self.assertTrue(_usernames_match("domain\\user", "user"))
        self.assertTrue(_usernames_match("user", "domain\\user"))
        self.assertFalse(_usernames_match("domain1\\user", "domain2\\user"))
        self.assertFalse(_usernames_match("domain\\user1", "domain\\user2"))


if __name__ == "__main__":
    unittest.main()
