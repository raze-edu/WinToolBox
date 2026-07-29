import win32api
import win32security
import win32con
import win32cred
import pywintypes
import getpass
from typing import Optional

class VaultKeyError(Exception):
    """Base exception for WinVaultKey errors."""
    pass

class KeyNotFoundError(VaultKeyError):
    """Raised when the specified key is not found in the vault."""
    pass

class AccessDeniedError(VaultKeyError):
    """Raised when access to the key is denied."""
    pass

class AuthenticationError(VaultKeyError):
    """Raised when authentication fails."""
    pass


def _get_target_name(name: str) -> str:
    """Returns the formatted target name for the Windows Vault credential."""
    return f"WinVaultKey:{name}"


def _get_current_user_normalized() -> str:
    """Gets the current logged-in user in DOMAIN\\Username format."""
    process = win32api.GetCurrentProcess()
    token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
    user_sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
    username, domain, account_type = win32security.LookupAccountSid(None, user_sid)
    return f"{domain}\\{username}".lower()


def _usernames_match(u1: str, u2: str) -> bool:
    """Compares two usernames case-insensitively, handling domains and dot defaults."""
    u1_norm = u1.replace('/', '\\').lower()
    u2_norm = u2.replace('/', '\\').lower()
    
    if u1_norm == u2_norm:
        return True
        
    p1 = u1_norm.split('\\')
    p2 = u2_norm.split('\\')
    
    if len(p1) == 2 and len(p2) == 2:
        d1, user1 = p1
        d2, user2 = p2
        if user1 != user2:
            return False
        if d1 in ('.', '') or d2 in ('.', ''):
            return True
        return d1 == d2
    
    user1 = p1[-1]
    user2 = p2[-1]
    return user1 == user2


def _authenticate_and_read_credential(
    name: str, 
    username: str, 
    password: str
) -> dict:
    """
    Authenticates a user via LogonUser, impersonates them, and attempts to read
    the credential from their Vault.
    """
    # Normalize username format for LogonUser
    username_norm = username.replace('/', '\\')
    if '\\' in username_norm:
        domain, user = username_norm.split('\\', 1)
    else:
        domain = '.'
        user = username_norm

    try:
        token = win32security.LogonUser(
            user,
            domain,
            password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT
        )
    except pywintypes.error as e:
        raise AuthenticationError(f"Authentication failed: {e.strerror}") from e

    try:
        # Impersonate the authenticated user
        win32security.ImpersonateLoggedOnUser(token)
        try:
            target_name = _get_target_name(name)
            cred = win32cred.CredRead(target_name, win32cred.CRED_TYPE_GENERIC)
            return cred
        except pywintypes.error as e:
            if e.winerror == 1168: # ERROR_NOT_FOUND
                raise KeyNotFoundError(f"Key '{name}' not found in the vault of user '{username}'.") from e
            raise VaultKeyError(f"Failed to read key from vault: {e.strerror}") from e
        finally:
            win32security.RevertToSelf()
    finally:
        token.Close()


def create_vault_key(name: str, value: str) -> None:
    """
    Creates or updates a key in the Windows Vault.
    The credential is encrypted and saved under the current user's profile.
    
    Args:
        name: The name identifier of the key.
        value: The string value of the key to store.
    """
    current_user = _get_current_user_normalized()
    target_name = _get_target_name(name)
    
    cred_dict = {
        'Type': win32cred.CRED_TYPE_GENERIC,
        'TargetName': target_name,
        'UserName': current_user,
        'CredentialBlob': value,
        'Persist': win32cred.CRED_PERSIST_LOCAL_MACHINE
    }
    
    try:
        win32cred.CredWrite(cred_dict)
    except pywintypes.error as e:
        raise VaultKeyError(f"Failed to create key in Windows Vault: {e.strerror}") from e


def delete_vault_key(name: str) -> None:
    """
    Deletes the key from the current user's Windows Vault.
    
    Args:
        name: The name identifier of the key to delete.
    """
    target_name = _get_target_name(name)
    try:
        win32cred.CredDelete(target_name, win32cred.CRED_TYPE_GENERIC)
    except pywintypes.error as e:
        if e.winerror == 1168: # ERROR_NOT_FOUND
            raise KeyNotFoundError(f"Key '{name}' not found in the vault.") from e
        raise VaultKeyError(f"Failed to delete key: {e.strerror}") from e


def get_vault_key(
    name: str, 
    username: Optional[str] = None, 
    password: Optional[str] = None, 
    prompt_on_fail: bool = False
) -> str:
    """
    Retrieves the key from the Windows Vault.
    
    Checks:
    - If credentials (username/password) are passed: Authenticate using Windows LogonUser
      and fetch the key from that user's vault.
    - If credentials are not passed: Attempt to fetch the key from the current user's vault.
      If it fails and prompt_on_fail is True, prompt the user for credentials in the console.
    
    Args:
        name: The name identifier of the key.
        username: Optional Windows username (Domain\\Username) to verify.
        password: Optional Windows password.
        prompt_on_fail: If True, prompt for credentials on the console if retrieval fails.
        
    Returns:
        The decrypted string key value.
        
    Raises:
        KeyNotFoundError: If the key does not exist.
        AccessDeniedError: If the user is not authorized.
        AuthenticationError: If credential verification fails.
    """
    target_name = _get_target_name(name)
    
    # Case A: Credentials are provided programmatically
    if username is not None and password is not None:
        cred = _authenticate_and_read_credential(name, username, password)
        creator = cred.get('UserName', '')
        if not _usernames_match(creator, username):
            raise AccessDeniedError(
                f"Access denied: Key was created by '{creator}', but authenticated as '{username}'."
            )
        blob = cred['CredentialBlob']
        return blob.decode('utf-16-le')

    # Case B: Try reading under the current user context
    try:
        cred = win32cred.CredRead(target_name, win32cred.CRED_TYPE_GENERIC)
        creator = cred.get('UserName', '')
        current_user = _get_current_user_normalized()
        
        if _usernames_match(creator, current_user):
            blob = cred['CredentialBlob']
            return blob.decode('utf-16-le')
        else:
            raise AccessDeniedError(
                f"Access denied: Key was created by '{creator}', but current user is '{current_user}'."
            )
            
    except pywintypes.error as e:
        # Key not found in current user's vault
        if e.winerror == 1168: # ERROR_NOT_FOUND
            if not prompt_on_fail:
                raise KeyNotFoundError(f"Key '{name}' not found in the current user's vault.") from e
        else:
            raise VaultKeyError(f"Failed to read key: {e.strerror}") from e

    # Case C: Prompt on fail is requested and retrieval has failed/denied
    if prompt_on_fail:
        print(f"\n--- Windows Vault Verification Required for Key '{name}' ---")
        prompted_username = input("Username (Domain\\User or User): ").strip()
        prompted_password = getpass.getpass("Password: ")
        
        if not prompted_username or not prompted_password:
            raise AuthenticationError("Credentials cannot be empty.")
            
        cred = _authenticate_and_read_credential(name, prompted_username, prompted_password)
        creator = cred.get('UserName', '')
        if not _usernames_match(creator, prompted_username):
            raise AccessDeniedError(
                f"Access denied: Key was created by '{creator}', but authenticated as '{prompted_username}'."
            )
        blob = cred['CredentialBlob']
        return blob.decode('utf-16-le')
        
    raise KeyNotFoundError(f"Key '{name}' not found.")
