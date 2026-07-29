import sys
import os
import ctypes
from ctypes import wintypes
from typing import Optional, Dict, List

# Ensure this script runs on Windows
if sys.platform != 'win32':
    raise RuntimeError("This Windows Credential Vault script can only be executed on Windows systems.")

        
class FILETIME(ctypes.Structure):
    """Windows FILETIME structure for timestamp tracking."""
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]

class CREDENTIAL(ctypes.Structure):
    """Windows CREDENTIALW structure mapping Advapi32 credential memory layout."""
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]

# Win32 Constants for Windows Credential Vault
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
ERROR_NOT_FOUND = 1168

# Load Advapi32 DLL
advapi32 = ctypes.windll.advapi32

# Define argument and return types for CredWriteW
advapi32.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
advapi32.CredWriteW.restype = wintypes.BOOL

# Define argument and return types for CredReadW
advapi32.CredReadW.argtypes = [
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.POINTER(CREDENTIAL))
]
advapi32.CredReadW.restype = wintypes.BOOL

# Define argument and return types for CredDeleteW
advapi32.CredDeleteW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
advapi32.CredDeleteW.restype = wintypes.BOOL

# Define argument and return types for CredEnumerateW
advapi32.CredEnumerateW.argtypes = [
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(CREDENTIAL)))
]
advapi32.CredEnumerateW.restype = wintypes.BOOL

# Define argument and return types for CredFree
advapi32.CredFree.argtypes = [ctypes.c_void_p]
advapi32.CredFree.restype = None

class WindowsVault:
    """
    A Python wrapper around the Windows Credential Manager (Advapi32 API).
    Provides methods to save, retrieve, list, and delete generic user credentials.
    """
    
    @staticmethod
    def get_current_domain_and_user():
        # 1. Get the handle to the current process
        process = win32api.GetCurrentProcess()
        
        # 2. Open the access token associated with the process
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        
        # 3. Get the User SID (Security Identifier) from the token
        user_sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
        
        # 4. Look up the account name using the SID
        # This natively returns a tuple of (Username, Domain, AccountType)
        username, domain, account_type = win32security.LookupAccountSid(None, user_sid)
        
        return f'{domain}/{username}'

    @staticmethod
    def store_credential(target: str, username: str, secret: str, comment: str = "Managed via Python") -> bool:
        """
        Stores or updates a credential in the Windows Credential Manager.

        :param target: Identifier name for the credential (e.g. 'MyApp_Database_Login')
        :param username: Username or account name associated with the credential
        :param secret: Password or secret key string to store securely
        :param comment: Optional comment stored alongside the credential
        :return: True if successful
        """
        secret_bytes = secret.encode('utf-8')
        blob_size = len(secret_bytes)
        blob_buffer = (ctypes.c_byte * blob_size)(*secret_bytes)

        cred = CREDENTIAL()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.Comment = comment
        cred.CredentialBlobSize = blob_size
        cred.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(ctypes.c_byte))
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.TargetAlias = None
        cred.UserName = username

        success = advapi32.CredWriteW(ctypes.byref(cred), 0)
        if not success:
            err = ctypes.GetLastError()
            raise OSError(err, f"Failed to save credential '{target}'. Windows Error Code: {err}")

        return True

    @staticmethod
    def get_credential(target: str) -> Optional[Dict[str, str]]:
        """
        Retrieves a credential from the Windows Credential Manager.

        :param target: Target identifier name
        :return: Dictionary containing 'target', 'username', and 'secret', or None if not found.
        """
        p_cred = ctypes.POINTER(CREDENTIAL)()
        success = advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(p_cred))

        if not success:
            err = ctypes.GetLastError()
            if err == ERROR_NOT_FOUND:
                return None
            raise OSError(err, f"Failed to retrieve credential '{target}'. Windows Error Code: {err}")

        try:
            cred_data = p_cred.contents

            # Extract credential blob secret bytes
            if cred_data.CredentialBlob and cred_data.CredentialBlobSize > 0:
                raw_bytes = ctypes.string_at(cred_data.CredentialBlob, cred_data.CredentialBlobSize)
                secret = raw_bytes.decode('utf-8', errors='replace')
            else:
                secret = ""

            return {
                "target": cred_data.TargetName or target,
                "username": cred_data.UserName or "",
                "secret": secret,
                "comment": cred_data.Comment or ""
            }
        finally:
            advapi32.CredFree(p_cred)

    @staticmethod
    def delete_credential(target: str) -> bool:
        """
        Deletes a credential from the Windows Credential Manager.

        :param target: Target identifier name to delete
        :return: True if successfully deleted, False if target was not found.
        """
        success = advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0)
        if not success:
            err = ctypes.GetLastError()
            if err == ERROR_NOT_FOUND:
                return False
            raise OSError(err, f"Failed to delete credential '{target}'. Windows Error Code: {err}")
        return True

    @staticmethod
    def list_credentials(filter_pattern: str = "*") -> List[Dict[str, str]]:
        """
        Lists stored credentials matching a filter pattern.

        :param filter_pattern: Search filter pattern (e.g. '*' or 'MyApp_*')
        :return: List of dictionaries containing credential details (excluding secrets for security).
        """
        count = wintypes.DWORD()
        p_p_creds = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()

        success = advapi32.CredEnumerateW(filter_pattern, 0, ctypes.byref(count), ctypes.byref(p_p_creds))
        if not success:
            err = ctypes.GetLastError()
            if err == ERROR_NOT_FOUND:
                return []
            raise OSError(err, f"Failed to list credentials. Windows Error Code: {err}")

        credentials_list = []
        try:
            for i in range(count.value):
                cred_ptr = p_p_creds[i]
                if cred_ptr:
                    cred = cred_ptr.contents
                    credentials_list.append({
                        "target": cred.TargetName or "",
                        "username": cred.UserName or "",
                        "comment": cred.Comment or ""
                    })
        finally:
            advapi32.CredFree(p_p_creds)

        return credentials_list

