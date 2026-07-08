import os
import ctypes
import base64
import hashlib
import getpass
import secrets
from ctypes import wintypes
from cryptography.fernet import Fernet

# Default path for the key file
KEY_PATH = os.path.join(os.path.dirname(__file__), "key.bin")

if os.name == 'nt':
    # DPAPI definitions
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char))
        ]

    kernel32 = ctypes.windll.kernel32
    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [wintypes.HLOCAL]
    LocalFree.restype = wintypes.HLOCAL

    crypt32 = ctypes.windll.crypt32
    CryptProtectData = crypt32.CryptProtectData
    CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),  # pDataIn
        wintypes.LPCWSTR,          # szDataDescr
        ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,           # pvReserved
        ctypes.c_void_p,           # pPromptStruct
        wintypes.DWORD,            # dwFlags
        ctypes.POINTER(DATA_BLOB)   # pDataOut
    ]
    CryptProtectData.restype = wintypes.BOOL

    CryptUnprotectData = crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),  # pDataIn
        ctypes.POINTER(wintypes.LPWSTR), # ppszDataDescr
        ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,           # pvReserved
        ctypes.c_void_p,           # pPromptStruct
        wintypes.DWORD,            # dwFlags
        ctypes.POINTER(DATA_BLOB)   # pDataOut
    ]
    CryptUnprotectData.restype = wintypes.BOOL

_session_key = None

class EncryptionManager:
    @staticmethod
    def encrypt_dpapi(data: bytes, desc: str = "ADAdmin Credentials") -> bytes:
        """
        Encrypts a byte array using Windows Data Protection API (DPAPI).
        """
        if os.name != 'nt':
            # Mock/fallback for non-Windows environments (like testing)
            return b"MOCK_ENC:" + base64.b64encode(data)

        data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        data_out = DATA_BLOB()
        
        # Flag 1: CRYPTPROTECT_UI_FORBIDDEN (no UI prompt)
        if not CryptProtectData(ctypes.byref(data_in), desc, None, None, None, 1, ctypes.byref(data_out)):
            raise OSError("CryptProtectData failed with error code: " + str(ctypes.GetLastError()))
        
        try:
            return ctypes.string_at(data_out.pbData, data_out.cbData)
        finally:
            LocalFree(data_out.pbData)

    @staticmethod
    def decrypt_dpapi(data: bytes) -> bytes:
        """
        Decrypts a byte array using Windows Data Protection API (DPAPI).
        """
        if os.name != 'nt':
            # Mock/fallback for non-Windows environments (like testing)
            if data.startswith(b"MOCK_ENC:"):
                return base64.b64decode(data[9:])
            raise OSError("DPAPI is only supported natively on Windows NT systems.")

        data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        data_out = DATA_BLOB()
        
        # Flag 1: CRYPTPROTECT_UI_FORBIDDEN (no UI prompt)
        if not CryptUnprotectData(ctypes.byref(data_in), None, None, None, None, 1, ctypes.byref(data_out)):
            raise OSError("CryptUnprotectData failed with error code: " + str(ctypes.GetLastError()))
        
        try:
            return ctypes.string_at(data_out.pbData, data_out.cbData)
        finally:
            LocalFree(data_out.pbData)

    @staticmethod
    def generate_safe_password(length: int = 32) -> str:
        """
        Generates a cryptographically secure random modhex password.
        Modhex characters (cbdefghijklnrtuv) are 100% safe across all keyboard layouts
        because they map to the same physical keys on standard keyboards worldwide.
        """
        alphabet = "cbdefghijklnrtuv"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def derive_fernet_key(password_str: str) -> bytes:
        """
        Derives a valid Fernet key (32 URL-safe base64-encoded bytes) from any string
        using SHA-256.
        """
        h = hashlib.sha256(password_str.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(h)

    @staticmethod
    def get_encryption_key() -> bytes:
        """
        Retrieves the plain text Fernet encryption/decryption key.
        - If a cached _session_key exists, return it.
        - If key.bin exists (TOTP flow), load it, decrypt via DPAPI, cache it, and return it.
        - If key.bin does not exist (Yubikey flow), prompt the user to tap/input the key,
          cache it, and return it.
        """
        global _session_key
        if _session_key is not None:
            return _session_key

        if os.path.exists(KEY_PATH):
            try:
                with open(KEY_PATH, "rb") as f:
                    encrypted_key = f.read().strip()
                _session_key = EncryptionManager.decrypt_dpapi(encrypted_key)
                return _session_key
            except Exception as e:
                raise RuntimeError(f"Failed to decrypt key file 'key.bin' via DPAPI: {e}")
        else:
            print("\n==================================================")
            print("      Master Yubikey Decryption Key Required     ")
            print("==================================================")
            print("Press and HOLD (long-press for 3-4 seconds) your master YubiKey to input the decryption key.")
            key_input = getpass.getpass("Long-press YubiKey (Slot 2): ").strip()
            if not key_input:
                raise ValueError("Decryption key cannot be empty.")
            _session_key = EncryptionManager.derive_fernet_key(key_input)
            return _session_key

    @staticmethod
    def encrypt_config(raw_data: bytes, key: bytes = None) -> bytes:
        """
        Encrypts a byte array using Fernet symmetric encryption and the provided or retrieved key.
        """
        if key is None:
            key = EncryptionManager.get_encryption_key()
        fernet = Fernet(key)
        return fernet.encrypt(raw_data)

    @staticmethod
    def decrypt_config(encrypted_data: bytes, key: bytes = None) -> bytes:
        """
        Decrypts a byte array using Fernet symmetric encryption and the provided or retrieved key.
        """
        if key is None:
            key = EncryptionManager.get_encryption_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
