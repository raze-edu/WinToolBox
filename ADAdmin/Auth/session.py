import os
import json
import ctypes
import getpass
from ctypes import wintypes
from .encryption import EncryptionManager
from .mfa import MFAHandler

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.bin")

if os.name == 'nt':
    # CreateProcessWithLogonW definitions
    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    advapi32 = ctypes.windll.advapi32
    CreateProcessWithLogonW = advapi32.CreateProcessWithLogonW
    CreateProcessWithLogonW.argtypes = [
        wintypes.LPCWSTR,             # lpUsername
        wintypes.LPCWSTR,             # lpDomain
        wintypes.LPCWSTR,             # lpPassword
        wintypes.DWORD,               # dwLogonFlags
        wintypes.LPCWSTR,             # lpApplicationName
        wintypes.LPWSTR,              # lpCommandLine
        wintypes.DWORD,               # dwCreationFlags
        ctypes.c_void_p,              # lpEnvironment
        wintypes.LPCWSTR,             # lpCurrentDirectory
        ctypes.POINTER(STARTUPINFOW),  # lpStartupInfo
        ctypes.POINTER(PROCESS_INFORMATION) # lpProcessInformation
    ]
    CreateProcessWithLogonW.restype = wintypes.BOOL
    kernel32 = ctypes.windll.kernel32

def run_process_as_user(username: str, domain: str, password: str, command: str) -> bool:
    """
    Launches a command under a specified user context in Windows.
    """
    if os.name != 'nt':
        print(f"\n[Mock Execution] Running: {command} as {domain or '.'}\\{username}")
        return True

    # Parse command or application name
    # We will invoke standard shells or executable paths
    startup_info = STARTUPINFOW()
    startup_info.cb = ctypes.sizeof(STARTUPINFOW)
    startup_info.dwFlags = 1  # STARTF_USESHOWWINDOW
    startup_info.wShowWindow = 1  # SW_SHOWNORMAL
    
    process_info = PROCESS_INFORMATION()
    
    # Unicode buffer is mutable
    cmd_buffer = ctypes.create_unicode_buffer(command)
    
    # dwLogonFlags: 1 = LOGON_WITH_PROFILE (loads user profile registry hive)
    # dwCreationFlags: 0x00000010 = CREATE_NEW_CONSOLE (launches command in a new command prompt window)
    success = CreateProcessWithLogonW(
        username,
        domain or ".",
        password,
        1,  # LOGON_WITH_PROFILE
        None,
        cmd_buffer,
        0x00000010,  # CREATE_NEW_CONSOLE
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(process_info)
    )
    
    if not success:
        error_code = ctypes.GetLastError()
        raise OSError(f"CreateProcessWithLogonW failed with error code: {error_code}")
        
    kernel32.CloseHandle(process_info.hProcess)
    kernel32.CloseHandle(process_info.hThread)
    return True

def save_config(username: str, domain: str, password: str, key: bytes = None):
    """
    Encrypts and saves AD credentials into the multi-user credentials sub-store.
    This assumes verification has already been done.
    """
    config = load_config(key=key)
    
    # Ensure "credentials" dictionary exists
    if "credentials" not in config:
        config["credentials"] = {}

    user_key = username.lower()
    config["credentials"][user_key] = {
        "username": username,
        "domain": domain,
        "password": password
    }

    raw_data = json.dumps(config).encode('utf-8')
    encrypted_data = EncryptionManager.encrypt_config(raw_data, key=key)
    
    with open(CONFIG_PATH, "wb") as f:
        f.write(encrypted_data)

def load_config(key: bytes = None) -> dict:
    """
    Loads and decrypts the multi-user credential store from config.bin.
    """
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError("Authentication configuration not found. Please run 'init' first.")
        
    with open(CONFIG_PATH, "rb") as f:
        encrypted_data = f.read()
        
    raw_data = EncryptionManager.decrypt_config(encrypted_data, key=key)
    data = json.loads(raw_data.decode('utf-8'))

    # Migration path: if the decrypted payload is from the old single-user version,
    # convert it on the fly to the new dictionary structure.
    if isinstance(data, dict) and "username" in data and "users" not in data:
        legacy_user = data["username"]
        return {
            "master_mfa_type": "totp",
            "master_mfa_secret": data.get("mfa_secret", ""),
            "credentials": {
                legacy_user.lower(): {
                    "username": legacy_user,
                    "domain": data.get("domain", ""),
                    "password": data.get("password", "")
                }
            }
        }

    return data

def verify_master_auth() -> bool:
    """
    Decrypts the config, extracts master MFA settings, and verifies the user.
    """
    try:
        config = load_config()
    except FileNotFoundError as e:
        print(f"[Error] {e}")
        return False
    except Exception as e:
        print(f"[Error] Failed to load/decrypt config: {e}")
        return False

    mfa_type = config.get("master_mfa_type")
    mfa_secret = config.get("master_mfa_secret")
    
    if not mfa_type or not mfa_secret:
        print("[Error] Config store is corrupted or has no master MFA setup.")
        return False

    print("\n==================================================")
    print("      ADAdmin Master MFA Verification             ")
    print("==================================================")

    if mfa_type == "totp":
        code = input("Enter your 6-digit Smartphone Authenticator code: ").strip()
        if MFAHandler.verify_totp(mfa_secret, code):
            print("[Success] Master TOTP verified.")
            return True
        else:
            print("[Error] Invalid master TOTP code.")
            return False

    elif mfa_type == "yubikey":
        # Since Yubikey was used to supply the decryption key to get here (load_config succeeded),
        # the user has already tapped their physical Yubikey. Successful decryption is implicit verification.
        print("[Success] Master Yubikey verified (decryption successful).")
        return True

    print(f"[Error] Unknown master MFA type: {mfa_type}")
    return False

class ADAuthSession:
    """
    Holds decrypted credentials for enrolled users and manages MFA verification
    and process execution using CreateProcessWithLogonW.
    """
    def __init__(self, credentials_dict: dict):
        self._credentials = credentials_dict  # Keyed by lowercase username

    def get_available_users(self) -> list:
        """
        Returns a list of username strings currently enrolled.
        """
        return [user_info["username"] for user_info in self._credentials.values()]

    def run_as(self, username: str, command: str) -> bool:
        """
        Performs MFA verification and launches the specified command under 
        the security context of the given user.
        """
        key = username.lower().strip()
        if key not in self._credentials:
            raise KeyError(f"User '{username}' is not enrolled in the credential store.")

        user_config = self._credentials[key]
        print(f"\nAuthenticating as: {user_config.get('domain') or '.'}\\{user_config.get('username')}")

        mfa_type = user_config.get("mfa_type")
        mfa_secret = user_config.get("mfa_secret")

        authenticated = False

        if mfa_type == "totp":
            code = input("Enter your 6-digit Smartphone Authenticator code: ").strip()
            if MFAHandler.verify_totp(mfa_secret, code):
                authenticated = True
            else:
                print("[Error] Invalid TOTP authentication code.")

        elif mfa_type == "yubikey":
            print("Tap your Yubikey...")
            otp_tap = getpass.getpass("").strip().lower()
            if MFAHandler.verify_yubikey_otp(otp_tap, mfa_secret):
                authenticated = True
            else:
                print("[Error] Yubikey validation failed.")

        if authenticated:
            print("\n[Success] MFA verified successfully!")
            print(f"Launching program: {command}")
            try:
                return run_process_as_user(
                    user_config["username"],
                    user_config["domain"],
                    user_config["password"],
                    command
                )
            except Exception as e:
                print(f"[Error] Failed to launch process: {e}")
                return False
        else:
            print("[Access Denied] Authentication failed.")
            return False
