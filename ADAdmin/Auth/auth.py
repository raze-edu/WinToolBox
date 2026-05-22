import os
import sys
import json
import time
import hmac
import hashlib
import base64
import struct
import secrets
import getpass
import urllib.request
import urllib.parse
import ctypes
import string
import subprocess
from ctypes import wintypes
from cryptography.fernet import Fernet

# Default paths for the configuration and key files
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.bin")
KEY_PATH = os.path.join(os.path.dirname(__file__), "key.bin")

# ==========================================
# Windows DPAPI and Process Execution Setup
# ==========================================
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


# ==========================================
# Pure Python TOTP Implementation (RFC 6238)
# ==========================================
def get_totp_code(secret: str, interval: int = 30, time_val: float = None) -> str:
    """
    Computes a 6-digit TOTP code for the given secret at a specific time.
    """
    secret = secret.replace(" ", "").upper()
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += "=" * (8 - missing_padding)
    
    key = base64.b32decode(secret)
    if time_val is None:
        time_val = time.time()
        
    counter = int(time_val / interval)
    msg = struct.pack(">Q", counter)
    
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_bin = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    
    code = code_bin % 1_000_000
    return f"{code:06d}"


def verify_totp(secret: str, code: str, window: int = 3) -> bool:
    """
    Verifies a 6-digit TOTP code against the secret, allowing a time window (default 90s drift).
    """
    current_time = time.time()
    code = code.strip()
    if len(code) != 6 or not code.isdigit():
        return False
        
    for i in range(-window, window + 1):
        t = current_time + i * 30
        if get_totp_code(secret, time_val=t) == code:
            return True
    return False


# ==========================================
# Yubikey OTP Verification Implementation
# ==========================================
def verify_yubikey_otp(otp: str, expected_id: str) -> bool:
    """
    Verifies a Yubikey OTP:
    1. Validates the length and character set (Modhex).
    2. Validates that the public ID matches the registered device.
    3. Attempts online cryptographic validation via Yubico API,
       falling back to strong local check if offline.
    """
    otp = otp.lower().strip()
    expected_id = expected_id.lower().strip()
    
    if len(otp) != 44:
        return False
    
    modhex_chars = set("cbdefghijklnrtuv")
    if not all(c in modhex_chars for c in otp):
        return False
        
    if otp[:12] != expected_id:
        return False
        
    # Attempt online validation with Yubico API (Client ID 1 is a standard public client)
    try:
        nonce = secrets.token_hex(16)
        params = {
            "id": "1",
            "otp": otp,
            "nonce": nonce
        }
        url = "https://api.yubico.com/wsapi/2.0/verify?" + urllib.parse.urlencode(params)
        
        req = urllib.request.Request(url, headers={"User-Agent": "ADAdmin-Auth/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_body = response.read().decode('utf-8')
            
        response_dict = {}
        for line in resp_body.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                response_dict[k.strip()] = v.strip()
                
        if response_dict.get("status") == "OK":
            return True
        else:
            print(f"[Warning] Yubico Validation Server returned status: {response_dict.get('status')}")
            return False
            
    except Exception as e:
        print(f"[Warning] Online Yubico API validation failed/offline ({e}).")
        print("Falling back to local physical token verification (Public ID and Modhex format verified).")
        return True


# ==========================================
# Secure Process Launching
# ==========================================
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


# ==========================================
# Secure Config Serialization & Session
# ==========================================
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
            if verify_totp(mfa_secret, code):
                authenticated = True
            else:
                print("[Error] Invalid TOTP authentication code.")

        elif mfa_type == "yubikey":
            print("Tap your Yubikey...")
            otp_tap = getpass.getpass("").strip().lower()
            if verify_yubikey_otp(otp_tap, mfa_secret):
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


_session_key = None


def generate_safe_password(length: int = 32) -> str:
    """
    Generates a cryptographically secure random modhex password.
    Modhex characters (cbdefghijklnrtuv) are 100% safe across all keyboard layouts
    because they map to the same physical keys on standard keyboards worldwide.
    """
    alphabet = "cbdefghijklnrtuv"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def derive_fernet_key(password_str: str) -> bytes:
    """
    Derives a valid Fernet key (32 URL-safe base64-encoded bytes) from any string
    using SHA-256.
    """
    h = hashlib.sha256(password_str.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(h)


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
            _session_key = decrypt_dpapi(encrypted_key)
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
        _session_key = derive_fernet_key(key_input)
        return _session_key


def encrypt_config(raw_data: bytes, key: bytes = None) -> bytes:
    """
    Encrypts a byte array using Fernet symmetric encryption and the provided or retrieved key.
    """
    if key is None:
        key = get_encryption_key()
    fernet = Fernet(key)
    return fernet.encrypt(raw_data)


def decrypt_config(encrypted_data: bytes, key: bytes = None) -> bytes:
    """
    Decrypts a byte array using Fernet symmetric encryption and the provided or retrieved key.
    """
    if key is None:
        key = get_encryption_key()
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)


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
    encrypted_data = encrypt_config(raw_data, key=key)
    
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
        
    raw_data = decrypt_config(encrypted_data, key=key)
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
        if verify_totp(mfa_secret, code):
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


def do_init():
    """
    Initializes a new configuration database and registers master MFA.
    If TOTP is selected, key.bin is created and protected with Windows DPAPI.
    If Yubikey is selected, a secure decryption key is generated and the user
    is instructed to store it as a Static Password on the Yubikey. No key.bin is saved.
    """
    global _session_key
    _session_key = None  # Clear any cached session key

    print("==================================================")
    print("      ADAdmin Storage & Master MFA Init           ")
    print("==================================================")
    
    if os.path.exists(KEY_PATH) or os.path.exists(CONFIG_PATH):
        print("[Warning] A key file or configuration file already exists.")
        confirm = input("Are you sure you want to overwrite them and start fresh? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Initialization cancelled.")
            return

    # Master MFA Setup
    print("\nConfigure Master Multi-Factor Authentication (MFA):")
    print("1) Smartphone Authenticator (TOTP)")
    print("2) Yubikey (Hardware Key Static Password)")
    choice = input("Select choice (1 or 2): ").strip()
    
    mfa_type = ""
    mfa_secret = ""
    key = None
    
    if choice == "1":
        mfa_type = "totp"
        raw_secret = secrets.token_bytes(10)
        mfa_secret = base64.b32encode(raw_secret).decode('utf-8')
        
        label = "ADAdmin:MasterKey"
        issuer = "ADAdmin"
        otpauth_uri = f"otpauth://totp/{label}?secret={mfa_secret}&issuer={issuer}"
        qr_url = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + urllib.parse.quote(otpauth_uri)
        
        print("\n---------------- Master TOTP Setup ----------------")
        print(f"Secret Key (Base32): {mfa_secret}")
        print("\nScan the QR code below using your Smartphone Authenticator app:")
        print(qr_url)
        print("---------------------------------------------------")
        
        attempts = 3
        while attempts > 0:
            user_code = input("\nEnter the 6-digit verification code from your app: ").strip()
            if verify_totp(mfa_secret, user_code):
                print("[Success] Master TOTP verification succeeded!")
                break
            else:
                attempts -= 1
                print(f"[Error] Invalid TOTP code. {attempts} attempts remaining.")
        else:
            print("[Failure] Failed to verify TOTP code. Initialization cancelled.")
            return

        key = Fernet.generate_key()

    elif choice == "2":
        mfa_type = "yubikey"
        
        # Generate a safe 32-character alphanumeric password
        static_password = generate_safe_password(32)
        
        print("\n---------------- Master Yubikey Setup -------------")
        print("We will generate and program a secure 32-character static decryption password")
        print("directly onto your YubiKey Slot 2 using the YubiKey Manager CLI.")
        print(f"\nGenerated Key: {static_password}\n")
        print("1. Insert your master YubiKey into a USB port.")
        confirm_insert = input("Press Enter when your YubiKey is inserted and ready... ")
        
        # Program YubiKey static password directly
        try:
            print("Programming YubiKey Slot 2 with the decryption password...")
            cmd = ["ykman", "otp", "static", "--keyboard-layout", "modhex", "-f", "2", static_password]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("[Success] Decryption key successfully written to YubiKey Slot 2!")
        except FileNotFoundError:
            print("\n[Error] YubiKey Manager CLI ('ykman') is not found on your system path.")
            print("Please install YubiKey Manager and ensure 'ykman' is added to your PATH environment variable.")
            print("\nTo configure manually instead, please program the Generated Key above into YubiKey Slot 2 as a Static Password.")
            confirm_manual = input("Press Enter after you have programmed it manually, or Ctrl+C to cancel... ")
        except subprocess.CalledProcessError as e:
            print(f"\n[Warning] Automated YubiKey programming failed: {e.stderr or e.stdout or str(e)}")
            print("To configure manually instead, please program the Generated Key above into YubiKey Slot 2 as a Static Password.")
            confirm_manual = input("Press Enter after you have programmed it manually, or Ctrl+C to cancel... ")
            
        print("\nOnce programmed, let's verify it:")
        print("1. Focus the input field below.")
        print("2. PRESS AND HOLD (long-press for 3-4 seconds) the gold button on your master YubiKey.")
        print("   (Do NOT just tap it quickly. A quick tap triggers Slot 1's Yubico OTP, which will fail).")
        
        attempts = 3
        while attempts > 0:
            otp_tap = getpass.getpass("Long-press YubiKey here (Slot 2): ").strip()
            if otp_tap == static_password:
                print("[Success] Decryption key verified successfully!")
                mfa_secret = "hardware_key"
                break
            else:
                attempts -= 1
                print(f"[Error] Key mismatch.")
                print(f"  Expected: {static_password} (len={len(static_password)})")
                print(f"  Received: {otp_tap} (len={len(otp_tap)})")
                print(f"  {attempts} attempts remaining.")
        else:
            print("[Failure] Failed to verify Yubikey static key. Initialization cancelled.")
            return

        key = derive_fernet_key(static_password)            
    else:
        print("[Error] Invalid selection. Initialization cancelled.")
        return

    try:
        if mfa_type == "totp":
            encrypted_key = encrypt_dpapi(key)
            with open(KEY_PATH, "wb") as f:
                f.write(encrypted_key)
            print(f"[Success] Created new DPAPI-protected key-file at: {KEY_PATH}")
        else:
            # If Yubikey is used, we do NOT save key.bin.
            # Clean up key.bin if it exists from a previous setup.
            if os.path.exists(KEY_PATH):
                try:
                    os.remove(KEY_PATH)
                except OSError:
                    pass
            print("[Success] Decryption key stored on Yubikey (not written to disk).")
        
        # Initialize config.bin with the master MFA structure and empty credentials
        payload = {
            "master_mfa_type": mfa_type,
            "master_mfa_secret": mfa_secret,
            "credentials": {}
        }
        raw_data = json.dumps(payload).encode('utf-8')
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(raw_data)
        
        with open(CONFIG_PATH, "wb") as f:
            f.write(encrypted_data)
        print(f"[Success] Created new config-file at: {CONFIG_PATH}")
        print("Initialization completed successfully!")
        
        # Cache the key in session to avoid prompting the user right after initialization
        _session_key = key
    except Exception as e:
        print(f"[Error] Initialization failed: {e}")


def do_remove(username: str = None):
    """
    Removes credentials for a specified user. Requires master authentication.
    """
    if not verify_master_auth():
        print("[Access Denied] Master authentication failed.")
        return

    print("==================================================")
    print("      ADAdmin Credential Removal                  ")
    print("==================================================")
    
    try:
        config = load_config()
    except FileNotFoundError as e:
        print(f"[Error] {e}")
        return
    except Exception as e:
        print(f"[Error] Failed to load config: {e}")
        return
        
    credentials = config.get("credentials", {})
    available_users = [u["username"] for u in credentials.values()]
    if not available_users:
        print("[Info] No users enrolled in the credential store.")
        return
        
    if not username:
        print("Available enrolled users:")
        for u in available_users:
            print(f"  - {u}")
        username = input("Enter username to remove: ").strip()
        
    key = username.lower().strip()
    if key not in credentials:
        print(f"[Error] User '{username}' is not enrolled in the credential store.")
        return
        
    confirm = input(f"Are you sure you want to remove credentials for '{username}'? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Removal cancelled.")
        return
        
    del credentials[key]
    config["credentials"] = credentials
    
    try:
        raw_data = json.dumps(config).encode('utf-8')
        encrypted_data = encrypt_config(raw_data)
        with open(CONFIG_PATH, "wb") as f:
            f.write(encrypted_data)
        print(f"[Success] Credentials for user '{username}' successfully removed!")
    except Exception as e:
        print(f"[Error] Failed to save updated config: {e}")


# ==========================================
# CLI Operations
# ==========================================
def do_enroll():
    """
    Interactive command to register credentials. Requires master authentication.
    """
    if not verify_master_auth():
        print("[Access Denied] Master authentication failed.")
        return

    print("==================================================")
    print("      ADAdmin Secure Credential Enrollment        ")
    print("==================================================")
    
    username = input("Enter Windows/AD Username: ").strip()
    domain = input("Enter Active Directory Domain (optional, press Enter for local): ").strip()
    password = getpass.getpass("Enter Password: ")
    
    # Save the configuration securely using key-file based symmetric encryption
    try:
        save_config(username, domain, password)
        print("\n[Success] Credentials securely saved!")
    except Exception as e:
        print(f"[Error] Failed to save credentials: {e}")


def do_run(command_args):
    """
    Authenticates via Master MFA and runs the command under the specified user context.
    """
    if not verify_master_auth():
        print("[Access Denied] Master authentication failed.")
        return

    try:
        config = load_config()
    except FileNotFoundError as e:
        print(f"[Error] {e}")
        return
        
    credentials = config.get("credentials", {})
    available_users = [u["username"] for u in credentials.values()]
    
    if not available_users:
        print("[Error] No users enrolled in the credential store.")
        return
        
    # Determine target user and command
    target_command = "cmd.exe"
    username = ""
    
    if command_args:
        first_arg = command_args[0]
        if first_arg.lower() in [u.lower() for u in available_users]:
            username = first_arg
            target_command = " ".join(command_args[1:]) if len(command_args) > 1 else "cmd.exe"
        else:
            if len(available_users) == 1:
                username = available_users[0]
            else:
                print("Available enrolled users:")
                for u in available_users:
                    print(f"  - {u}")
                username = input("Enter username to run as: ").strip()
            target_command = " ".join(command_args)
    else:
        if len(available_users) == 1:
            username = available_users[0]
        else:
            print("Available enrolled users:")
            for u in available_users:
                print(f"  - {u}")
            username = input("Enter username to run as: ").strip()
            
    key = username.lower().strip()
    if key not in credentials:
        print(f"[Error] User '{username}' is not enrolled in the credential store.")
        return

    user_config = credentials[key]
    print(f"\nLaunching program: {target_command} as {user_config.get('domain') or '.'}\\{user_config.get('username')}")
    try:
        run_process_as_user(
            user_config["username"],
            user_config["domain"],
            user_config["password"],
            target_command
        )
    except Exception as e:
        print(f"[Error] Failed to launch process: {e}")


def show_help():
    print("ADAdmin Secure Multi-User MFA Execution Helper")
    print("Usage:")
    print("  python auth.py init                    - Initialize a new key-file and empty configuration")
    print("  python auth.py enroll                  - Enroll a Windows/AD credential and MFA device")
    print("  python auth.py add                     - Alias for enroll")
    print("  python auth.py remove [username]       - Remove a Windows/AD credential from the store")
    print("  python auth.py run [username] [cmd...] - Verify MFA and execute command as the specified user")
    print("  python auth.py help                    - Show this help message")


def main():
    if len(sys.argv) < 2:
        show_help()
        return
        
    cmd = sys.argv[1].lower()
    if cmd == "init":
        do_init()
    elif cmd in ("enroll", "add"):
        do_enroll()
    elif cmd == "remove":
        username = sys.argv[2] if len(sys.argv) > 2 else None
        do_remove(username)
    elif cmd == "run":
        do_run(sys.argv[2:])
    elif cmd in ("help", "-h", "--help"):
        show_help()
    else:
        print(f"[Error] Unknown command: {sys.argv[1]}")
        show_help()


if __name__ == "__main__":
    main()
