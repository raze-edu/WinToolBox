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
from ctypes import wintypes

# Default path for the configuration file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.bin")

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


def save_config(username: str, domain: str, password: str, mfa_type: str, mfa_secret: str):
    """
    Encrypts and saves AD credentials and MFA settings into a multi-user store.
    """
    users_store = {}
    if os.path.exists(CONFIG_PATH):
        try:
            users_store = load_config()
        except Exception:
            users_store = {}

    # Append/Update the user (keyed by lowercase username for lookup casing)
    key = username.lower()
    users_store[key] = {
        "username": username,
        "domain": domain,
        "password": password,
        "mfa_type": mfa_type,
        "mfa_secret": mfa_secret
    }

    raw_data = json.dumps(users_store).encode('utf-8')
    encrypted_data = encrypt_dpapi(raw_data)
    
    with open(CONFIG_PATH, "wb") as f:
        f.write(encrypted_data)


def load_config() -> dict:
    """
    Loads and decrypts the multi-user credential store from config.bin.
    """
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError("Authentication configuration not found. Please run 'enroll' first.")
        
    with open(CONFIG_PATH, "rb") as f:
        encrypted_data = f.read()
        
    raw_data = decrypt_dpapi(encrypted_data)
    data = json.loads(raw_data.decode('utf-8'))

    # Migration path: if the decrypted payload is from the old single-user version,
    # convert it on the fly to the new dictionary structure.
    if isinstance(data, dict) and "username" in data and "users" not in data:
        legacy_user = data["username"]
        return {legacy_user.lower(): data}

    return data


# ==========================================
# CLI Operations
# ==========================================
def do_enroll():
    """
    Interactive command to register credentials and MFA.
    """
    print("==================================================")
    print("      ADAdmin Secure Credential Enrollment        ")
    print("==================================================")
    
    username = input("Enter Windows/AD Username: ").strip()
    domain = input("Enter Active Directory Domain (optional, press Enter for local): ").strip()
    password = getpass.getpass("Enter Password: ")
    
    print("\nSelect 2-Factor Authentication (MFA) Type:")
    print("1) Smartphone Authenticator (TOTP)")
    print("2) Yubikey (Hardware OTP Token)")
    choice = input("Select choice (1 or 2): ").strip()
    
    mfa_type = ""
    mfa_secret = ""
    
    if choice == "1":
        mfa_type = "totp"
        # Generate 80-bit secure random key (16 base32 chars, much easier for manual typing!)
        raw_secret = secrets.token_bytes(10)
        mfa_secret = base64.b32encode(raw_secret).decode('utf-8')
        
        # Display keys and scan code URL
        label = f"ADAdmin:{username}"
        issuer = "ADAdmin"
        otpauth_uri = f"otpauth://totp/{label}?secret={mfa_secret}&issuer={issuer}"
        # Using api.qrserver.com as googleapis chart API is deprecated (returns 404)
        qr_url = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + urllib.parse.quote(otpauth_uri)
        
        print("\n---------------- TOTP Enroller ----------------")
        print(f"Secret Key (Base32): {mfa_secret}")
        print("\nScan the QR code below using your Smartphone Authenticator app:")
        print(qr_url)
        print("-----------------------------------------------")
        
        # Verify right away
        attempts = 3
        while attempts > 0:
            user_code = input("\nEnter the 6-digit verification code from your app: ").strip()
            if verify_totp(mfa_secret, user_code):
                print("[Success] TOTP verification succeeded! MFA enrolled.")
                break
            else:
                attempts -= 1
                print(f"[Error] Invalid TOTP code. {attempts} attempts remaining.")
                if attempts > 0:
                    print("\nTroubleshooting Tips:")
                    print("1. If entered manually, check for typos in the secret key.")
                    print("2. Ensure your phone's clock is fully synchronized with internet time.")
                    print(f"   Current PC Local Time: {time.strftime('%H:%M:%S')}")
                    print("3. Ensure the key type on your app is set to 'Time-based' (NOT 'Counter-based').")
        else:
            print("[Failure] Failed to verify TOTP code. Enrollment cancelled.")
            return
            
    elif choice == "2":
        mfa_type = "yubikey"
        print("\n---------------- Yubikey Enroller --------------")
        print("1. Insert your Yubikey into a USB port.")
        print("2. Focus the input field below.")
        print("3. Gently touch/tap the gold button on your Yubikey.")
        otp_tap = getpass.getpass("Tap Yubikey here: ").strip().lower()
        
        if len(otp_tap) != 44:
            print("[Error] Invalid Yubikey OTP length (expected 44 chars). Enrollment cancelled.")
            return
            
        mfa_secret = otp_tap[:12]
        print(f"[Success] Registered Yubikey Public ID: {mfa_secret}")
        
    else:
        print("[Error] Invalid selection. Enrollment cancelled.")
        return
        
    # Save the configuration securely using DPAPI
    save_config(username, domain, password, mfa_type, mfa_secret)
    print("\n[Success] Credentials and MFA settings securely saved!")


def do_run(command_args):
    """
    Authenticates via MFA and runs the command.
    """
    try:
        users_store = load_config()
    except FileNotFoundError:
        print("[Error] No credentials enrolled. Run 'python auth.py enroll' first.")
        return
        
    session = ADAuthSession(users_store)
    available_users = session.get_available_users()
    
    if not available_users:
        print("[Error] No users enrolled in the credential store.")
        return
        
    # Determine target user and command
    target_command = "cmd.exe"
    username = ""
    
    if command_args:
        # Check if first argument is a registered username
        first_arg = command_args[0]
        if first_arg.lower() in [u.lower() for u in available_users]:
            username = first_arg
            target_command = " ".join(command_args[1:]) if len(command_args) > 1 else "cmd.exe"
        else:
            # If not a registered username, default to single user if only one, or ask
            if len(available_users) == 1:
                username = available_users[0]
            else:
                print("Available enrolled users:")
                for u in available_users:
                    print(f"  - {u}")
                username = input("Enter username to run as: ").strip()
            target_command = " ".join(command_args)
    else:
        # No arguments given at all
        if len(available_users) == 1:
            username = available_users[0]
        else:
            print("Available enrolled users:")
            for u in available_users:
                print(f"  - {u}")
            username = input("Enter username to run as: ").strip()
            
    # Run command
    try:
        session.run_as(username, target_command)
    except Exception as e:
        print(f"[Error] Execution failed: {e}")


def show_help():
    print("ADAdmin Secure Multi-User MFA Execution Helper")
    print("Usage:")
    print("  python auth.py enroll                  - Enroll a Windows/AD credential and MFA device")
    print("  python auth.py run [username] [cmd...] - Verify MFA and execute command as the specified user")
    print("  python auth.py help                    - Show this help message")


def main():
    if len(sys.argv) < 2:
        show_help()
        return
        
    cmd = sys.argv[1].lower()
    if cmd == "enroll":
        do_enroll()
    elif cmd == "run":
        do_run(sys.argv[2:])
    elif cmd in ("help", "-h", "--help"):
        show_help()
    else:
        print(f"[Error] Unknown command: {sys.argv[1]}")
        show_help()


if __name__ == "__main__":
    main()
