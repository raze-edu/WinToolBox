import sys
import os
import secrets
import base64
import urllib.parse
import subprocess
import getpass
import json
from cryptography.fernet import Fernet

from .mfa import MFAHandler
from .encryption import EncryptionManager, KEY_PATH
from .session import CONFIG_PATH, save_config, load_config, verify_master_auth, run_process_as_user

def do_init():
    """
    Initializes a new configuration database and registers master MFA.
    If TOTP is selected, key.bin is created and protected with Windows DPAPI.
    If Yubikey is selected, a secure decryption key is generated and the user
    is instructed to store it as a Static Password on the Yubikey. No key.bin is saved.
    """
    # Clear any cached session key
    import ADAdmin.Auth.encryption as encryption_mod
    encryption_mod._session_key = None

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
            if MFAHandler.verify_totp(mfa_secret, user_code):
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
        static_password = EncryptionManager.generate_safe_password(32)
        
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

        key = EncryptionManager.derive_fernet_key(static_password)            
    else:
        print("[Error] Invalid selection. Initialization cancelled.")
        return

    try:
        if mfa_type == "totp":
            encrypted_key = EncryptionManager.encrypt_dpapi(key)
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
        encryption_mod._session_key = key
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
        encrypted_data = EncryptionManager.encrypt_config(raw_data)
        with open(CONFIG_PATH, "wb") as f:
            f.write(encrypted_data)
        print(f"[Success] Credentials for user '{username}' successfully removed!")
    except Exception as e:
        print(f"[Error] Failed to save updated config: {e}")

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

def do_manage():
    """
    Interactive loop to manage credentials (list, add, edit, remove).
    """
    if not verify_master_auth():
        print("[Access Denied] Master authentication failed.")
        return

    while True:
        print("\n==================================================")
        print("      ADAdmin Credential Management               ")
        print("==================================================")
        print("1. List Credentials")
        print("2. Add Credential")
        print("3. Edit Credential")
        print("4. Remove Credential")
        print("5. Exit")
        
        choice = input("\nSelect an option (1-5): ").strip()
        
        if choice == '5':
            print("Exiting management interface.")
            break
            
        try:
            config = load_config()
        except Exception as e:
            print(f"[Error] Failed to load config: {e}")
            continue
            
        credentials = config.get("credentials", {})
        available_users = [u["username"] for u in credentials.values()]
        
        if choice == '1':
            print("\n--- Enrolled Credentials ---")
            if not available_users:
                print("No users enrolled.")
            else:
                for key, user_data in credentials.items():
                    domain = user_data.get('domain') or '.'
                    username = user_data.get('username')
                    print(f" - {domain}\\{username}")
                    
        elif choice == '2':
            print("\n--- Add Credential ---")
            username = input("Enter Windows/AD Username: ").strip()
            domain = input("Enter Active Directory Domain (optional, press Enter for local): ").strip()
            password = getpass.getpass("Enter Password: ")
            
            try:
                save_config(username, domain, password)
                print("\n[Success] Credentials securely saved!")
            except Exception as e:
                print(f"[Error] Failed to save credentials: {e}")
                
        elif choice == '3':
            print("\n--- Edit Credential ---")
            if not available_users:
                print("No users enrolled to edit.")
                continue
                
            print("Available enrolled users:")
            for u in available_users:
                print(f"  - {u}")
                
            username = input("\nEnter username to edit: ").strip()
            key = username.lower().strip()
            if key not in credentials:
                print(f"[Error] User '{username}' is not enrolled.")
                continue
                
            domain = input("Enter new Active Directory Domain (optional, press Enter for local): ").strip()
            password = getpass.getpass("Enter new Password: ")
            
            try:
                save_config(username, domain, password)
                print("\n[Success] Credentials successfully updated!")
            except Exception as e:
                print(f"[Error] Failed to update credentials: {e}")
                
        elif choice == '4':
            print("\n--- Remove Credential ---")
            if not available_users:
                print("No users enrolled to remove.")
                continue
                
            print("Available enrolled users:")
            for u in available_users:
                print(f"  - {u}")
                
            username = input("\nEnter username to remove: ").strip()
            key = username.lower().strip()
            if key not in credentials:
                print(f"[Error] User '{username}' is not enrolled.")
                continue
                
            confirm = input(f"Are you sure you want to remove credentials for '{username}'? (y/N): ").strip().lower()
            if confirm == 'y':
                del credentials[key]
                config["credentials"] = credentials
                try:
                    raw_data = json.dumps(config).encode('utf-8')
                    encrypted_data = EncryptionManager.encrypt_config(raw_data)
                    with open(CONFIG_PATH, "wb") as f:
                        f.write(encrypted_data)
                    print(f"\n[Success] Credentials for user '{username}' successfully removed!")
                except Exception as e:
                    print(f"[Error] Failed to save updated config: {e}")
            else:
                print("Removal cancelled.")
        else:
            print("[Error] Invalid selection. Please choose 1-5.")

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
    print("  python -m ADAdmin.Auth.main init                    - Initialize a new key-file and empty configuration")
    print("  python -m ADAdmin.Auth.main enroll                  - Enroll a Windows/AD credential and MFA device")
    print("  python -m ADAdmin.Auth.main add                     - Alias for enroll")
    print("  python -m ADAdmin.Auth.main remove [username]       - Remove a Windows/AD credential from the store")
    print("  python -m ADAdmin.Auth.main manage                  - Open an interactive credential management menu")
    print("  python -m ADAdmin.Auth.main run [username] [cmd...] - Verify MFA and execute command as the specified user")
    print("  python -m ADAdmin.Auth.main help                    - Show this help message")

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
    elif cmd == "manage":
        do_manage()
    elif cmd == "run":
        do_run(sys.argv[2:])
    elif cmd in ("help", "-h", "--help"):
        show_help()
    else:
        print(f"[Error] Unknown command: {sys.argv[1]}")
        show_help()

if __name__ == "__main__":
    main()
