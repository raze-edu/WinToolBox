import os
import ctypes
from ctypes import wintypes

try:
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession, SLOT
except ImportError:
    pass

class CREDUI_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hwndParent", wintypes.HWND),
        ("pszMessageText", wintypes.LPCWSTR),
        ("pszCaptionText", wintypes.LPCWSTR),
        ("hbmBanner", wintypes.HBITMAP),
    ]

# Windows CredUI constants
ERROR_SUCCESS = 0
ERROR_CANCELLED = 1223
CREDUIWIN_GENERIC = 0x1
CREDUIWIN_CHECKBOX = 0x2

class HardwareToken:
    def __init__(self, management_key=None, pin=None):
        """
        Initialize the HardwareToken object.
        :param management_key: PIV Management Key (bytes), default is standard Yubikey 9B key.
        :param pin: PIV PIN (string), standard default is '123456'.
        """
        # Default YubiKey management key (24 bytes for 3DES)
        self.management_key = management_key or bytes.fromhex("010203040506070801020304050607080102030405060708")
        self.pin = pin or "123456"
        # 0x005FC109 is the "Printed Information" PIV Data Object, supporting arbitrary data up to a few KB.
        self.key_object_id = 0x005FC109

    def _get_piv_session(self):
        """Finds the first connected YubiKey and returns a PivSession."""
        try:
            for device, info in list_all_devices():
                try:
                    conn = device.open_connection(SmartCardConnection)
                    return PivSession(conn)
                except Exception:
                    continue
        except NameError:
            raise RuntimeError("yubikey-manager is not installed. Please install it via 'pip install yubikey-manager'.")
            
        raise RuntimeError("No YubiKey with PIV application found.")

    def is_windows_hardware_token(self):
        """
        Checks if the YubiKey is provisioned as a Microsoft Windows Hardware token
        by looking for Smart Card Logon certificates in PIV slots 9A (Authentication)
        or 9C (Digital Signature).
        """
        session = self._get_piv_session()
        
        for slot in [SLOT.AUTHENTICATION, SLOT.SIGNATURE]:
            try:
                cert = session.get_certificate(slot)
                if cert is not None:
                    # If any certificate is present in the smart card logon slots,
                    # it strongly indicates usage as a Windows Hardware token.
                    return True
            except Exception:
                pass
                
        return False

    def check_user_signed_in_or_prompt(self, message="Please sign in to verify your identity."):
        """
        Checks if the user is signed in to the system. Since standard Python execution
        means a session is active, we explicitly prompt the user for Windows Credentials
        to re-authenticate them (supporting Smart Card / YubiKey and Windows Hello).
        """
        if os.name != 'nt':
            raise NotImplementedError("This method is only supported on Microsoft Windows.")

        credui_info = CREDUI_INFO()
        credui_info.cbSize = ctypes.sizeof(CREDUI_INFO)
        credui_info.hwndParent = 0
        credui_info.pszMessageText = message
        credui_info.pszCaptionText = "Windows Security"
        credui_info.hbmBanner = 0

        auth_package = wintypes.ULONG(0)
        out_auth_buffer = ctypes.c_void_p()
        out_auth_buffer_size = wintypes.ULONG(0)
        save_checkbox = wintypes.BOOL(False)

        credui = ctypes.windll.credui
        
        # CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX brings up the standard Windows Logon UI
        result = credui.CredUIPromptForWindowsCredentialsW(
            ctypes.byref(credui_info),
            0,
            ctypes.byref(auth_package),
            None,
            0,
            ctypes.byref(out_auth_buffer),
            ctypes.byref(out_auth_buffer_size),
            ctypes.byref(save_checkbox),
            CREDUIWIN_GENERIC
        )

        if result == ERROR_SUCCESS:
            if out_auth_buffer:
                ctypes.windll.ole32.CoTaskMemFree(out_auth_buffer)
            return True
        elif result == ERROR_CANCELLED:
            return False
        else:
            raise ctypes.WinError(result)

    def generate_and_store_256bit_key(self):
        """
        Creates a random 256-bit (32 byte) key and stores it on the YubiKey.
        Overwrites any existing data in the relevant PIV Data Object slot.
        """
        new_key = os.urandom(32) # 256 bits = 32 bytes
        session = self._get_piv_session()
        
        # Authenticate with Management Key to write data
        session.authenticate(self.management_key)
        
        # Write the 256-bit key to the Printed Information slot
        # Notice we prefix the data with a tag/length or just store raw bytes.
        # We will wrap it slightly so it doesn't fail basic parsing if needed, or put raw.
        session.put_object(self.key_object_id, new_key)
        return new_key

    def read_256bit_key(self):
        """
        Reads the 256-bit key from the YubiKey.
        """
        session = self._get_piv_session()
        try:
            # Some YubiKey configurations might require PIN verification for reading
            session.verify_pin(self.pin)
            data = session.get_object(self.key_object_id)
            if data and len(data) == 32:
                return data
            else:
                return None
        except Exception as e:
            # If PIN verification fails or the object is empty/malformed
            return None
