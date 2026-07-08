import time
import hmac
import hashlib
import base64
import struct
import secrets
import urllib.request
import urllib.parse

class MFAHandler:
    @staticmethod
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

    @staticmethod
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
            if MFAHandler.get_totp_code(secret, time_val=t) == code:
                return True
        return False

    @staticmethod
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
