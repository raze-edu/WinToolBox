import sys
import argparse
from typing import Optional

# Cryptography primitives for RSA public key handling & PKCS1v15 padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Yubico SDK imports
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import (
    PivSession,
    SLOT,
    KEY_TYPE,
    PIN_POLICY,
    TOUCH_POLICY,
    MANAGEMENT_KEY_TYPE,
    ApduError,
)

# Default PIV Management Key (24 bytes Triple-DES / AES default hex)
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")

# PIV Data Object slot used to store the encrypted payload on the YubiKey (User Data 1)
OBJECT_ID_SECRET = 0x5FC109


def get_piv_device():
    """
    Locates an inserted YubiKey supporting PIV (Smart Card connection).
    """
    devices = list_all_devices()
    for device, info in devices:
        if device.supports_connection(SmartCardConnection):
            return device
    raise RuntimeError("No YubiKey supporting PIV (Smart Card) found. Please check your USB connection.")


def store_secret(
    secret_text: str,
    pin: str,
    mgmt_key: bytes = DEFAULT_MGMT_KEY,
    slot: SLOT = SLOT.KEY_MANAGEMENT
) -> None:
    """
    Generates an RSA keypair on the YubiKey with PIN_POLICY.ALWAYS and TOUCH_POLICY.ALWAYS,
    encrypts the secret string with the public key, and stores the encrypted data on the YubiKey.
    """
    device = get_piv_device()

    with device.open_connection(SmartCardConnection) as connection:
        session = PivSession(connection)

        print("[*] Verifying PIN...")
        try:
            session.verify_pin(pin)
        except ApduError as e:
            raise ValueError(f"PIN verification failed: {e}")

        print("[*] Authenticating management key...")
        try:
            session.authenticate(mgmt_key)
        except ApduError as e:
            raise ValueError(f"Management key authentication failed: {e}")

        print("[*] Generating hardware key pair on YubiKey (PIN + Touch required for decryption)...")
        # Generate RSA-2048 key directly on the YubiKey slot with strict hardware policies
        public_key = session.generate_key(
            slot,
            KEY_TYPE.RSA2048,
            pin_policy=PIN_POLICY.ALWAYS,
            touch_policy=TOUCH_POLICY.ALWAYS
        )

        print("[*] Encrypting secret payload...")
        encrypted_payload = public_key.encrypt(
            secret_text.encode("utf-8"),
            padding.PKCS1v15()
        )

        print("[*] Saving encrypted secret payload to YubiKey PIV storage...")
        session.put_object(OBJECT_ID_SECRET, encrypted_payload)
        print("[+] Secret stored successfully on YubiKey!")


def read_secret(pin: str, slot: SLOT = SLOT.KEY_MANAGEMENT) -> str:
    """
    Retrieves the encrypted secret from the YubiKey, verifies the PIN,
    prompts the user to touch the YubiKey button, and returns the decrypted secret string.
    """
    device = get_piv_device()

    with device.open_connection(SmartCardConnection) as connection:
        session = PivSession(connection)

        print("[*] Verifying PIN for storage retrieval...")
        try:
            session.verify_pin(pin)
        except ApduError as e:
            raise ValueError(f"PIN verification failed: {e}")

        print("[*] Fetching encrypted secret from YubiKey...")
        try:
            encrypted_payload = session.get_object(OBJECT_ID_SECRET)
        except ApduError:
            raise RuntimeError("No stored secret found on this YubiKey. Run 'store' first.")

        if not encrypted_payload:
            raise RuntimeError("Secret storage is empty.")

        print("[*] Verifying PIN again for decryption (PIN_POLICY.ALWAYS)...")
        try:
            session.verify_pin(pin)
        except ApduError as e:
            raise ValueError(f"PIN verification failed: {e}")

        print("\n" + "=" * 50)
        print(">>> TOUCH YOUR YUBIKEY BUTTON NOW TO REVEAL SECRET <<<")
        print("=" * 50 + "\n")

        try:
            # Triggers YubiKey hardware touch wait LED prompt
            plaintext_bytes = session.decrypt(slot, encrypted_payload, padding.PKCS1v15())
        except ApduError as e:
            raise RuntimeError(f"Decryption failed or touch timed out: {e}")

        return plaintext_bytes.decode("utf-8")


if __name__ == "__main__":
    store_secret('Hello World!', '123456')
    print(read_secret('123456'))