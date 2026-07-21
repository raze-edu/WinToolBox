import base64
import hashlib
from cryptography.fernet import Fernet


class CryptoKey(Fernet):

    @classmethod
    def from_string(cls, string: str) -> 'CryptoKey':
        """
        Generates a consistent Fernet key from a string input.
        The same input string will always produce the same Fernet key.
        """
        # Hash the input string to get a consistent 32-byte output
        # SHA256 produces a 32-byte (256-bit) hash digest
        key_material = hashlib.sha256(string.encode()).digest()
        # Fernet keys must be URL-safe base64-encoded
        return cls(base64.urlsafe_b64encode(key_material))

    @classmethod
    def resolve_keychain(cls, *args):
        key = cls.from_string(args[0])
        for arg in args[1:]:
            key = cls.from_string(key.decrypt(arg))
        return key

if __name__ == "__main__":
    key = CryptoKey.from_string("test")
    print(key.decrypt(b'gAAAAABqXdLyZTnBb2DrLo78wOXzrseX8ur-S-cswfd9H3VI3Agi8OSj-x8EiBpsuBEwISSnEY6ez6Hiq2aS8i7gj5nMXzx0NA=='))
    test = key.encrypt(b"test")
    print(test)

    key = CryptoKey.from_string("test")

    print(key.decrypt(test))
