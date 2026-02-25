import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bitarray import bitarray as ba

class Creds:
    def __init__(self, storage_dir="vault"):
        """
        Initialize the Creds object.
        :param storage_dir: Directory to store encrypted credential files.
        """
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

    def _get_filename(self, username):
        """
        Generates a filename based on the SHA256 hash of the username.
        """
        hasher = hashlib.sha256()
        hasher.update(username.encode('utf-8'))
        return os.path.join(self.storage_dir, hasher.hexdigest())

    def save_creds(self, username, password, key):
        """
        Encrypts the password with AES-GCM using the provided key and saves it.
        :param username: The username as a string.
        :param password: The password as a string.
        :param key: The 256-bit encryption key (bytes or bitarray).
        """
        # Ensure key is bytes for AESGCM
        if isinstance(key, ba):
            key_bytes = key.tobytes()
        else:
            key_bytes = key

        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)  # Recommended nonce size for AES-GCM
        encrypted_pass = aesgcm.encrypt(nonce, password.encode('utf-8'), None)
        
        filename = self._get_filename(username)
        with open(filename, 'wb') as f:
            # Store nonce followed by encrypted data
            f.write(nonce + encrypted_pass)

    def load_creds(self, username, key):
        """
        Loads and decrypts the password for the given username.
        :param username: The username as a string.
        :param key: The 256-bit encryption key (bytes or bitarray).
        :return: Decrypted password string, or None if decryption fails or file not found.
        """
        filename = self._get_filename(username)
        if not os.path.exists(filename):
            return None

        # Ensure key is bytes for AESGCM
        if isinstance(key, ba):
            key_bytes = key.tobytes()
        else:
            key_bytes = key

        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(key_bytes)
            decrypted_pass = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_pass.decode('utf-8')
        except Exception:
            # Decryption failed or file corrupted
            return None

    def get_ps_credential_command(self, username, key):
        """
        Creates a PowerShell command string to create a PSCredential object.
        """
        password = self.load_creds(username, key)
        if not password:
            return None

        # Escaping single quotes for PowerShell
        ps_password = password.replace("'", "''")
        ps_username = username.replace("'", "''")
        
        # This command creates a PSCredential object without user interaction
        # Note: In a production environment, passing passwords in command lines
        # can be visible in process listings. Use with caution.
        cmd = f"$secPassword = ConvertTo-SecureString '{ps_password}' -AsPlainText -Force; " \
              f"$creds = New-Object System.Management.Automation.PSCredential('{ps_username}', $secPassword); " \
              f"$creds"
        
        return cmd

if __name__ == "__main__":
    # Example usage:
    # from HardwareToken import HardwareToken
    # token = HardwareToken()
    # key = token.read_256bit_key()
    # creds = Creds()
    # creds.save_creds("bob", "secret123", key)
    # print(creds.load_creds("bob", key))
    pass
