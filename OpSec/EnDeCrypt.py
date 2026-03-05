import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from json import loads, dumps

class EnDeCrypt:
    """
    EnDeCrypt handles 256-bit AES-GCM encryption and decryption of binary data.
    """
    def __init__(self, key: bytes):
        """
        Initialize with a 256-bit (32 byte) key.
        :param key: 32 bytes of key material.
        """
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, data) -> bytes:
        """
        Encrypts binary data using AES-GCM.
         Returns a concatenated bytes object: nonce (12 bytes) + ciphertext + tag.
        :param data: The binary data to encrypt.
        :return: Encrypted data.
        """
        if not isinstance(data, bytes):
            data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
            
        nonce = os.urandom(12) # GCM standard nonce size
        # encrypt returns ciphertext + tag
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts binary data.
        Expects concatenated bytes: nonce (first 12 bytes) + (ciphertext + tag).
        :param encrypted_data: The data to decrypt.
        :return: Original binary data.
        :raises ValueError: If decryption fails (e.g., tampered data).
        """
        if len(encrypted_data) < 12 + 16: # 12 byte nonce + minimum 16 byte tag
             raise ValueError("Encrypted data is too short or malformed.")
             
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        try:
            return self.aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError("Decryption failed. Data might be tampered with or key is incorrect.") from e

    def read_table(self, table: Data, name: str):
        return loads(self.decrypt(table.read_file(name)).decode('utf-8'))

    def write_table(self, table: Data, name: str, data: dict):
        table.write_file(name, self.encrypt(dumps(data).encode('utf-8')))

if __name__ == "__main__":
    def test():
        test_key = os.urandom(32)
        cipher = EnDeCrypt(test_key)
        msg = b"Hello world, this is a secret binary message."
        with open('test.bin', 'wb') as f:
            temp = cipher.encrypt(msg)
            print(temp)
            f.write(temp)
        return test_key, msg, temp

    def test2(key, msg, temp):
        cipher = EnDeCrypt(key)
        with open('test.bin', 'rb') as f:
            temp2 = f.read()
            print(temp == temp2, temp2)
            print(msg == cipher.decrypt(temp2), cipher.decrypt(temp2))
			
    test2(*test())
