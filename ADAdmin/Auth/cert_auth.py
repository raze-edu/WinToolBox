from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class AuthHandle:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    @staticmethod
    def _2_bytes(value):
        if value is None:
            return None
        elif isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bytes):
            return value
        elif isinstance(value, int):
            return value.to_bytes(2, 'big')
        elif isinstance(value, list):
            try:
                return bytes(value)
            except TypeError:
                return b''.join(value)
        return None

    @property
    def _key(self):
        return rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    )

    def _pem_key(self, password: str|bytes|None = None):
        enc_algo = serialization.NoEncryption() if self._2_bytes(password) is None else serialization.BestAvailableEncryption(self._2_bytes(password))
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
        )

    def _pem_key_load(self, pem_key: str|bytes, password: str|bytes|None=None):
        return serialization.load_pem_private_key(
            self._2_bytes(pem_key),
            password=self._2_bytes(password)
        )

    def _pem_lock_load(self, pem_lock: str|bytes):
        return serialization.load_pem_public_key(
            self._2_bytes(pem_lock))

    def _pem_lock(self):
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


print(pem_key.decode())
print(pem_lock.decode())