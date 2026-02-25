from pathlib import Path
from OpSec.EnDeCrypt import EnDeCrypt
from OpSec.Data import Data
from OpSec.HardwareToken import HardwareToken
import os



filepath = Path("TESTFILE")

key = os.urandom(32)

crypt_handle = EnDeCrypt(key)
data_handle = Data(filepath)

data_handle.write_file("TESTFILE", crypt_handle.encrypt(b"Hello world, this is a secret binary message."))

