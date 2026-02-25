from pathlib import Path
from OpSec.EnDeCrypt import EnDeCrypt
from OpSec.Data import Data
from OpSec.HardwareToken import HardwareToken
import os
from json import dumps, loads

key = os.urandom(32)
crypt_handle = EnDeCrypt(key)
fp = Path("TESTFILE")

def write(name, data):
    data_handle = Data(fp)
    print(data)
    for key, val in data.items():
        data_handle.write_file(key, crypt_handle.encrypt(val))

def read(name):
    data_handle = Data(fp)
    print(data_handle.read_file(name))
    return crypt_handle.decrypt(data_handle.read_file(name))

def test_a():
    data_file = dict(kontoA={"name": "kontoA", "password": "[PASSWORD]"}, kontoB={"name": "kontoB", "password": "[PASSWORD]"})
    data = {key: dumps(value).encode('utf-8') for key, value in data_file.items()}
    write("TESTFILE", data)
    temp = Data("TESTFILE")
    print(temp.list_files())
    for file in temp.list_files():
        if file != "TESTFILE":
            print(file)
            print(loads(read(file).decode('utf-8')))

import win32api
import win32security
import win32con

def get_current_domain_and_user():
    # 1. Get the handle to the current process
    process = win32api.GetCurrentProcess()
    
    # 2. Open the access token associated with the process
    token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
    
    # 3. Get the User SID (Security Identifier) from the token
    user_sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
    
    # 4. Look up the account name using the SID
    # This natively returns a tuple of (Username, Domain, AccountType)
    username, domain, account_type = win32security.LookupAccountSid(None, user_sid)
    
    return domain, username

print(get_current_domain_and_user())