import os
import struct
from time import perf_counter_ns as nsec
from math import ceil
from bitarray import bitarray as ba
from bitarray.util import ba2int as b2i, int2ba as i2b, ba2hex as b2h, hex2ba as h2b
from pathlib import Path
from GUI import *
from HardwareToken import HardwareToken

class UserRegister:
    def __init__(self, archive_path, n_user, username_length=32):
        """
        Initialize the UserRegister object with a path to a custom fixed-size slot archive.
        
        :param archive_path: Path to the archive file.
        :param n_user: Maximum number of users (determines file size and index block size).
        """
        print(n_user)
        if isinstance(n_user, str):
            n_user = int(n_user)
        self.secret_length = 60
        self.archive_path = Path(archive_path, '.users')                                                                                         
        self.n_user = n_user
        self.username_length = username_length
        # Calculate the size of the index block in bytes
        # It needs to be large enough to hold integer values up to n_user - 1
        self.index_size = ceil(n_user.bit_length() / 8)
        
        # A user slot is built from blocks:
        # - index number: index_size bytes
        # - username: 32 bytes
        # - flags: 1 byte
        # - key: 32 bytes
        # - 4 blocks of size index_size (list of 4 ints): 4 * index_size bytes
        self.slot_size = self.index_size + 32 + 1 + 60 + (4 * self.index_size)
        
        # Initialize the file with blank slots if it doesn't exist
        if not os.path.exists(self.archive_path):
            with open(self.archive_path, "wb") as f:
                # Pre-allocate the file to exactly contain n_user slots
                for i in range(self.n_user):
                    # Write the static iterating index value
                    f.write(i.to_bytes(self.index_size, byteorder='little'))
                    # Write 0s for the rest of the slot to initialize as empty slots
                    f.write(b'\x00' * (self.slot_size - self.index_size))
    
    @classmethod
    def config_load(cls, config):
        return cls(config.archive_path, config.n_user, config.username_length)
    
    def _pack_slot(self, index: int, username: str, flags: list[bool], key: bytes, int_list: list[int]) -> bytes:
        if len(int_list) != 4:
            raise ValueError("int_list must contain exactly 4 integers")
            
        byte_order = 'little'
        
        # 1. index number (1 block)
        index_bytes = index.to_bytes(self.index_size, byteorder=byte_order)
        
        # 2. username (32 bytes)
        u_bytes = username.encode('utf-8')
        if len(u_bytes) == 0:
            raise ValueError("Username cannot be empty")
        if len(u_bytes) > self.username_length:
            raise ValueError("Username too long (max 32 bytes UTF-8)")
        u_bytes = u_bytes.ljust(self.username_length, b'\x00')
        
        # 3. flags (1 byte holding max 8 flags)
        if len(flags) > 8:
            raise ValueError("Flags list too long (max 8 booleans)")
        flag_byte = 0
        for i, b in enumerate(flags):
            if b:
                flag_byte |= (1 << i)
        flags_bytes = struct.pack("<B", flag_byte)
        
        # 4. key (60 bytes)
        if len(key) > self.secret_length:
            raise ValueError("Key too long (max 32 bytes)")
        key_bytes = key.ljust(60, b'\x00')
        
        # 5. 4 blocks of index_size
        int_bytes = bytearray()
        for val in int_list:
            int_bytes.extend(val.to_bytes(self.index_size, byteorder=byte_order))
            
        return index_bytes + u_bytes + flags_bytes + key_bytes + bytes(int_bytes)

    def _unpack_slot(self, data: bytes) -> tuple[int, str, list[bool], bytes, list[int]]:
        if len(data) != self.slot_size:
            raise ValueError(f"Invalid Data size: expected {self.slot_size}, got {len(data)}")
            
        byte_order = 'little'
        offset = 0
        
        # 1. index number
        index = int.from_bytes(data[offset:offset+self.index_size], byteorder=byte_order)
        offset += self.index_size
        
        # 2. username
        u_bytes = data[offset:offset+self.username_length]
        username = u_bytes.split(b'\x00', 1)[0].decode('utf-8')
        offset += self.username_length
        
        # 3. flags
        flag_byte = struct.unpack("<B", data[offset:offset+1])[0]
        flags = [(flag_byte & (1 << i)) != 0 for i in range(8)]
        offset += 1
        
        # 4. secret
        key = data[offset:offset+60]
        offset += self.secret_length
        
        # 5. 4 blocks of index_size
        int_list = []
        for _ in range(4):
            val = int.from_bytes(data[offset:offset+self.index_size], byteorder=byte_order)
            offset += self.index_size
            int_list.append(val)
            
        return index, username, flags, key, int_list

    def _find_user(self, username: str) -> int:
        """Helper to find the slot index of a user. Returns -1 if not found."""
        u_bytes = username.encode('utf-8')
        if len(u_bytes) > 32:
            raise ValueError("Username too long (max 32 bytes UTF-8)")
            
        with open(self.archive_path, "rb") as f:
            for i in range(self.n_user):
                f.seek(i * self.slot_size + self.index_size)
                slot_u_bytes = f.read(self.username_length)
                if slot_u_bytes.split(b'\x00', 1)[0] == u_bytes:
                    return i
        return -1

    def _find_empty_slot(self) -> int:
        """Helper to find the first empty slot. Returns -1 if no free slot."""
        with open(self.archive_path, "rb") as f:
            for i in range(self.n_user):
                f.seek(i * self.slot_size + self.index_size)
                slot_u_bytes = f.read(self.username_length)
                if slot_u_bytes[0] == 0:  # Empty username means it starts with a null byte
                    return i
        return -1

    def write_user(self, username: str, flags: list[bool], key: bytes, int_list: list[int]):
        """
        Write a new user slot to the archive. Finds an empty slot, fails if none or if username exists.
        :param username: usernamelen-byte max username. Must be unique and not empty.
        :param flags: list of booleans (up to 8).
        :param key: 60-byte max key.
        :param int_list: list of 4 integers.
        """
        if len(username) == 0:
            raise ValueError("Username cannot be empty")
            
        if self._find_user(username) != -1:
            raise ValueError(f"User '{username}' already exists")
            
        slot_idx = self._find_empty_slot()
        if slot_idx == -1:
            raise RuntimeError("No free user slots available")
            
        data = self._pack_slot(slot_idx, username, flags, key, int_list)
        
        # Write in-place to the found free slot, note that the physical position slot_idx 
        # is also used as its prefilled slot index
        with open(self.archive_path, "r+b") as f:
            f.seek(slot_idx * self.slot_size)
            f.write(data)

    def read_user(self, username: str|int) -> tuple[int, str, list[bool], bytes, list[int]]:
        """
        Read a user slot from the archive using their username.
        :param username: Name of the user to find.
        :return: Tuple of (index, username, flags, key, int_list)
        """
        if isinstance(username, str):
            slot_idx = self._find_user(username)
            if slot_idx == -1:
                raise ValueError(f"User '{username}' not found")
        elif isinstance(username, int):
            slot_idx = username
        else:
            raise TypeError("Username must be a string or an integer")    
        with open(self.archive_path, "rb") as f:
            f.seek(slot_idx * self.slot_size)
            data = f.read(self.slot_size)
        return self._unpack_slot(data)

    def delete_user(self, username: str):
        """
        Wipes a user slot by writing 0 to the entire slot except the index value.
        :param username: Name of the user to delete.
        """
        slot_idx = self._find_user(username)
        if slot_idx == -1:
            raise ValueError(f"User '{username}' not found")
            
        with open(self.archive_path, "r+b") as f:
            # Seek past the index block to preserve its iterated position value
            f.seek(slot_idx * self.slot_size + self.index_size)
            f.write(b'\x00' * (self.slot_size - self.index_size))


class Flags(list):
    def __init__(self, *args):
        temp = [False for _ in range(8)]
        if len(args) > 8:
            raise ValueError("Flags list must contain at most 8 elements")
        for i in range(len(args)):
            temp[i] = args[i]
        super().__init__(*temp)


class User:
    timeout = 0
    validation = None
    def __init__(self, *args):
        self.timestamp = nsec()
        self.index, self.username, self.flags, self._puplic_key, self.refs = args
        self.private_key = None

    @classmethod
    def config_load(cls, config):
        cls.timeout = config.timeout
        cls.validation = config.validate_key
        return cls

    def _auth_prompt(self):
        if self.flags[0]:
            pw = run_gui(PasswordPromptWindow).get('password', False)
            if pw:
                self.private_key = EnDeCrypt.from_password(pw).mutate(self._puplic_key)
                if self.validation(self.private_key):
                    self.timestamp = nsec()
                else:
                    raise ValueError("Password is incorrect")
            else:
                raise ValueError("Password not provided")

    @property
    def key(self):
        if any([(nsec() - self.timestamp) * (1000 ** -3) > self.timeout, self.private_key is None]):
            self.private_key = None
            self._auth_prompt()
        if not self.validation(self.private_key):
            raise ValueError("Password is incorrect")
        else:
            self.timestamp = nsec()
            return self._puplic_key

    @classmethod
    def create_root(cls):
        dom, user = cls.get_current_domain_and_user()
        pw = input(f"Enter password for {dom}/{user}: ")
        key = EnDeCrypt.from_password(pw).encrypt(b'root')
        
    @classmethod
    def load(cls, ureg: UserRegister):
        dom, user = cls.get_current_domain_and_user()
        return cls(user, Flags(), b'', [])

    def __setattr__(self, key, val):
        if key == 'username':
            if len(val) > 32:
                raise ValueError("Username too long (max 32 bytes UTF-8)")
        super().__setattr__(key, val)

    @staticmethod
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
        
        return f'{domain}/{username}'