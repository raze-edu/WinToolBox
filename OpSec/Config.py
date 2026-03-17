from json import dumps, loads
from hashlib import sha256
from pathlib import Path
from util.bits import Bits
from Data import Data
from Users import UserRegister

ROOT = Path().cwd()

class ConfigHandle:
    config_path = Path(ROOT, 'OpSec', 'config.json')
    try:
        config_obj = loads(open(config_path, 'r').read())
    except:
        config_obj = {}
    __slots__ = 'archive_name', 'archive_path', 'slot_size', 'n_slots', 'n_user', 'dataname_length', 'username_length', 'timeout', 'checksum'
    def __init__(self, **kwargs):
        default = dict(slot_size=4096, n_slots=4096, n_users=16, dataname_length=32, timeout=300)
        [super().__setattr__(slot, kwargs.get(slot, default.get(slot))) for slot in self.__slots__]
        if isinstance(self.archive_path, str):
            self.archive_path = Path(self.archive_path)
        if isinstance(self.archive_path, list):
            self.archive_path = Path(*self.archive_path)
        if isinstance(self.checksum, str):
            self.checksum = Bits(self.checksum)
        if isinstance(self.checksum, bytes):
            self.checksum = Bits.from_bytes(self.checksum)

    @property
    def configs(self):
        return [key for key in self.config_obj.keys()]

    def validate_key(self, key):
        return key.decrypt(self.checksum).decode('utf-8') == self.archive_name

    @property
    def data(self):
        return Data.config_load(self)

    @property
    def users(self):
        return UserRegister.config_load(self)
    
    def get_puplic_key(self, name):
        return sha256(name.encode('utf-8')).hexdigest()
    
    def __setattr__(self, key, val):
        if key == 'archive_path':
            if not isinstance(val, Path):
                if isinstance(val, str):
                    val = Path(val)
                if isinstance(val, list):
                    val = Path(*val)
        elif key == 'checksum':
            if isinstance(val, str):
                val = Bits(val)
            elif isinstance(val, bytes):
                val = Bits.from_bytes(val)
        super().__setattr__(key, val)

    def save(self):
        # if not exists create empty config file
        if not self.config_path.exists():
            with open(self.config_path, 'w') as f:
                f.write(dumps({}))
        # load the config file 
        temp = self.config_obj
        data = {'archive_name': self.archive_name, 
                'archive_path': self.archive_path.parts, 
                'slot_size': self.slot_size, 
                'n_slots': self.n_slots, 
                'n_user': self.n_user, 
                'dataname_length': self.dataname_length, 
                'username_length': self.username_length,
                'timeout': self.timeout,
                'checksum': ''.join([str(t) for t in self.checksum])}
        temp.update({self.archive_name: data})
        with open(self.config_path, 'w') as f:
            f.write(dumps(temp, indent=4))

    def remove(self, name):
        temp = self.config_obj
        if name in temp:
            del temp[name]
            with open(self.config_path, 'w') as f:
                f.write(dumps(temp, indent=4))

    @classmethod
    def load(cls, name):
        if cls.config_obj.get(name, False):
            return cls(**cls.config_obj[name])
        else:
            raise ValueError(f"Config '{name}' not found")
