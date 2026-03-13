from json import dumps, loads
from hashlib import sha256
from pathlib import Path
from util.bits import Bits

ROOT = Path().cwd()

class ConfigHandle:
    config_path = Path(ROOT, 'config.json')
    config_obj = loads(open(Path(ROOT, 'config.json'), 'r').read())
    __slots__ = 'archive_name', 'archive_path', 'slot_size', 'n_slots', 'n_users', 'name_length', 'username_len', 'timeout', 'checksum'
    def __init__(self, **kwargs):
        default = dict(slot_size=4096, n_slots=4096, n_users=16, name_length=32, timeout=300)
        [super().__setattr__(slot, kwargs.get(slot, default.get(slot))) for slot in self.__slots__]
    
    @property
    def configs(self):
        return [key for key in self.config_obj.keys()]

    def validate_key(self, key):
        return key.decrypt(self.key_validation).decode('utf-8') == self.archive_name

    def get_users_config(self, name):
        if (config := self.get(name, False)):
            return self.read_path(config['path']), config['n_user']
        return None

    def get_data_config(self, name):
        if (config := self.get(name, False)):
            return self.read_path(config['path']), config['n_slots'], config['slot_size'], config['n_users'], config['name_length']
        return None

    def get_local_secret_part(self, name):
        if (config := self.get(name, False)):
            return config['secret']
        return None

    def get_puplic_key(self, name):
        return sha256(name.encode('utf-8')).hexdigest()
    
    def __setattr__(self, key, val):
        if key == 'archive_path':
            if not isinstance(val, Path):
                if isinstance(val, str):
                    val = Path(val)
                if isinstance(val, list):
                    val = Path(*val)
        elif key == 'key_validation':
            if isinstance(val, str):
                val = Bits(val)
            elif isinstance(val, bytes):
                val = Bits.from_bytes(val)
        super().__setattr__(key, val)

    def create(self):
        if not self.configpath.exists():
            with open(self.configpath, 'w') as f:
                f.write(dumps({}))
        temp = self.config_obj
        data = {'archive_name': self.archive_name, 
                'archive_path': self.archive_path.parts, 
                'slot_size': self.slot_size, 
                'n_slots': self.n_slots, 
                'n_users': self.n_users, 
                'name_length': self.name_length, 
                'timeout': self.timeout,
                'checksum': self.checksum}
        temp.update({self.archive_name: data})
        with open(self.configpath, 'w') as f:
            f.write(dumps(temp, indent=4))

    def remove(self, name):
        temp = self.config_obj
        if name in temp:
            del temp[name]
            with open(self.configpath, 'w') as f:
                f.write(dumps(temp, indent=4))

    @classmethod
    def load(cls, name):
        if cls.config_obj.get(name, False):
            return cls(**cls.config_obj[name])
        else:
            raise ValueError(f"Config '{name}' not found")
