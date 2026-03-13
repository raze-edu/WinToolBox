from json import dumps, loads
from pathlib import Path

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
        
    def __setattr__(self, key, val):
        if key == 'archive_path':
            if not isinstance(val, Path):
                if isinstance(val, str):
                    val = Path(val)
                if isinstance(val, list):
                    val = Path(*val)
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
