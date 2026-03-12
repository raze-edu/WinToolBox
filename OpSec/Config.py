from json import dumps, loads
from hashlib import sha256
from pathlib import Path

ROOT = Path().cwd()

class ConfigHandle(dict):
    def __init__(self):
        super().__init__(**self.config_obj)

    @property
    def configpath(self):
        return Path(ROOT, 'config.json')

    @property
    def config_obj(self):
        return loads(open(self.configpath, 'r').read())

    @staticmethod
    def read_path(path:list):
        return Path(*path)

    @staticmethod
    def write_path(path:Path):
        return list(path.parts)

    @property
    def configs(self):
        return [key for key in self.config_obj.keys()]
    
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
        if key == 'path':
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
        temp.update({self.name:{'name':self.name, 'blocksize': self.blocksize, 'blocks': self.blocks, 'path': self.path.parts}})

print(Path(Path().cwd(), 'config.json'))