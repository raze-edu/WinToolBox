from json import dumps, loads
from pathlib import Path

ROOT = Path().cwd()

class ConfigHandle:
    __slots__ = 'name', 'blocksize', 'blocks', 'path'
    def __init__(self, **kwargs):
        [super().__setattr__(slot, kwargs.get(slot)) for slot in self.__slots__]
        pass

    @property
    def configpath(self):
        return Path(ROOT, 'config.json')

    @property
    def config_obj(self):
        return loads(open(self.configpath, 'r').read())
    
    @property
    def configs(self):
        return [key for key in self.config_obj.keys()]
        
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