from OpSec.util.bits import *
from OpSec.EnDeCrypt import *
from json import loads, dumps
from pathlib import Path


class DataFileType:
    slot_size = None
    def __init__(self, data:Bits, ftype: str):
        self.ftype = ftype
        self.data = data
        
    @classmethod
    def load_config(cls, config):
        cls.slot_size = config.slot_size
        return cls
    
    def from_file(self, fpath: Path | str):
        if isinstance(fpath, str):
            fpath = Path(fpath)
        with open(fpath, 'rb') as f:
            data = Bits(f.read())
        if len(data) // 8 > self.slotsize:
            raise ValueError("File is too large for the given slot size.")
        else:
            return fpath.suffix.lsplit('.'), data.to_bytes()
    
    @classmethod
    def from_json_obj(cls, data):
        return cls(Bits(dumps(data).encode('utf-8')), 'json')
    

    def encrypt(self, key: EnDeCrypt):
        self.data = key.encrypt(self.data)
    
    def decrypt(self, key: EnDeCrypt):
        self.data = key.decrypt(self.data)

    def to_json_obj(self):
        return loads(self.data.to_bytes().decode('utf-8'))

    
