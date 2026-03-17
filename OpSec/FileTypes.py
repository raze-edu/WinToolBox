from OpSec.util.bits import *
from json import loads, dumps
from pathlib import Path


class FileType:
    def __init__(self, slotsize: int):
        self.slotsize = slotsize
        self.types = {
            
        
        }
    
    def from_file(self, fpath: Path | str):
        if isinstance(fpath, str):
            fpath = Path(fpath)
        with open(fpath, 'rb') as f:
            data = Bits(f.read())
        if len(data) // 8 > self.slotsize:
            raise ValueError("File is too large for the given slot size.")
        else:
            return fpath.suffix.lsplit('.'), data.to_bytes()
        