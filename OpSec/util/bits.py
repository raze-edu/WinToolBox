from bitarray import bitarray as ba
from bitarray.util import ba2hex as b2h, hex2ba as h2b, ba2int as b2i, int2ba as i2b
from numpy.random import bytes as rng_b
from time import perf_counter_ns as nsec
import hashlib

class Bits(ba):
    @classmethod
    def from_int(cls, integer:int, length=None):
        if length is None:
            length = integer.bit_length()
        return cls(i2b(integer, length))
    
    @classmethod
    def from_hex(cls, hexadecimal:str, endian='big'):
        if hexadecimal.startswith('0x'):
            hexadecimal = hexadecimal[2:]
        return cls(h2b(hexadecimal, endian))

    @classmethod
    def from_bytes(cls, bytes_:bytes):
        temp = cls()
        temp.frombytes(bytes_)
        return temp

    @classmethod
    def random(cls, n_bytes:int):
        temp = cls()
        temp.frombytes(rng_b(n_bytes))
        return temp

    def to_int(self, slice=None):
        if slice is None:
            return b2i(self)
        return b2i(self[slice])

    def get_part_i(self, part:int, length:int):
        return self[slice(part*length, (part+1)*length)]

    def set_part_i(self, part:int, length:int, value):
        self[slice(part*length, (part+1)*length)] = value



if __name__ == '__main__':
    print(hashlib.sha256(Bits.from_hex(hex(nsec())).tobytes()).digest())
    temp = Bits.from_int(0, 128)
    temp.set_part_i(2, 8, Bits('1111'))
    print(temp)
    t = Bits.random(32)
    print(t)
    print(t.tobytes())