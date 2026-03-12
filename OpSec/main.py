from Config import *
from Data import *
from Creds import *
from EnDeCrypt import *
from HardwareToken import *



class KeyBase:
    def __init__(self):
        self.config = ConfigHandle()
        self.userReg = None
        self.dataBase = None
        self.user = None

    def create(self, **kwargs):
        

    