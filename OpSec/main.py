from Config import *
from Data import *
from Users import *
from Creds import *
from EnDeCrypt import *
from HardwareToken import *
from GUI import *


class DataContainer:
    def __init__(self, config: ConfigHandle):
        self.config = config
        
    @property
    def data(self):
        return self.config.data
    
    @property
    def users(self):
        return self.config.users

    @classmethod
    def create_new(cls):
        real_key = os.urandom(32)
        data = run_gui(NewContainerConfigWindow)
        temp = EnDeCrypt.from_password(data['supw'])
        user = ('root', temp.encrypt(real_key), [True for _ in range(8)], [0 for _ in range(4)])
        user_register = UserRegister(data['archive_name'], data['archive_path'], data['username_length'])
        user_register.create(user)
        data = Data(data['archive_name'], data['archive_path'], data['n_slots'], data['slot_size'], data['n_users'], data['dataname_length'])
        data['check_sum'] = temp.encrypt(data['archive_name'])
        config = ConfigHandle(data['archive_name'], data['archive_path'], data['n_slots'], data['slot_size'], data['n_users'], data['dataname_length'], data['username_length'], data['timeout'], temp.encrypt(real_key))
        config.save()
        return cls(config)



if __name__ == '__main__':
    temp = DataContainer.create_new()
    print(temp.users)
    temp.data.write_file('test', b'Hello World')
    