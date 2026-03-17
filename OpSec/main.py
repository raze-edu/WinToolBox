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
        _data = run_gui(NewContainerConfigWindow)
        temp = EnDeCrypt.from_password(_data['supw'])
        user = ('root', [True for _ in range(8)], temp.encrypt(real_key), [0 for _ in range(4)])
        user_register = UserRegister(_data['archive_path'], _data['n_user'], _data['username_length'])
        user_register.write_user(*user)
        Data(_data['archive_name'], _data['archive_path'], _data['n_slots'], _data['slot_size'], _data['n_user'], _data['dataname_length'])
        _data['checksum'] = temp.encrypt(_data['archive_name'])
        
        config = ConfigHandle(**_data)
        config.save()
        return cls(config)

    def create_Session(self, archive, username=None):
        if username is None:
            username = run_gui(LoginWindow)
            if self.users._find_user(username) is None:
                raise ValueError("User not found")
            u = self.users.read_user(username)


        

if __name__ == '__main__':
    temp = DataContainer.create_new()
    print(temp.users)
    temp.data.write_file('test', b'Hello World')
    pass
