import tkinter as tk
from tkinter import filedialog, simpledialog, ttk
from pathlib import Path
try:
    from Config import ConfigHandle
except ImportError:
    pass
class Global:
    data = {}


class NewContainerConfigWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("New Container config")
        self.geometry("400x400")
        
        # Configure scaling
        self.columnconfigure(1, weight=1)

        # String and Int Variables for inputs
        self.archive_name_var = tk.StringVar()
        self.archive_path_var = tk.StringVar()
        self.slot_size_var = tk.IntVar(value=4096)
        self.n_slots_var = tk.IntVar(value=4096)
        self.n_users_var = tk.IntVar(value=32)
        self.dataname_length_var = tk.IntVar(value=32)
        self.username_length_var = tk.IntVar(value=32)
        self.timeout_var = tk.IntVar(value=600)
        self.supw_var = tk.StringVar()

        # Layout mapping
        row = 0

        # archive_name: str
        tk.Label(self, text="archive_name:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.archive_name_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # archive_path: Path
        tk.Label(self, text="archive_path:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        path_frame = tk.Frame(self)
        path_frame.grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        path_frame.columnconfigure(0, weight=1)
        tk.Entry(path_frame, textvariable=self.archive_path_var).grid(row=0, column=0, sticky="ew")
        tk.Button(path_frame, text="Browse...", command=self.browse_path).grid(row=0, column=1, padx=(5, 0))
        row += 1

        # slot_size: int
        tk.Label(self, text="slot_size:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.slot_size_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # n_slots: int
        tk.Label(self, text="n_slots:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.n_slots_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # n_users: int
        tk.Label(self, text="n_users:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.n_users_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # dataname_length: int
        tk.Label(self, text="dataname_length:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.dataname_length_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # username_length: int
        tk.Label(self, text="username_length:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.username_length_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # timeout: int
        tk.Label(self, text="timeout:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.timeout_var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # supw: str
        tk.Label(self, text="supw:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        tk.Entry(self, textvariable=self.supw_var, show="*").grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        row += 1

        # Buttons Frame
        button_frame = tk.Frame(self)
        button_frame.grid(row=row, column=0, columnspan=2, pady=15)
        
        tk.Button(button_frame, text="create", command=self.create, width=10).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="cancle", command=self.cancle, width=10).pack(side=tk.LEFT, padx=10)

    def browse_path(self):
        directory = filedialog.askdirectory(title="Select Archive Path")
        if directory:
            self.archive_path_var.set(directory)

    def __dict__(self):
        return {
            'archive_name': self.archive_name_var.get(),
            'archive_path': self.archive_path_var.get(),
            'slot_size': self.slot_size_var.get(),
            'n_slots': self.n_slots_var.get(),
            'n_user': self.n_users_var.get(),
            'dataname_length': self.dataname_length_var.get(),
            'username_length': self.username_length_var.get(),
            'timeout': self.timeout_var.get(),
            'supw': self.supw_var.get()
        }

    def create(self):
        Global.data.update(self.__dict__())
        print(Global.data)
        self.destroy()

    def cancle(self):
        self.destroy()


class LoginWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Login")
        self.geometry("300x200")

        self.columnconfigure(1, weight=1)

        try:
            archive_names = list(ConfigHandle.config_obj.keys())
        except NameError:
            archive_names = []
            
        options = ["create new"] + archive_names

        self.archive_var = tk.StringVar(value="create new")
        
        row = 0
        tk.Label(self, text="Archive:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
        self.archive_dropdown = ttk.Combobox(self, textvariable=self.archive_var, values=options, state="readonly")
        self.archive_dropdown.grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        
        row += 1
        
        self.win_login_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self, text="use Windows Login", variable=self.win_login_var).grid(row=row, column=0, columnspan=2, pady=5)
        
        row += 1
        
        tk.Button(self, text="Connect", command=self.connect).grid(row=row, column=0, columnspan=2, pady=15)

    def connect(self):
        archive = self.archive_var.get()
        win_login = self.win_login_var.get()
        
        if archive == "create new":
            self.withdraw()
            new_win = NewContainerConfigWindow(self.master)
            self.master.wait_window(new_win)
            self.destroy()
        else:
            if not win_login:
                username = simpledialog.askstring("Username", "Please enter username:")
                if username:
                    Global.data['archive_name'] = archive
                    Global.data['use_windows_login'] = win_login
                    Global.data['username'] = username
                    self.destroy()
            else:
                Global.data['archive_name'] = archive
                Global.data['use_windows_login'] = win_login
                self.destroy()

def run_gui(window):
    root = tk.Tk()
    root.withdraw() # Hide the root window
    app = window(root)
    root.wait_window(app)
    try:
        root.destroy()
    except tk.TclError:
        pass
    return Global.data

if __name__ == "__main__":
    print(run_gui(LoginWindow))
    pass