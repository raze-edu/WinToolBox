import tkinter as tk
from tkinter import filedialog
from pathlib import Path

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
            'n_users': self.n_users_var.get(),
            'dataname_length': self.dataname_length_var.get(),
            'username_length': self.username_length_var.get(),
            'timeout': self.timeout_var.get(),
            'supw': self.supw_var.get()
        }
    def create(self):
        # Empty method for now
        pass

    def cancle(self):
        self.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() # Hide the root window
    app = NewContainerConfigWindow(root)
    app.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
