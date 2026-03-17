import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import os

class EmployeeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Employee Viewer")
        self.geometry("600x400")

        self.data = []  # List of dicts
        self.filtered_data = [] # List of dicts for export

        self.unique_titles = set()
        self.unique_departments = set()
        self.unique_licenses = set()
        
        self.title_vars = {}
        self.dept_vars = {}
        self.license_vars = {}

        self.load_csv()

        # Exit if no data was loaded (e.g. user canceled dialog)
        if not self.data:
            self.destroy()
            return

        self.create_widgets()
        self.update_list()

    def load_csv(self):
        filepath = filedialog.askopenfilename(
            title="Select Employee CSV",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(filepath, 'r', newline='', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                self.headers = reader.fieldnames
                if not self.headers:
                    raise ValueError("CSV structure is empty")
                
                for row in reader:
                    self.data.append(row)
                    
                    title = row.get('Title')
                    if title and title.strip():
                        self.unique_titles.add(title.strip())

                    dept = row.get('Department')
                    if dept and dept.strip():
                        self.unique_departments.add(dept.strip())
                        
                    license_val = row.get('Licenses')
                    if license_val and license_val.strip():
                        self.unique_licenses.add(license_val.strip())
                        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read CSV:\n{e}")

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        # Bind tab change event to dynamically update checkboxes
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # Main Tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Main")

        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(side=tk.TOP, pady=5, fill=tk.X, padx=10)

        self.export_btn = ttk.Button(btn_frame, text="Export Filtered CSV", command=self.export_csv)
        self.export_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(btn_frame, text="Clear Filters", command=self.clear_filters)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)

        self.listbox_frame = ttk.Frame(self.main_frame)
        self.listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.scrollbar = ttk.Scrollbar(self.listbox_frame, orient=tk.VERTICAL)
        self.listbox = tk.Listbox(self.listbox_frame, yscrollcommand=self.scrollbar.set, font=("TkDefaultFont", 10))
        self.scrollbar.config(command=self.listbox.yview)

        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Title Tab
        self.title_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.title_frame, text="Title")
        self.title_container = self.create_scrollable_container(self.title_frame)

        # Department Tab
        self.dept_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dept_frame, text="Department")
        self.dept_container = self.create_scrollable_container(self.dept_frame)

        # Licenses Tab
        self.license_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.license_frame, text="Licenses")
        self.license_container = self.create_scrollable_container(self.license_frame)

    def create_scrollable_container(self, parent_frame):
        canvas = tk.Canvas(parent_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return scrollable_frame

    def get_current_available_values(self):
        """Calculates which unique values are still available based on currently active filters (for cross-filtering)"""
        selected_titles = {title for title, var in self.title_vars.items() if var.get()}
        selected_depts = {dept for dept, var in self.dept_vars.items() if var.get()}
        selected_licenses = {lic for lic, var in self.license_vars.items() if var.get()}

        avail_titles = set()
        avail_depts = set()
        avail_licenses = set()

        # To know what's available in "Title", we filter the original data using ONLY Dept and Licenses filters.
        for row in self.data:
            t = (row.get('Title') or '').strip()
            d = (row.get('Department') or '').strip()
            l = (row.get('Licenses') or '').strip()

            t_match = (not selected_titles) or (t in selected_titles) or ("(Empty)" in selected_titles and not t)
            d_match = (not selected_depts) or (d in selected_depts) or ("(Empty)" in selected_depts and not d)
            l_match = (not selected_licenses) or (l in selected_licenses) or ("(Empty)" in selected_licenses and not l)

            if d_match and l_match:
                avail_titles.add(t if t else "(Empty)")
            if t_match and l_match:
                avail_depts.add(d if d else "(Empty)")
            if t_match and d_match:
                avail_licenses.add(l if l else "(Empty)")

        return avail_titles, avail_depts, avail_licenses

    def on_tab_changed(self, event):
        tab_id = self.notebook.select()
        tab_name = self.notebook.tab(tab_id, "text")

        avail_titles, avail_depts, avail_licenses = self.get_current_available_values()

        if tab_name == "Title":
            self.repopulate_tab(self.title_container, sorted(list(avail_titles)), self.title_vars)
        elif tab_name == "Department":
            self.repopulate_tab(self.dept_container, sorted(list(avail_depts)), self.dept_vars)
        elif tab_name == "Licenses":
            self.repopulate_tab(self.license_container, sorted(list(avail_licenses)), self.license_vars)

    def repopulate_tab(self, parent, items, var_dict):
        # Clear existing checkboxes from view
        for widget in parent.winfo_children():
            widget.destroy()

        # Generate checkboxes for available items
        for item in items:
            # Re-use existing variables if they were already selected, otherwise create new
            if item not in var_dict:
                var_dict[item] = tk.BooleanVar(value=False)
            
            cb = ttk.Checkbutton(
                parent, 
                text=item, 
                variable=var_dict[item], 
                command=self.update_list
            )
            cb.pack(anchor=tk.W, padx=5, pady=2)

    def update_list(self):
        self.listbox.delete(0, tk.END)
        self.filtered_data = []
        
        selected_titles = {title for title, var in self.title_vars.items() if var.get()}
        selected_depts = {dept for dept, var in self.dept_vars.items() if var.get()}
        selected_licenses = {lic for lic, var in self.license_vars.items() if var.get()}
        
        for row in self.data:
            title = row.get('Title', '')
            title = title.strip() if title else ''
            
            dept = row.get('Department', '')
            dept = dept.strip() if dept else ''
            
            license_val = row.get('Licenses', '')
            license_val = license_val.strip() if license_val else ''
            
            # Match logic: if nothing selected, ignore filter
            title_match = (not selected_titles) or (title in selected_titles) or ("(Empty)" in selected_titles and title == "")
            dept_match = (not selected_depts) or (dept in selected_depts) or ("(Empty)" in selected_depts and dept == "")
            license_match = (not selected_licenses) or (license_val in selected_licenses) or ("(Empty)" in selected_licenses and license_val == "")
            
            if title_match and dept_match and license_match:
                self.filtered_data.append(row)
                display_name = row.get('Display name', 'Unknown')
                self.listbox.insert(tk.END, display_name)

    def clear_filters(self):
        # Reset all variables
        for var in self.title_vars.values():
            var.set(False)
        for var in self.dept_vars.values():
            var.set(False)
        for var in self.license_vars.values():
            var.set(False)
        
        # Select the main tab
        self.notebook.select(self.main_frame)
        self.update_list()

    def export_csv(self):
        if not self.filtered_data:
            messagebox.showinfo("Export", "No entries to export.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export Filtered CSV",
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                writer.writeheader()
                writer.writerows(self.filtered_data)
            messagebox.showinfo("Export", "Export successful!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

def run():
    app = EmployeeApp()
    app.mainloop()

if __name__ == "__main__":
    run()
