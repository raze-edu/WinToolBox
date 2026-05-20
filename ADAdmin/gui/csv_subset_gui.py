import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import os

class CSVSubsetApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSV Subset Creator")
        self.geometry("1000x700")

        self.all_data = []      # List of dicts
        self.headers = []       # List of all headers
        self.active_selection = []  # List of dicts (selected)
        self.active_headers = {}    # dict mapping header -> BooleanVar
        self.applied_filters = []   # List of (column, query) tuples

        self.load_csv()
        if not self.all_data:
            self.destroy()
            return

        self.setup_ui()

    def load_csv(self):
        filepath = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            # Try sniffing the delimiter or default to semicolon/comma
            with open(filepath, 'r', newline='', encoding='utf-8-sig') as f:
                content = f.read(2048)
                f.seek(0)
                dialect = csv.Sniffer().sniff(content) if content.strip() else None
                
                # If sniffer fails, default to common delimiters
                if not dialect:
                    reader = csv.DictReader(f, delimiter=';')
                else:
                    reader = csv.DictReader(f, dialect=dialect)
                
                self.headers = reader.fieldnames if reader.fieldnames else []
                self.all_data = [row for row in reader]
                
                # Initialize all headers as active by default
                for h in self.headers:
                    self.active_headers[h] = tk.BooleanVar(value=True)
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV: {e}")
            self.all_data = []

    def setup_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.setup_search_tab()
        self.setup_column_tab()
        self.setup_selection_tab()

        self.update_tree_visibility()

    def setup_search_tab(self):
        self.search_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.search_tab, text="Search & Filter")

        # Top controls
        ctrl_frame = ttk.Frame(self.search_tab, padding=5)
        ctrl_frame.pack(side="top", fill="x")

        ttk.Label(ctrl_frame, text="Search Column:").pack(side="left", padx=5)
        self.search_col_var = tk.StringVar()
        self.search_col_combo = ttk.Combobox(ctrl_frame, textvariable=self.search_col_var, values=self.headers, state="readonly")
        self.search_col_combo.pack(side="left", padx=5)
        if self.headers:
            self.search_col_combo.current(0)

        ttk.Label(ctrl_frame, text="Search Text:").pack(side="left", padx=5)
        self.search_text_var = tk.StringVar()
        self.search_entry = ttk.Entry(ctrl_frame, textvariable=self.search_text_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.search_text_var.trace_add("write", lambda *args: self.perform_search())

        ttk.Button(ctrl_frame, text="Add Filter", command=self.add_filter).pack(side="left", padx=5)
        ttk.Button(ctrl_frame, text="Reset Filters", command=self.reset_filters).pack(side="left", padx=5)

        # Active Filters Display
        self.filter_status_var = tk.StringVar(value="Active Filters: None")
        ttk.Label(self.search_tab, textvariable=self.filter_status_var, foreground="blue").pack(side="top", fill="x", padx=10)

        # Table
        table_frame = ttk.Frame(self.search_tab)
        table_frame.pack(expand=True, fill="both", padx=5, pady=5)

        self.search_tree = ttk.Treeview(table_frame, columns=self.headers, show="headings")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.search_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.search_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        for col in self.headers:
            self.search_tree.heading(col, text=col)
            self.search_tree.column(col, width=100)

        # Actions
        btn_frame = ttk.Frame(self.search_tab, padding=5)
        btn_frame.pack(side="bottom", fill="x")
        ttk.Button(btn_frame, text="Add Selected to Active Selection", command=self.add_to_selection).pack(side="right")

        self.perform_search()

    def setup_column_tab(self):
        self.column_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.column_tab, text="Column Selection")

        lbl = ttk.Label(self.column_tab, text="Select columns to include in the active selection view and export:", padding=10)
        lbl.pack(side="top", anchor="w")

        canvas = tk.Canvas(self.column_tab)
        scrollbar = ttk.Scrollbar(self.column_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        scrollbar.pack(side="right", fill="y")

        for h in self.headers:
            cb = ttk.Checkbutton(scrollable_frame, text=h, variable=self.active_headers[h], command=self.update_tree_visibility)
            cb.pack(anchor="w", pady=2)

    def setup_selection_tab(self):
        self.selection_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.selection_tab, text="Active Selection")

        # Selection Table only (column manager moved to its own tab)
        table_side = ttk.Frame(self.selection_tab)
        table_side.pack(expand=True, fill="both", padx=10, pady=5)

        self.selection_tree = ttk.Treeview(table_side, columns=self.headers, show="headings")
        vsb = ttk.Scrollbar(table_side, orient="vertical", command=self.selection_tree.yview)
        hsb = ttk.Scrollbar(table_side, orient="horizontal", command=self.selection_tree.xview)
        self.selection_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.selection_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        table_side.grid_columnconfigure(0, weight=1)
        table_side.grid_rowconfigure(0, weight=1)

        for col in self.headers:
            self.selection_tree.heading(col, text=col)
            self.selection_tree.column(col, width=100)

        btn_row = ttk.Frame(table_side, padding=5)
        btn_row.grid(column=0, row=2, sticky="ew")
        ttk.Button(btn_row, text="Remove Selected from Selection", command=self.remove_from_selection).pack(side="left")
        ttk.Button(btn_row, text="Export Subset to CSV", command=self.export_csv).pack(side="right")

    def add_filter(self):
        col = self.search_col_var.get()
        query = self.search_text_var.get().strip()
        if query:
            self.applied_filters.append((col, query))
            self.search_text_var.set("") # Clear for next filter
            self.update_filter_status()
            self.perform_search()

    def reset_filters(self):
        self.applied_filters = []
        self.search_text_var.set("")
        self.update_filter_status()
        self.perform_search()

    def update_filter_status(self):
        if not self.applied_filters:
            self.filter_status_var.set("Active Filters: None")
        else:
            f_str = ", ".join([f"{c}={q}" for c, q in self.applied_filters])
            self.filter_status_var.set(f"Active Filters: {f_str}")

    def perform_search(self):
        # Current UI filter
        curr_query = self.search_text_var.get().lower()
        curr_col = self.search_col_var.get()
        
        # Clear tree
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)

        # Filter: matching query AND not in active selection
        selection_ids = [row.get('Id', row.get('UserPrincipalName', str(row))) for row in self.active_selection]
        
        for row in self.all_data:
            row_id = row.get('Id', row.get('UserPrincipalName', str(row)))
            if row_id in selection_ids:
                continue

            # Apply all persistent filters
            match = True
            for f_col, f_query in self.applied_filters:
                if f_query.lower() not in str(row.get(f_col, "")).lower():
                    match = False
                    break
            
            if not match:
                continue

            # Apply current UI filter
            if curr_query and curr_query not in str(row.get(curr_col, "")).lower():
                continue

            values = [row.get(h, "") for h in self.headers]
            self.search_tree.insert("", "end", values=values, tags=(row_id,))

    def add_to_selection(self):
        selected_items = self.search_tree.selection()
        if not selected_items:
            return

        for item in selected_items:
            row_values = self.search_tree.item(item)['values']
            # Convert values back to dict
            row_dict = dict(zip(self.headers, row_values))
            self.active_selection.append(row_dict)
        
        self.update_selection_table()
        self.perform_search()

    def remove_from_selection(self):
        selected_items = self.selection_tree.selection()
        if not selected_items:
            return

        for item in selected_items:
            row_values = self.selection_tree.item(item)['values']
            row_dict = dict(zip(self.headers, [str(v) for v in row_values]))
            
            # Find and remove from list (comparing based on row content)
            self.active_selection = [r for r in self.active_selection if r != row_dict]

        self.update_selection_table()
        self.perform_search()

    def update_selection_table(self):
        for item in self.selection_tree.get_children():
            self.selection_tree.delete(item)
        
        for row in self.active_selection:
            values = [row.get(h, "") for h in self.headers]
            self.selection_tree.insert("", "end", values=values)

    def update_tree_visibility(self):
        # Update displayed columns dynamically based on active selection checkboxes
        active_cols = [h for h in self.headers if self.active_headers[h].get()]
        self.search_tree.configure(displaycolumns=active_cols)
        self.selection_tree.configure(displaycolumns=active_cols)

    def export_csv(self):
        if not self.active_selection:
            messagebox.showwarning("Warning", "No rows selected for export.")
            return

        export_headers = [h for h in self.headers if self.active_headers[h].get()]
        if not export_headers:
            messagebox.showwarning("Warning", "No columns selected for export.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            initialfile="subset_export.csv"
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=export_headers, extrasaction='ignore', delimiter=';')
                writer.writeheader()
                writer.writerows(self.active_selection)
            
            messagebox.showinfo("Success", f"Successfully exported {len(self.active_selection)} rows to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

if __name__ == "__main__":
    app = CSVSubsetApp()
    app.mainloop()
