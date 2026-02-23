from pathlib import Path

class CSVHandler:
    def __init__(self, file_path: str, separator: str = ","):
        self.head = []
        self.data = []
        self.file_path = Path(file_path)
        self.separator = separator
        self.read_csv()

    @staticmethod
    def splitter(line: str, separator: str = ",") -> list[str]:
        """
        Splits a line by the separator.
        """
        arr, first, encapsuled = [], 0, False
        for i in range(len(line)):
            if line[i] == '"':
                encapsuled = not encapsuled
            elif line[i] == separator and not encapsuled:
                arr.append(line[first:i].strip(f'"{separator}"'))
                first = i + 1
        arr.append(line[first:].strip(f'"{separator}"'))
        return arr

    @staticmethod
    def search_entry(entry, col, search):
        if col is None:
            return search in entry 
        else:
            return entry[col] == search

    @staticmethod
    def get_row(row, get):
        if get is None:
            return row
        return row[get]

    def load_csv(self, file_path: str):
        self.file_path = Path(file_path)
        self.read_csv()

    def read_csv(self):
        """
        Reads a CSV file and returns a list of dictionaries.
        """
        with open(self.file_path, 'r', encoding='utf-8') as f:
            lines = f.read().split('\n')
            self.head = self.splitter(lines[0], self.separator)
            self.data = [self.splitter(line, self.separator) for line in lines[1:] if len(self.splitter(line, self.separator)) == len(self.head)]

    def __list__(self):
        return [{k: v for k, v in zip(self.head, row)} for row in self.data]

    def __iter__(self):
        return iter(self.__list__())

    def get_column_sets(self):
        return {self.head[i]: list(set(d[i] for d in self.data)) for i in range(len(self.head))}

    def get_column_index(self, col):
        if isinstance(col, str):
            col = self.head.index(col)
        if isinstance(col, int):
            if col < len(self.head):
                return col
            raise IndexError("Column index out of range")

    def find_row(self, search, col=None, get=None):
        arr = []
        for item in self.data:
            if self.search_entry(item, self.get_column_index(col), search):
                arr.append(self.get_row(item, self.get_column_index(get)))
        return arr


if __name__ == "__main__":
    temp = CSVHandler('exportUsers_2026-2-22.csv')
    [print(line) for line in temp.get_column_sets().items()]
    print(temp.find_row('Guest', col='userType', get='displayName'))