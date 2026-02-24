import os
import struct

class Data:
    def __init__(self, archive_path, slot_size=4096):
        """
        Initialize the Data object with a path to a custom fixed-size slot archive.
        :param archive_path: Path to the archive file.
        :param slot_size: Fixed size for the data section of each slot.
        """
        self.archive_path = archive_path
        self.slot_size = slot_size
        self.header_size = 128  # 124 bytes for name, 4 bytes for actual size
        self.full_slot_size = self.header_size + self.slot_size
        
        if not os.path.exists(self.archive_path):
            with open(self.archive_path, "wb") as f:
                pass

    def _get_slots_count(self):
        if not os.path.exists(self.archive_path):
            return 0
        size = os.path.getsize(self.archive_path)
        return size // self.full_slot_size

    def _find_slot(self, filename):
        """
        Scans the archive for a slot with the given filename.
        Returns (offset, actual_size) if found, or (None, None).
        """
        if not os.path.exists(self.archive_path):
            return None, None

        with open(self.archive_path, "rb") as f:
            slot_idx = 0
            while True:
                header_data = f.read(self.header_size)
                if not header_data or len(header_data) < self.header_size:
                    break
                
                # Unpack: 124s for name, I for uint32 size
                name_bytes, actual_size = struct.unpack("<124sI", header_data)
                name = name_bytes.decode('utf-8').split('\x00', 1)[0]
                
                if name == filename:
                    return slot_idx * self.full_slot_size, actual_size
                
                # Skip the data part
                f.seek(self.slot_size, os.SEEK_CUR)
                slot_idx += 1
        return None, None

    def _find_empty_slot(self):
        """
        Finds the first empty slot or returns the offset at the end of the file.
        """
        if not os.path.exists(self.archive_path):
            return 0

        with open(self.archive_path, "rb") as f:
            slot_idx = 0
            while True:
                header_data = f.read(self.header_size)
                if not header_data or len(header_data) < self.header_size:
                    break
                
                name_bytes, _ = struct.unpack("<124sI", header_data)
                name = name_bytes.decode('utf-8').split('\x00', 1)[0]
                
                if not name: # Empty slot
                    return slot_idx * self.full_slot_size
                
                f.seek(self.slot_size, os.SEEK_CUR)
                slot_idx += 1
        
        return slot_idx * self.full_slot_size

    def write_file(self, filename, content):
        """
        Write a single file's content to the archive in-place.
        :param filename: Name of the file within the archive (max 123 chars).
        :param content: Byte content to write (max slot_size).
        """
        if isinstance(content, str):
            content = content.encode('utf-8')

        if len(content) > self.slot_size:
            raise ValueError(f"Content exceeds slot size of {self.slot_size} bytes")
        
        if len(filename.encode('utf-8')) >= 124:
            raise ValueError("Filename too long (max 123 bytes UTF-8)")

        # Find existing slot or a new one
        offset, _ = self._find_slot(filename)
        if offset is None:
            offset = self._find_empty_slot()

        # Prepare header
        name_bytes = filename.encode('utf-8').ljust(124, b'\x00')
        header = struct.pack("<124sI", name_bytes, len(content))
        
        # Prepare data (pad with nulls to stay fixed size)
        data_padding = b'\x00' * (self.slot_size - len(content))
        
        # Write in-place
        with open(self.archive_path, "r+b" if os.path.exists(self.archive_path) else "wb") as f:
            f.seek(offset)
            f.write(header)
            f.write(content)
            f.write(data_padding)

    def read_file(self, filename):
        """
        Read a single file's content from the archive.
        :param filename: Name of the file within the archive.
        :return: Byte content of the file, or None if not found.
        """
        offset, actual_size = self._find_slot(filename)
        if offset is None:
            return None

        with open(self.archive_path, "rb") as f:
            # Skip header to get to data
            f.seek(offset + self.header_size)
            return f.read(actual_size)

    def list_files(self):
        """
        List all filenames within the archive.
        :return: List of strings.
        """
        if not os.path.exists(self.archive_path):
            return []
        
        filenames = []
        with open(self.archive_path, "rb") as f:
            while True:
                header_data = f.read(self.header_size)
                if not header_data or len(header_data) < self.header_size:
                    break
                
                name_bytes, _ = struct.unpack("<124sI", header_data)
                name = name_bytes.decode('utf-8').split('\x00', 1)[0]
                if name:
                    filenames.append(name)
                
                f.seek(self.slot_size, os.SEEK_CUR)
        return filenames

if __name__ == "__main__":
    # Example usage:
    # arch = Data("vault.bin", slot_size=1024)
    # arch.write_file("test.txt", "In-place update test")
    # print(arch.read_file("test.txt"))
    pass
