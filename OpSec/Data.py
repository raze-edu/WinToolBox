import os
from pathlib import Path

class Data:
    def __init__(self, archive_name: str, archive_path: Path | str, n_slots: int, slot_size: int, n_users: int, name_length: int = 64):
        """
        Initialize the Data object with a fixed-size slot archive.
        """
        self.archive_name = archive_name
        self.archive_path = Path(archive_path) if isinstance(archive_path, str) else archive_path
        self.full_path = self.archive_path / self.archive_name
        
        self.n_slots = n_slots
        self.slot_size = slot_size
        self.n_users = n_users
        self.name_length = name_length
        
        # Calculate sizes
        self.id_bytes = max(1, (max(0, n_slots - 1).bit_length() + 7) // 8)
        
        # Permission bytes: 3 flags + user ID bits
        user_bits = max(0, n_users - 1).bit_length()
        total_perm_bits = 3 + user_bits
        self.perm_bytes = max(1, (total_perm_bits + 7) // 8)
        
        self.index_entry_size = (
            self.id_bytes + 
            self.name_length + 
            1 + 
            (4 * self.perm_bytes)
        )
            
        self.index_block_size = self.n_slots * self.index_entry_size
        self.data_block_size = self.n_slots * self.slot_size
        self.total_size = self.index_block_size + self.data_block_size
        
        self._initialize_archive()

    def _initialize_archive(self):
        if not os.path.exists(self.full_path):
            self.full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.full_path, "wb") as f:
                # Pre-allocate index entries
                # Owner by default set to 111 (7) and rest 0 for id=i. User ID for owner is 0 here.
                default_owner_perm = 7  # user_id 0 << 3 | 7
                default_ext_perm = 0
                
                for i in range(self.n_slots):
                    index_bytes = self._pack_index_entry(
                        entry_id=i, 
                        name="", 
                        data_type=0, 
                        perms=[default_owner_perm, default_ext_perm, default_ext_perm, default_ext_perm]
                    )
                    f.write(index_bytes)
                
                # Pre-allocate data block perfectly to size
                if self.total_size > 0:
                    f.seek(self.total_size - 1)
                    f.write(b'\x00')

    def _pack_index_entry(self, entry_id: int, name: str, data_type: int, perms: list) -> bytes:
        id_b = entry_id.to_bytes(self.id_bytes, 'big')
        
        name_b = name.encode('utf-8')[:self.name_length]
        name_b = name_b.ljust(self.name_length, b'\x00')
        
        type_b = data_type.to_bytes(1, 'big')
        
        perm_b = b''
        for p in perms:
            perm_b += p.to_bytes(self.perm_bytes, 'big')
            
        return id_b + name_b + type_b + perm_b

    def _unpack_index_entry(self, data: bytes) -> dict:
        offset = 0
        
        entry_id = int.from_bytes(data[offset:offset+self.id_bytes], 'big')
        offset += self.id_bytes
        
        name_raw = data[offset:offset+self.name_length]
        name = name_raw.split(b'\x00', 1)[0].decode('utf-8')
        offset += self.name_length
        
        data_type = int.from_bytes(data[offset:offset+1], 'big')
        offset += 1
        
        perms = []
        for _ in range(4):
            p = int.from_bytes(data[offset:offset+self.perm_bytes], 'big')
            perms.append(p)
            offset += self.perm_bytes
            
        return {
            'id': entry_id,
            'name': name,
            'type': data_type,
            'perms': perms
        }

    def _get_index_entry(self, index: int) -> dict:
        with open(self.full_path, "rb") as f:
            f.seek(index * self.index_entry_size)
            data = f.read(self.index_entry_size)
            return self._unpack_index_entry(data)

    def _set_index_entry(self, index: int, entry_id: int, name: str, data_type: int, perms: list):
        with open(self.full_path, "r+b") as f:
            f.seek(index * self.index_entry_size)
            f.write(self._pack_index_entry(entry_id, name, data_type, perms))

    def get_user_permissions(self, name: str|int, user_ids: list) -> dict:
        """
        Returns max permissions for the given user_id over the file `name`.
        """
        if isinstance(name, str):
            entry = self.get_file_info(name)
        elif isinstance(name, int):
            entry = self._get_index_entry(name)
        if not entry:
            return None    
        max_flags = 0
        for p in entry['perms']:
            p_user = p >> 3
            p_flags = p & 0b111
            if p_user in user_ids:
                max_flags |= p_flags
                
        return {
            'read': bool(max_flags & 1),
            'write': bool(max_flags & 2),
            'set_perm': bool(max_flags & 4)
        }

    def find_empty_slot(self) -> int:
        with open(self.full_path, "rb") as f:
            for i in range(self.n_slots):
                f.seek(i * self.index_entry_size)
                data = f.read(self.index_entry_size)
                # Quick check if name is empty without full unpack
                # id takes self.id_bytes
                # The first byte of name would be at offset self.id_bytes.
                # If name is empty, it starts with \x00.
                if data[self.id_bytes] == 0:
                    return i
        return -1

    
    def get_file_info(self, name: str|int) -> dict:
        if not name:
            return None
        if isinstance(name, int):
            return self._get_index_entry(name)
        with open(self.full_path, "rb") as f:
            for i in range(self.n_slots):
                f.seek(i * self.index_entry_size)
                data = f.read(self.index_entry_size)
                # First check name string quickly
                name_raw = data[self.id_bytes:self.id_bytes+self.name_length]
                if name_raw.startswith(name.encode('utf-8') + b'\x00') or name_raw == name.encode('utf-8').ljust(self.name_length, b'\x00'):
                    entry = self._unpack_index_entry(data)
                    return entry
        return None

    def write_file(self, filename: str, content: bytes, data_type: int = 0, perms: list = None):
        """
        Write a file to the archive. If it already exists, replace it in the same slot.
        """
        if isinstance(content, str):
            content = content.encode('utf-8')
            
        if len(content) > self.slot_size:
            raise ValueError(f"Content exceeds slot size of {self.slot_size} bytes")
            
        name_bytes = filename.encode('utf-8')
        if len(name_bytes) > self.name_length:
            raise ValueError(f"Name exceeds max length of {self.name_length} bytes")

        entry = self.get_file_info(filename)
        if entry:
            slot_id = entry['id']
            if perms is None:
                perms = entry['perms']
        else:
            slot_id = self.find_empty_slot()
            if slot_id == -1:
                raise RuntimeError("Archive is full. No empty slots available.")
                
            if perms is None:
                default_owner_perm = 7  # default user 0, flags 111
                perms = [default_owner_perm, 0, 0, 0]

        # Ensure slot_id is set properly in case it was a blank entry
        self._set_index_entry(slot_id, slot_id, filename, data_type, perms)
        
        data_offset = self.index_block_size + slot_id * self.slot_size
        with open(self.full_path, "r+b") as f:
            f.seek(data_offset)
            f.write(content)
            
            padding = self.slot_size - len(content)
            if padding > 0:
                f.write(b'\x00' * padding)

    def read_file(self, filename: str) -> bytes:
        """
        Read a file's content (entire slot).
        """
        entry = self.get_file_info(filename)
        if not entry:
            return None
            
        slot_id = entry['id']
        data_offset = self.index_block_size + slot_id * self.slot_size
        
        with open(self.full_path, "rb") as f:
            f.seek(data_offset)
            return f.read(self.slot_size)
            
    def delete_file(self, filename: str):
        """
        Delete a file by clearing its index entry.
        """
        entry = self.get_file_info(filename)
        if entry:
            slot_id = entry['id']
            # Only reset the index entry, leave data block as is (or zero it out)
            self._set_index_entry(slot_id, slot_id, "", 0, [0, 0, 0, 0])

    def list_files(self, user_ids: list) -> list:
        filenames = []
        with open(self.full_path, "rb") as f:
            for i in range(self.n_slots):
                if self.get_user_permissions(i, user_ids)['read']:
                    f.seek(i * self.index_entry_size)
                    data = f.read(self.index_entry_size)
                    entry = self._unpack_index_entry(data)
                    if entry['name']:
                        filenames.append(entry['name'])
            
        return filenames
