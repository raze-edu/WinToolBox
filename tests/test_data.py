import os
import sys
import unittest
import shutil

# Add root to path so we can import OpSec
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from OpSec.Data import Data

class TestData(unittest.TestCase):
    def setUp(self):
        self.test_archive = "test_archive.bin"
        self.slot_size = 1024
        self.data_manager = Data(self.test_archive, slot_size=self.slot_size)
        self.filename = "test_file.txt"
        self.content = b"This is a test content."

    def tearDown(self):
        if os.path.exists(self.test_archive):
            os.remove(self.test_archive)

    def test_create_and_write(self):
        self.data_manager.write_file(self.filename, self.content)
        self.assertTrue(os.path.exists(self.test_archive))
        
        # Verify it exists in listing
        files = self.data_manager.list_files()
        self.assertIn(self.filename, files)

    def test_read_file(self):
        self.data_manager.write_file(self.filename, self.content)
        read_content = self.data_manager.read_file(self.filename)
        self.assertEqual(self.content, read_content)

    def test_inplace_overwrite_size(self):
        self.data_manager.write_file(self.filename, self.content)
        initial_size = os.path.getsize(self.test_archive)
        
        new_content = b"Updated content, should be at same offset."
        self.data_manager.write_file(self.filename, new_content)
        
        final_size = os.path.getsize(self.test_archive)
        self.assertEqual(initial_size, final_size, "Archive size should not change on overwrite")
        
        read_content = self.data_manager.read_file(self.filename)
        self.assertEqual(new_content, read_content)

    def test_exceed_size_raises(self):
        too_big = b"X" * (self.slot_size + 1)
        with self.assertRaises(ValueError):
            self.data_manager.write_file("big.txt", too_big)

    def test_multiple_slots(self):
        file1 = "file1.dat"
        file2 = "file2.dat"
        self.data_manager.write_file(file1, b"data1")
        size1 = os.path.getsize(self.test_archive)
        
        self.data_manager.write_file(file2, b"data2")
        size2 = os.path.getsize(self.test_archive)
        
        self.assertEqual(size2, size1 + self.data_manager.full_slot_size)
        self.assertIn(file1, self.data_manager.list_files())
        self.assertIn(file2, self.data_manager.list_files())

if __name__ == '__main__':
    unittest.main()
