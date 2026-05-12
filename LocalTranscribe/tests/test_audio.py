import unittest
from audio_capture import list_audio_devices

class TestAudioCapture(unittest.TestCase):
    def test_list_devices(self):
        devices = list_audio_devices()
        self.assertIsInstance(devices, list)
        # We can't guarantee there's a device in a headless environment, 
        # but we can check the return type and structure.
        for dev in devices:
            self.assertEqual(len(dev), 2)
            self.assertIsInstance(dev[0], int)
            self.assertIsInstance(dev[1], str)

if __name__ == "__main__":
    unittest.main()
