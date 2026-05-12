import sounddevice as sd
import numpy as np
import queue
import sys

def list_audio_devices():
    """Returns a list of available input devices."""
    devices = sd.query_devices()
    input_devices = []
    for i, dev in enumerate(devices):
        if dev['max_input_channels'] > 0:
            input_devices.append((i, dev['name']))
    return input_devices

class AudioRecorder:
    def __init__(self, device_id=None, samplerate=16000, channels=1):
        self.device_id = device_id
        self.samplerate = samplerate
        self.channels = channels
        self.audio_queue = queue.Queue()
        self.stream = None

    def _callback(self, indata, frames, time, status):
        """This is called (from a separate thread) for each audio block."""
        if status:
            print(status, file=sys.stderr)
        self.audio_queue.put(indata.copy())

    def start(self):
        self.stream = sd.InputStream(
            device=self.device_id,
            samplerate=self.samplerate,
            channels=self.channels,
            callback=self._callback
        )
        self.stream.start()

    def stop(self):
        if self.stream:
            self.stream.stop()
            self.stream.close()
            self.stream = None

    def get_audio_data(self):
        """Returns all currently buffered audio data as a single numpy array."""
        data_list = []
        while not self.audio_queue.empty():
            data_list.append(self.audio_queue.get())
        
        if not data_list:
            return np.array([], dtype=np.float32)
        
        return np.concatenate(data_list, axis=0)

if __name__ == "__main__":
    print("Available Input Devices:")
    for idx, name in list_audio_devices():
        print(f"{idx}: {name}")
