import time
import sys
from audio_capture import list_audio_devices, AudioRecorder
from transcriber import GemmaTranscriber

def main():
    print("--- Local Transcribe Tool (Gemma 4) ---")
    
    # 1. Device Selection
    devices = list_audio_devices()
    if not devices:
        print("No input devices found.")
        return

    print("\nAvailable Input Devices:")
    for idx, name in devices:
        print(f"[{idx}] {name}")

    try:
        selection = int(input("\nSelect device ID: "))
        if selection not in [d[0] for d in devices]:
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a valid number.")
        return

    # 2. Initialize Transcriber
    try:
        transcriber = GemmaTranscriber()
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    # 3. Start Recording
    recorder = AudioRecorder(device_id=selection)
    print("\nStarting recording... Press Ctrl+C to stop and transcribe.")
    recorder.start()

    try:
        while True:
            time.sleep(1)
            # Optional: Real-time transcription could be added here by processing chunks
    except KeyboardInterrupt:
        print("\nStopping recording...")
        recorder.stop()

    # 4. Process and Transcribe
    print("Processing audio...")
    audio_data = recorder.get_audio_data()
    
    if len(audio_data) == 0:
        print("No audio captured.")
        return

    # Flatten audio if it's stereo (though we requested mono)
    if len(audio_data.shape) > 1:
        audio_data = audio_data.flatten()

    transcript = transcriber.transcribe(audio_data)
    
    print("\n--- Transcript ---")
    print(transcript)
    print("------------------")

if __name__ == "__main__":
    main()
