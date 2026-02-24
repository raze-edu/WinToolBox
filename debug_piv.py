from OpSec.HardwareToken import HardwareToken
import os
from bitarray import bitarray as ba

def debug():
    token = HardwareToken()
    
    print("Reading current key...")
    existing_key = token.read_256bit_key()
    if existing_key:
        print(f"Read existing key (length {len(existing_key)} bits)")
    else:
        print("No existing key found or read failed.")

    print("\nGenerating and storing new key...")
    new_key = token.generate_and_store_256bit_key()
    print(f"Stored key: {new_key.hex()}")

    print("\nReading back key in same session...")
    read_back = token.read_256bit_key()
    if read_back:
        bit_bytes = read_back.tobytes()
        print(f"Read back hex: {bit_bytes.hex()}")
        if bit_bytes == new_key:
            print("SUCCESS: Read matches what was written.")
        else:
            print("FAILURE: Read does NOT match what was written.")
    else:
        print("FAILURE: Could not read back key.")

if __name__ == "__main__":
    debug()
