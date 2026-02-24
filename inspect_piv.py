from OpSec.HardwareToken import HardwareToken
import os
from bitarray import bitarray as ba

def inspect_piv():
    token = HardwareToken()
    try:
        session = token._get_piv_session()
        print(f"Connected to YubiKey. Checking object 0x{token.key_object_id:06X}...")
        
        # Try to read without PIN first
        try:
            data = session.get_object(token.key_object_id)
            print(f"Read without PIN: {len(data)} bytes" if data else "No data without PIN")
        except Exception as e:
            print(f"Read without PIN failed: {e}")
            
        # Try with PIN
        try:
            session.verify_pin(token.pin)
            data = session.get_object(token.key_object_id)
            if data:
                print(f"Read with PIN: {len(data)} bytes")
                print(f"Data hex: {data.hex()}")
            else:
                print("No data with PIN")
        except Exception as e:
            print(f"Read with PIN failed: {e}")
            
    except Exception as e:
        print(f"Session failed: {e}")

if __name__ == "__main__":
    inspect_piv()
