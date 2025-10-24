import sys
import binascii

def binary_sid_to_string(sid_bytes):
    # Ensure input is bytes; if hex string, convert it
    if isinstance(sid_bytes, str):
        try:
            # Remove optional b'' prefix/suffix from hex string
            sid_bytes = sid_bytes.strip().replace("b'", "").replace("'", "")
            sid_bytes = binascii.unhexlify(sid_bytes)
        except binascii.Error:
            raise ValueError("Invalid hex string provided")
    elif not isinstance(sid_bytes, bytes):
        raise ValueError("Input must be a bytes object or hex string")

    # Check minimum length (8 bytes: 1 for revision, 1 for subauthority count, 6 for identifier authority)
    if len(sid_bytes) < 8:
        raise ValueError("SID binary data is too short")

    # Parse SID structure
    revision = sid_bytes[0]
    subauthority_count = sid_bytes[1]

    # Extract identifier authority (6 bytes, big-endian)
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

    # Calculate expected length: 8 bytes (header) + 4 bytes per subauthority
    expected_length = 8 + subauthority_count * 4
    if len(sid_bytes) != expected_length:
        raise ValueError(f"Invalid SID length: expected {expected_length} bytes, got {len(sid_bytes)}")

    
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

   
    subauthorities = []
    for i in range(subauthority_count):
        start = 8 + i * 4
        subauthority = int.from_bytes(sid_bytes[start:start+4], byteorder='little')
        subauthorities.append(str(subauthority))

  
    sid_string = f"S-{revision}-{identifier_authority}-{'-'.join(subauthorities)}"
    return sid_string

if __name__ == "__main__":
    
    if len(sys.argv) != 2:
        print("Usage: python convert_sid.py <binary_sid>")
        print("Example: python convert_sid.py \"0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000\"")
        sys.exit(1)

    
    input_sid = sys.argv[1]
    try:
        result = binary_sid_to_string(input_sid)
        print(f"Readable SID: {result}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
