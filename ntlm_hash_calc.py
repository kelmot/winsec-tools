import sys
import hashlib

def calculate_ntlm_hash(password):
    # Convert password to UTF-16LE (little-endian Unicode)
    password_bytes = password.encode('utf-16le')
    
    # Create MD4 hash object
    md4 = hashlib.new('md4')
    
    # Update hash with password bytes
    md4.update(password_bytes)
    
    # Get hexadecimal representation of the hash
    ntlm_hash = md4.hexdigest().upper()
    
    return ntlm_hash

if __name__ == "__main__":
    # Check for command-line argument
    if len(sys.argv) != 2:
        print("Usage: python ntlm_hash.py <password>")
        print("Example: python ntlm_hash.py MySecurePassword123")
        sys.exit(1)
    
    # Get password from command-line argument
    password = sys.argv[1]
    
    try:
        # Calculate and print NTLM hash
        result = calculate_ntlm_hash(password)
        print(f"NTLM Hash: {result}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
