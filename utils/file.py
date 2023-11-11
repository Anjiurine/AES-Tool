from . import aes
from . import base64
import sys
import os

def process_single_file(input_file, key, operation):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Input file {input_file} not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {input_file}: {e}")
        sys.exit(1)

    if operation in ['enc', 'encrypt']:
        try:
            ext = os.path.splitext(input_file)[1]
            encoded_data = base64.base64_encode(data) + ext
            encrypted_data = aes.encrypt(key, encoded_data.encode())
            output_file = os.path.splitext(input_file)[0] + '.zaes'

            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            print(f"Encrypted data written to {output_file}")
        except Exception as e:
            print(f"Error encrypting file {input_file}: {e}")
            sys.exit(1)
    elif operation in ['dec', 'decrypt']:
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = aes.decrypt(key, encrypted_data)
            decoded_data, ext = os.path.splitext(decrypted_data.decode())
            decoded_data = base64.base64_decode(decoded_data)
            output_file = input_file.replace('.zaes', '') + ext

            with open(output_file, 'wb') as f:
                f.write(decoded_data)
            print(f"Decrypted data written to {output_file}")
        except Exception as e:
            print(f"Error decrypting file {input_file}: {e}")
            sys.exit(1)
