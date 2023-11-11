import os
from . import aes
from . import base64

def process_directory(input_dir, output_dir, key, operation):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            input_file = os.path.join(root, file)
            relative_path = os.path.relpath(input_file, input_dir)
            output_file = os.path.join(output_dir, relative_path)
            output_folder = os.path.dirname(output_file)

            if not os.path.exists(output_folder):
                try:
                    os.makedirs(output_folder)
                except OSError as e:
                    print(f"Error creating directory {output_folder}: {e}")
                    continue

            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
            except FileNotFoundError:
                print(f"Input file {input_file} not found.")
                continue
            except IOError as e:
                print(f"Error reading file {input_file}: {e}")
                continue

            if operation in ['enc', 'encrypt']:
                try:
                    ext = os.path.splitext(input_file)[1]
                    encoded_data = base64.base64_encode(data) + ext
                    encrypted_data = aes.encrypt(key, encoded_data.encode())
                    output_file = os.path.splitext(output_file)[0] + '.zaes'

                    with open(output_file, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"Encrypted data written to {output_file}")
                except Exception as e:
                    print(f"Error encrypting file {input_file}: {e}")
                    continue
            elif operation in ['dec', 'decrypt']:
                try:
                    with open(input_file, 'rb') as f:
                        encrypted_data = f.read()
                    decrypted_data = aes.decrypt(key, encrypted_data)
                    decoded_data, ext = os.path.splitext(decrypted_data.decode())
                    decoded_data = base64.base64_decode(decoded_data)
                    output_file = os.path.splitext(output_file)[0] + ext

                    with open(output_file, 'wb') as f:
                        f.write(decoded_data)
                    print(f"Decrypted data written to {output_file}")
                except Exception as e:
                    print(f"Error decrypting file {input_file}: {e}")
                    continue
