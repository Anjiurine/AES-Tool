import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import argparse
import os
import sys

AES_BLOCK_SIZE = AES.block_size
AES_KEY_SIZE = 32

def pad_key(key):
    if len(key) > AES_KEY_SIZE:
        return key[:AES_KEY_SIZE]
    return key.ljust(AES_KEY_SIZE, b' ')

def encrypt(key, data):
    iv = b'\x00' * AES_BLOCK_SIZE
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return encrypted_data

def decrypt(key, encrypted_data):
    iv = encrypted_data[:AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(encrypted_data[AES_BLOCK_SIZE:]), AES_BLOCK_SIZE)
    return data

def base64_encode(data):
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data):
    return base64.b64decode(data.encode('utf-8'))

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
                    encoded_data = base64_encode(data) + ext
                    encrypted_data = encrypt(key, encoded_data.encode())
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
                    decrypted_data = decrypt(key, encrypted_data)
                    decoded_data, ext = os.path.splitext(decrypted_data.decode())
                    decoded_data = base64_decode(decoded_data)
                    output_file = os.path.splitext(output_file)[0] + ext

                    with open(output_file, 'wb') as f:
                        f.write(decoded_data)
                    print(f"Decrypted data written to {output_file}")
                except Exception as e:
                    print(f"Error decrypting file {input_file}: {e}")
                    continue

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
            encoded_data = base64_encode(data) + ext
            encrypted_data = encrypt(key, encoded_data.encode())
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
            decrypted_data = decrypt(key, encrypted_data)
            decoded_data, ext = os.path.splitext(decrypted_data.decode())
            decoded_data = base64_decode(decoded_data)
            output_file = input_file.replace('.zaes', '') + ext

            with open(output_file, 'wb') as f:
                f.write(decoded_data)
            print(f"Decrypted data written to {output_file}")
        except Exception as e:
            print(f"Error decrypting file {input_file}: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files using AES and base64 encoding.')
    parser.add_argument('operation', choices=['enc', 'dec', 'encrypt', 'decrypt'], help='Operation to perform: encrypt or decrypt')
    parser.add_argument('-k', '--key', required=True, help='Encryption/decryption key')
    parser.add_argument('-d', '--dir', help='Input directory for bulk processing')
    parser.add_argument('-o', '--output', help='Output directory for bulk processing')
    parser.add_argument('-f', '--file', help='Input file for single file processing')

    args = parser.parse_args()

    key = pad_key(args.key.encode())

    if args.dir and args.output:
        process_directory(args.dir, args.output, key, args.operation)
    elif args.file:
        process_single_file(args.file, key, args.operation)
    else:
        print("Please specify either -d or -f.")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
