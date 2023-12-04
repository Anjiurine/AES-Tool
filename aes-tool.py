import argparse
import sys
from utils import folder
from utils import file
from utils import aes

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files using AES and base64 encoding.')
    parser.add_argument('operation', choices=['enc', 'dec', 'encrypt', 'decrypt'], help='Operation to perform: encrypt or decrypt')
    parser.add_argument('-k', '--key', required=True, help='Encryption/decryption key')
    parser.add_argument('-d', '--dir', help='Input directory for bulk processing')
    parser.add_argument('-o', '--output', help='Output directory for bulk processing')
    parser.add_argument('-f', '--file', help='Input file for single file processing')

    args = parser.parse_args()

    key = aes.pad_key(args.key.encode())

    if args.dir and args.output:
        folder.process_directory(args.dir, args.output, key, args.operation)
    elif args.file:
        file.process_single_file(args.file, key, args.operation)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
