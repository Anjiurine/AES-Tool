import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import os
import shutil

AES_BLOCK_SIZE = AES.block_size
AES_KEY_SIZE = 16

try:
    key = sys.argv[sys.argv.index('-key') + 1]
except (IOError, ValueError):
    print("Please specify the key")

def PadKey(key):
   if len(key) > AES_KEY_SIZE:
       return key[:AES_KEY_SIZE]
   return key.ljust(AES_KEY_SIZE, b' ')

def EnCrypt(key, bytes):
   iv = b'\x00' * AES_BLOCK_SIZE
   myCipher = AES.new(key, AES.MODE_CBC, iv)
   encryptData = iv + myCipher.encrypt(pad(bytes, AES_BLOCK_SIZE))
   return encryptData

def DeCrypt(key, encryptData):
   iv = encryptData[:AES_BLOCK_SIZE]
   myCipher = AES.new(key, AES.MODE_CBC, iv)
   bytes = unpad(myCipher.decrypt(encryptData[AES_BLOCK_SIZE:]), AES_BLOCK_SIZE)
   return bytes

def Base64Encode(data):
   return base64.b64encode(data).decode('utf-8')

def Base64Decode(data):
   return base64.b64decode(data.encode('utf-8'))

def AddSuffix(data, suffix):
   return data + base64.b64encode(suffix.encode()).decode('utf-8')

def RemoveSuffix(data):
   suffix_length = 8
   return data[:-suffix_length], base64.b64decode(data[-suffix_length:]).decode('utf-8')

if __name__ == '__main__':
   if len(sys.argv) < 3:
       print("Usage: python main.py <operation> [-dir <input_dir> -odir <output_dir>] [-input <input_file>] [-key <your_key>]")
       sys.exit(1)

   operation = sys.argv[1]

   if operation not in ['encrypt', 'decrypt']:
       print("Invalid operation. Use 'encrypt' or 'decrypt'.")
       sys.exit(1)

   key = PadKey(key.encode())

   if '-dir' in sys.argv and '-odir' in sys.argv:
       input_dir = sys.argv[sys.argv.index('-dir') + 1]
       output_dir = sys.argv[sys.argv.index('-odir') + 1]
       for root, dirs, files in os.walk(input_dir):
           for file in files:
               input_file = os.path.join(root, file)
               relative_path = os.path.relpath(input_file, input_dir)
               output_file = os.path.join(output_dir, relative_path)
               output_folder = os.path.dirname(output_file)
               if not os.path.exists(output_folder):
                   os.makedirs(output_folder)
               try:
                   with open(input_file, 'rb') as f:
                       bytes = f.read()
               except FileNotFoundError:
                   print(f"Input file {input_file} not found.")
                   continue

               if operation == 'encrypt':
                   encodedData = Base64Encode(bytes)
                   suffix = os.path.splitext(input_file)[1]
                   encodedData = AddSuffix(encodedData, suffix)
                   encryptedData = EnCrypt(key, encodedData.encode())
                   output_file = output_file.replace(suffix, '.aes')
                   try:
                       with open(output_file, 'wb') as f:
                           f.write(encryptedData)
                       shutil.copyfile(output_file, output_folder)
                       print(f"Encrypted data written to {output_file}")
                   except IOError:
                       print(f"Output file {output_file} cannot be written.")
                       continue
               elif operation == 'decrypt':
                   try:
                       with open(input_file, 'rb') as f:
                           encryptedData = f.read()
                       decryptData = DeCrypt(key, encryptedData)
                       decodedData, suffix = RemoveSuffix(decryptData.decode())
                       decodedData = Base64Decode(decodedData)
                       output_file = output_file.replace('.aes', suffix)
                       with open(output_file, 'wb') as f:
                           f.write(decodedData)
                       shutil.copyfile(output_file, output_folder)
                       print(f"Decrypted data written to {output_file}")
                   except (IOError, ValueError):
                       print(f"Input file {input_file} cannot be decrypted.")
                       continue
   elif '-input' in sys.argv:
       input_file = sys.argv[sys.argv.index('-input') + 1]
       try:
           with open(input_file, 'rb') as f:
               bytes = f.read()
       except FileNotFoundError:
           print(f"Input file {input_file} not found.")
           sys.exit(1)

       if operation == 'encrypt':
           encodedData = Base64Encode(bytes)
           suffix = os.path.splitext(input_file)[1]
           encodedData = AddSuffix(encodedData, suffix)
           encryptedData = EnCrypt(key, encodedData.encode())
           output_file = input_file.replace(suffix, '.aes')
           try:
               with open(output_file, 'wb') as f:
                   f.write(encryptedData)
               print(f"Encrypted data written to {output_file}")
           except IOError:
               print(f"Output file {output_file} cannot be written.")
               sys.exit(1)
       elif operation == 'decrypt':
           try:
               with open(input_file, 'rb') as f:
                   encryptedData = f.read()
               decryptData = DeCrypt(key, encryptedData)
               decodedData, suffix = RemoveSuffix(decryptData.decode())
               decodedData = Base64Decode(decodedData)
               output_file = input_file.replace('.aes', suffix)
               with open(output_file, 'wb') as f:
                   f.write(decodedData)
               print(f"Decrypted data written to {output_file}")
           except (IOError, ValueError):
               print(f"Input file {input_file} cannot be decrypted.")
               sys.exit(1)
   else:
       print("Please specify either -dir or -input.")
       sys.exit(1)