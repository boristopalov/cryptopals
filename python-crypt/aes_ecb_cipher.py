import base64
import sys
import os
from pandas.core import base
from hashlib import sha256
from bitarray import bitarray
from Crypto.Cipher import AES
from Crypto import Random

# class AESCipher(object):

#     def __init__(self, key): 
#         self.blocksize = AES.block_size
#         self.key = sha256(key.encode()).digest()

#     def _pad(self, s):
#         num_bytes_to_pad = self.blocksize - len(s) % self.blocksize
#         padding = num_bytes_to_pad * chr(num_bytes_to_pad)
#         return s + padding

#     @staticmethod
#     def _unpad(s):
#         last_char = s[len(s)-1:]
#         to_remove = ord(last_char)  
#         return s[:-to_remove]

#     def encrypt(self, s):
#         s = self._pad(s)
#         iv = Random.new().read(self.blocksize)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return base64.b64encode(iv + cipher.encrypt(s.encode()))

#     def decrypt(self, enc): 
#         enc = base64.b64decode(enc)
#         iv = enc[:self.blocksize]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return self._unpad(cipher.decrypt(enc[self.blocksize:])).decode('utf-8')


def AES_ECB_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)
    
def AES_ECB_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.decrypt(ciphertext)


def detect_AES_ECB(plaintext):
    blocks = set()
    dupes = set()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if block in blocks:
            dupes.add(block)
        else:
            blocks.add(block)
    if len(dupes) > 0: 
        return dupes
    else:
        return False


def main():
    # with open(os.path.join(sys.path[0], "7.txt"), "r") as f:
    #     ciphertext = base64.b64decode(f.read())
    #     print(AES_ECB_decrypt(ciphertext, b"YELLOW SUBMARINE"))
    with open(os.path.join(sys.path[0], "8.txt"), "r") as f:
        # ciphertext = base64.b64decode(f.read())
        dupes = detect_AES_ECB(f.read())
        print(dupes)
        # print(AES_ECB_encrypt(ciphertext, b"YELLOW SUBMARINE"))
        # key = AESCipher.decrypt(ciphertext, b"YELLOW SUBMARINE")


if __name__ == '__main__':
    main()
