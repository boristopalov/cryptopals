from collections import defaultdict
from re import split
from Crypto import Cipher
from Crypto.Cipher import AES
from Crypto import Random
import base64
import os
import sys
from hashlib import sha256
from Crypto.Random import random


def byte_xor(b1, b2):
    ret = b''
    for i in range(len(b1)):
        ret += bytes([b1[i] ^ b2[i]])
    return ret

def pad(plaintext, blocksize) -> bytes:
    num_bytes_to_pad = blocksize - len(plaintext) % blocksize
    padding = bytes(num_bytes_to_pad * chr(num_bytes_to_pad), 'utf-8')
    return plaintext + padding

def unpad(s):
        last_char = s[len(s)-1:]
        to_remove = ord(last_char)  
        return s[:-to_remove]

def split_into_blocks(s, blocksize):
    blocks = []
    for i in range(0, len(s), blocksize):
        blocks.append(s[i:i+blocksize])
    return blocks

def AES_ECB_encrypt(plaintext, key): 
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def AES_ECB_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext))

def CBC_encrypt(plaintext, blocksize, iv, key):
    ret = b''
    padded_plaintext = pad(plaintext, blocksize)
    blocks = split_into_blocks(padded_plaintext, blocksize)
    prev_block = iv
    
    for block in blocks:
        to_encrypt = byte_xor(block, prev_block)
        encrypted = AES_ECB_encrypt(to_encrypt, key)
        ret += encrypted
        prev_block = encrypted
    return ret
        

def CBC_decrypt(ciphertext, blocksize, iv, key):
    ret = ""
    prev_block = iv
    blocks = split_into_blocks(ciphertext, blocksize)

    for block in blocks:
        to_xor = AES_ECB_decrypt(block, key)
        ret += byte_xor(to_xor, prev_block).decode()
        prev_block = block
    return unpad(ret)
        


def random_key_encrypt(plaintext):
    key = Random.get_random_bytes(16)
    prepend = Random.new().read(random.randint(5, 10))
    append = Random.new().read(random.randint(5, 10))
    plaintext = prepend + plaintext + append
    ecb_flag = random.randint(0, 1)
    if ecb_flag == 0:
        return AES_ECB_encrypt(plaintext, key), True
    if ecb_flag == 1:
        iv = Random.get_random_bytes(16)
        return CBC_encrypt(plaintext, 16, iv, key), False


#128-bit detection
def detect_AES_ECB(ciphertext):
    blocks = set()
    dupes = set()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        if block in blocks:
            dupes.add(block)
        else:
            blocks.add(block)
    if len(dupes) > 0: 
        return dupes
    else:
        return False

def aes_ecb_cbc_oracle(plaintext):
    encrypted, type = random_key_encrypt(plaintext)
    is_ecb = detect_AES_ECB(plaintext)
    #correct detection
    if (is_ecb and type) or (not is_ecb and not type):
        return {'guess': "Correct!", 'ciphertext': encrypted}
    #incorrectly guesses cbc
    if not is_ecb and type:
        return {'guess': "CBC_False_Positive", 'ciphertext': encrypted}
    #incorrectly guesses ecb
    if is_ecb and not type:
        return {'guess': "ECB_False_Positive", 'ciphertext': encrypted}

#we have a piece of text that we know, and add to it a piece of text that we want to decrypt
#decode unknown string to a regular string first and then encrypt it 
#key outside the function so it stays consistent throughout rounds 
KEY = Random.get_random_bytes(16)
def aes_oracle(plaintext):
    global KEY
    plaintext = pad(plaintext, 16)
    return AES_ECB_encrypt(plaintext, KEY)


#since the size of the ciphertext should stay consistent within a certain range when it gets padded,
#there is a point when the ciphertext length % blocksize = 0, and at that point the ciphertext
#will get padded by *blocksize* number of characters
#so we keep adding a byte to the ciphertext until it increases in size from the padding
#and at that point we can figure out the block size 
def guess_block_size(unknown):
    known_bytes = b"A" * 32
    prev_length = len(unknown)
    for i in range(1, len(known_bytes)):
        ciphertext = aes_oracle(known_bytes[:i]+unknown)
        ciphertext_length = len(ciphertext)
        if ciphertext_length != prev_length:
            return ciphertext_length - prev_length
        

            
def simple_ecb_decrypt(ciphertext):
    known_bytes = b"YELLOW SUBMARINEYELLOW SUBMARINE"
    #feed in 2 b
    blocksize = guess_block_size(ciphertext)

    is_ecb = detect_AES_ECB(aes_oracle(known_bytes+ciphertext))
    if not is_ecb:
        print("Not ECB!")
        exit(1)
    out = ""
    #this map will serve as a lookup table for all possible last byte outputs
    map = {}

    #1 byte short of the blocksize 
    short_input = b"A" * (blocksize-1)

    for i in range(256):
        full_input = short_input + i.to_bytes(1, sys.byteorder)

        #we only care about the first block
        map[aes_oracle(full_input)[:16]] = i
    for i in ciphertext: 
        byte = i.to_bytes(1, sys.byteorder)
        unknown_block = aes_oracle(short_input+byte)[:16]
        out += (chr(map.get(unknown_block)))
    return out 


def kv_parser(byte_string):
    s = byte_string.decode()
    return dict(x.split("=") for x in s.split("&"))


#returns an encoded version of a user profile
def profile_for(email_bytes):
    if b"&" in email_bytes or b"=" in email_bytes:
        print("Cannot use metacharacters in email!")
        exit(1)
    d = {}
    d['email'] = email_bytes
    d['uid'] = b'10'
    d['role'] = b'user'
    return b"email="+d['email']+b"&uid="+d['uid']+b"&role="+d['role']
    

def create_admin_role():
    global KEY
    plaintext_bytes = profile_for(b"foooo@bar.com")
    blocksize = guess_block_size(aes_oracle(plaintext_bytes))
    print("plaintext bytes: ", plaintext_bytes)

    #we split it into blocks so that the role (in this case user, is at the start of its own block)
    print("We need to isolate the last block here: ", split_into_blocks(plaintext_bytes, blocksize))
    encrypted = aes_oracle(plaintext_bytes)

    #we want to replace the 'user' role with this admin role, first we pad it so that it works correctly with the cipher
    admin_attack_text = pad(b"admin", blocksize)
    #now we create the profile for it, and make sure that the admin role is at the start of its own block
    #len - 1 to acccount for the '=' in the encoded profile
    fake_pad = b"A" * (blocksize - len(b"admin")-1)
    admin_profile = profile_for(fake_pad+admin_attack_text)
    print("We need the 2nd block here: ", split_into_blocks(admin_profile, blocksize))
    admin_encrypted = AES_ECB_encrypt(pad(admin_profile, blocksize), KEY)
    #now we cut out the part of the encrypted text where 'admin' is
    #the 2nd block is the text we want to cut out
    encrypted_text_to_cut = admin_encrypted[blocksize:2*blocksize]
    #the last block of the original text is what we want to add the cut text to
    encrypted_text_to_append = encrypted[:-blocksize]
    new_encrypted = encrypted_text_to_append + encrypted_text_to_cut
    return kv_parser(AES_ECB_decrypt(new_encrypted, KEY))


    
def main():
    global KEY
    # iv = bytes(chr(0), 'utf-8') * 16
    # with open(os.path.join(sys.path[0], "10.txt"), "r") as f:
    #     print(CBC_decrypt(base64.b64decode(f.read()), 16, iv, b"YELLOW SUBMARINE"))
    # with open(os.path.join(sys.path[0], "12.txt"), "r", encoding="utf-8") as f:
    #     random_bytes = Random.get_random_bytes(random.randint())
    #     decoded = base64.b64decode(f.read())
    #     print(simple_ecb_decrypt(decoded))
    print(create_admin_role())

if __name__ == '__main__':
    main()