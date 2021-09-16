from bitarray import bitarray

# returns bytes 
def PKCS_pad(s, blocksize) -> bytes:
    b = bytes(s,'utf-8')
    num_bytes_to_pad = blocksize - len(b) % blocksize
    if num_bytes_to_pad == 0:
        num_bytes_to_pad = blocksize
    padding = bytes(num_bytes_to_pad * chr(num_bytes_to_pad), 'utf-8')
    return b + padding


def main():
    print(chr(140))
    print(PKCS_pad("YELLOW SUBMARINE", 20))


if __name__ == '__main__':
    main()

