from bitarray import bitarray
import base64


def single_byte_xor(text: bytes, key) -> bytes:
    out = b''
    for b in text:
        out += bytes([b ^ key])
    return out



def brute_force_xor(text: bytes):
    output = []
    freq_dict = {
        'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
        'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
        'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
        'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
        'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
        'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
        'y': 1.9913847,    'z': 0.0746517,    ' ': 12.99
    }
    for i in range(256):
        print(chr(i))
        message = single_byte_xor(text, i)
        score = sum([freq_dict.get(chr(byte), 0) for byte in message.lower()])
        data = {
            'message': message,
            'score': score,
            'key': i
        }
        output.append(data)
    return sorted(output, key=lambda x: x['score'], reverse=True)[0]
    # return sorted(output, key=lambda x: x['score'])

        


def repeating_key_xor(text, key):
    out = b''
    i = 0
    for b in text:
        out += bytes([b^key[i]])
        if i+1 == len(key):
            i = 0
        else:
            i += 1 
    return out



def find_possible_keysizes(text):
    possible_keysizes = {}
    keysize = 0
    distances = []
    for i in range(2, 41):
        keysize = i
        with open(text, "r") as f:
            decoded = base64.b64decode(f.read())
            # print(decoded.hex())
        chunks = [decoded[i:i+keysize] for i in range(0, len(decoded), keysize)]

        while True:
            try:
                normalized_dist = hamming_distance(chunks[0], chunks[1]) / keysize
                # possible_keysizes[normalized_dist] = keysize
                distances.append(normalized_dist)
                del chunks[0]
                del chunks[1]
            except Exception as e:
                break
        avg_hamming = sum(distances) / len(distances)
        possible_keysizes[avg_hamming] = keysize        
    for key in sorted(possible_keysizes):
        print(key, possible_keysizes[key])
    
    

def hamming_distance(s1, s2):
    dist = 0
    a = bitarray()
    b = bitarray()
    a.frombytes(s1)
    b.frombytes(s2)
    # print(a, b)
    
    for i in range(0,len(a)):
        if a[i] != b[i]:
            dist += 1
    return dist
    
# keysizes = [2, 11, 29, 30]
def break_repeating_key_xor(text, k_size):
    blocks = [b'' for i in range(k_size)]
    key = ""

    with open(text, "r") as f:
        # convert to bytes
        decoded = base64.b64decode(f.read())
        for i in range(0, len(decoded)):
            j = i % k_size
            blocks[j] += bytes([decoded[i]])

        for block in blocks:
            # print(block)
            key += chr(brute_force_xor(block)['key'])
    
    print(key)
    return key 
             

def main():
    # s = bytes.fromhex("Burning 'em, if you ain't quick and nimble")
    with open("c:\\Users\\Boris\\Desktop\\Projects\\python-crypt\\6.txt", "r") as f:
        ciphertext = base64.b64decode(f.read())
    # print(repeating_key_xor(ciphertext, b"Terminator X: Bring the noise"))
    # print(hamming_distance(b"this is a test", b"wokka wokka!!!"))
    # find_possible_keysizes("c:\\Users\\Boris\\Desktop\\Projects\\python-crypt\\6.txt")
    # break_repeating_key_xor("c:\\Users\\Boris\\Desktop\\Projects\\python-crypt\\6.txt", 29) 
    # print(single_byte_xor(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 88).hex())
    # print(single_byte_xor(b'\x1dM\x02\x13\x1a\x1f\x0e\x01N\x16\x00ITCN\x06TE\x04\x12\x1e\x1aO!+\x1d\x11\x00\x077\x0cAR_\x13GHN\x16E\x08\x07Yj\x0cA\x06\x1bB\x1e\x1a\x02\x7fH\x1a\x1aH\r:\x19A\x00_\x15\t\x0b\x14y\x0b\x05\x07NH\x04E\x08O\x08\x1d\x02\x16Re\x02\x00\x07\x10&M\x02\x1b0R\t\x07NS\x10I\x10\x00GIO\x10O\x11\x06\x02C=/\r\x17T\x0e^M\x12UN\x06G\x0c\x17\x1fB."IA\x06*\x08\x1bB\x07N\x0e+*\x19TW\x051,ARO\x1d\x13\x01N\x17\x0b\x1d\x1aw\x00\x1cT\x0cOER\x01\n7b\x0f\x11\x00\x07;\x19A\x13\x1a\x1a\x02HN\x00\x0b\x08\x1bDiI\x00E\x01\r\x17:O*\'\x1d\rHI"\x00\x00R[\x1b\x08b\nS\x0b\x08\x11EE\x1dN\x0b\x04ER\x0fe,\'NTA\x01;MF\x13[\x1b\x02\x1cdT\nITAS\x05\x00\x00\nE\x13\x1a\x000\x11\'\x15F\x02 \x1d\x0f\x1f_\x06\x08\x0c\x01SHZ\x1b\rN\x02N\nO\nx\x1c\x00x!N\x18E\x10<\x08\x00\x1dUR\x12\x1a\x02\x01\x0c\x1a\x17PL\x06OEH\x04\x17\x0bO<*N\x01A\x0btM\x0f\x13\x1a\x14G\x1a\x0fS\x0e\x01TT*NL\x00\x0e\n_=\x1cxb\x02\x15*\x0cs\x03\x05\x0b\x1d+G\x06\x1c\x07\r\x0e6\x00U\x05EE\x16B\x1d\x0b\x02+.d\x11AI1M\x00\x1b\x1a\x19G\x1a\ry\x11\x06\x1dY\x07IL\x03Ao\x07\x02\n6*\x0b\x1aP\ntM\x0cR\x1a\x00G\x07NSEI\x10HE\r\x00\x10\x1d\x04\x0b\x0fe9\'\x07\x1d\x00\x1a;M\x0c\x1d[R\x1e\x1cd:E\x07\x18i\x00\x19YIH\x06\x1bN\x1d4\'N\x1d\x00\x07,\x0c\x0f\x01CR\x06\r\x02\x16E\x07~\x00NIO\x11\x06E\x16\x07O7!\x07TA\x05t\x08\x12\x17SR\x03\x07\x1e\x03E\x0c\x01N*\x08E\r\x1bE\x17\x1d\x1d2)I\x1d\x00\x08t\x18k\x04\x1d\x1c\x00\x07\x00\x07\x0cITNA\x07*\t\x07\x10R\x0b\x07,%\x01\x1aT\x1a1M\x0fxM\x1d\x15\t\x14SE\x0c=PSIs\x15\x01\x16\x1a\n\x06x\x05\x03TZc5\x01AR_\x13\x14\x01\x07S\n\r RS\x06R\x15H\x0b\x1bBH26\x0b\x1d\x00\x1e^\x0c\x00\x06\x16U\x0f\x0fI\x1a\x11\x00TFA\nyE\x0e\x00\x1f\x01\n6\x0b\x06\x13\x00\x08^\x18\x08\x06[RG\x07\x1aS\x12\x08TNM\x10R\x04e\\\x1c\x17\x06y-NDS\x101Ck\x07_\x17\x02\x06\x08\x07<I\x10\x00N\x0c\x00E\x00E\x16\x1d\n1b\x1a\x07\x00I7M\x04R\x1a\x1d\x08\x1c\x0b\x12\x04I\x1a\x00\x00\r\x07\x10O\x00\x0b\r\r7bN1yI:\x0cAR^+@H\x1a\x1aE\x0fXOTIC\x04O\x01\x17"O=+\x06\x1bOI1\t\x15RTRG\x1adS\x08\x1c\x17SAINEO\x10\x177O6b\x1a\x11ED:\x04M\x1cR\x17m\x1d\x06\x14E\x08=AW\x02bI\x00\x17\x16\n\x1d?\x11\r\x11N\x0c&\x02A\x16SR\x0e\x1b\ty\x1cD\x18\x00A\x0fK\x08\x066^\x01\x07=-NTII-\x02\x11\x0bRR\tH\x1dSE\x00TYG\x1eT\x07C\n>N\x189b\x01\x11N\x19-\x05A\x1c\x1a\x01G\x04\x17S\x00c\x18\x00A\x0fK\x08\x06&\x17\x00,=,\x02T\x00\x08^\x0c\x15\x06O\x0b\x12\x0b\x06\x16\n\x10TYT\x1a\x00E\x03E\x13\x08\x045+/\x1dL\x050M\x16"C\x1aG\x06N\x00I\x01\x11Oc\x0cN&\n\x0b1\x0b\x01\x08;\x06TNI\'M', 4))
    print(brute_force_xor(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))



if __name__ == '__main__':
    main()

