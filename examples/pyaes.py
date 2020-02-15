import binascii
import base64
import math
import random
import time

rCon = [ [0x00, 0x00, 0x00, 0x00],
         [0x01, 0x00, 0x00, 0x00],
         [0x02, 0x00, 0x00, 0x00],
         [0x04, 0x00, 0x00, 0x00],
         [0x08, 0x00, 0x00, 0x00],
         [0x10, 0x00, 0x00, 0x00],
         [0x20, 0x00, 0x00, 0x00],
         [0x40, 0x00, 0x00, 0x00],
         [0x80, 0x00, 0x00, 0x00],
         [0x1b, 0x00, 0x00, 0x00],
         [0x36, 0x00, 0x00, 0x00] ]

sBox =  [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
         0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
         0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
         0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
         0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
         0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
         0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
         0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
         0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
         0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
         0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
         0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
         0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
         0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
         0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
         0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

def sub_word(w):
    for i in range(4):
        w[i] = sBox[w[i]]
    return w

def rot_word(w):
    tmp = w[0]
    for i in range(3):
        w[i] = w[i+1]
    w[3] = tmp
    return w

def add_round_key(state, w, rnd, Nb):
    for r in range(4):
        for c in range(Nb):
            state[r][c] ^= w[rnd*4+c][r];
    return state

def sub_bytes(s, Nb):
    for r in range(4):
        for c in range(Nb):
             s[r][c] = sBox[s[r][c]]
    return s

def shift_rows(s, Nb):
    t = [0, 0, 0, 0]
    for r in range(4):
        for c in range(4):
            t[c] = s[r][(c+r)%Nb];  # shift into temp copy
        for c in range(4):
            s[r][c] = t[c];         # and copy back
    return s

def mix_columns(s, Nb):
    for c in range(4):
        a = [0, 0, 0, 0]
        b = [0, 0, 0, 0]
        for i in range(4):
            a[i] = s[i][c]
            b[i] = s[i][c]&0x80
            if s[i][c]&0x80:
                b[i] = s[i][c]<<1 ^ 0x011b
            else:
                b[i] = s[i][c]<<1
        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]
    return s

def key_expansion(key):
    Nb = 4;          # block size (in words): no of columns in state (fixed at 4 for AES)
    Nk = 4;          # key length (in words): 4/6/8 for 128/192/256-bit keys
    Nr = Nk + 6;     # no of rounds: 10/12/14 for 128/192/256-bit keys
    w = []
    temp = [0, 0, 0, 0]
    for i in range(Nb*(Nr+1)):
        w.append(0)
    for i in range(Nk):
        w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
    for i in range(Nk, (Nb*(Nr+1))):
        w[i] = [0, 0, 0, 0]
        for t in range(4):
            temp[t] = w[i-1][t];
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            for t in range(4):
                temp[t] ^= rCon[int(i/Nk)][t]
        else:
            if Nk > 6 and i%Nk == 4:
                temp = sub_word(temp)
        for t in range(4):    
            w[i][t] = w[i-Nk][t] ^ temp[t]
    return w

def aes_cipher(input, w):
    Nb = 4           # block size (in words): no of columns in state (fixed at 4 for AES)
    Nr = 10          # no of rounds: 10/12/14 for 128/192/256-bit keys
    state = [ [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0] ]
    for i in range(4*Nb):
        state[i%4][int(i/4)] = input[i]
    state = add_round_key(state, w, 0, Nb)
    for round in range(1, Nr):
        state = sub_bytes(state, Nb)
        state = shift_rows(state, Nb)
        state = mix_columns(state, Nb)
        state = add_round_key(state, w, round, Nb)
    state = sub_bytes(state, Nb)
    state = shift_rows(state, Nb)
    state = add_round_key(state, w, Nr, Nb)
    output = []                            
    for i in range(4*Nb):
        output.append(0)
    for i in range(4*Nb):
         output[i] = state[i%4][int(i/4)];
    return output

def decrypt_message(password, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    blocksize = 16
    pwbytes = []
    for i in range(blocksize):
        pwbytes.append(ord(password[i]))
    key = aes_cipher(pwbytes, key_expansion(pwbytes))
    counter_block = [ ]
    for i in range(16):
        counter_block.append(0)
    ctrtxt = ciphertext[:8]
    for i in range(8):
        counter_block[i] = ctrtxt[i]
    key_schedule = key_expansion(key)
    nblocks = math.ceil((len(ciphertext)-8) / blocksize);
    ct = []
    for i in range(nblocks):
        ct.append(0)
    for b in range(nblocks):
        ct[b] = ciphertext[8+b*blocksize:8+b*blocksize+blocksize]
    ciphertext = ct
    plaintext = []
    for i in range(len(ciphertext)):
        plaintext.append(0)
    for b in range(nblocks):
        for c in range(4):
            counter_block[15-c] = ((b) >> c*8) & 0xff
#        for c in range(4):
#            counter_block[15-c-4] = (((b+1)//0x100000000-1) >> c*8) & 0xff
        cipher_counter = aes_cipher(counter_block, key_schedule)
        plaintxtbyte = []
        for i in range(len(ciphertext[b])):
            plaintxtbyte.append(0)
        for i in range(len(ciphertext[b])):
            plaintxtbyte[i] = cipher_counter[i] ^ ciphertext[b][i]
            plaintxtbyte[i] = chr(plaintxtbyte[i])
        plaintext[b] = "".join(plaintxtbyte)
    return  "".join(plaintext)

def encrypt_message(password, plaintext):
    blocksize = 16
    pwbytes = []
    for i in range(16):
        pwbytes.append(ord(password[i]))
    key = aes_cipher(pwbytes, key_expansion(pwbytes))
    counter_block = [ ]
    for i in range(blocksize):
        counter_block.append(0)
    nonce = int(time.time()*1000)
    nonce_ms = nonce%1000;
    nonce_sec = math.floor(nonce/1000)
    nonce_rnd = math.floor(random.random()*0xffff)
    for i in range(2):
        counter_block[i] = (nonce_ms >> i*8) & 0xff
    for i in range(2):
        counter_block[i+2] = (nonce_rnd >> i*8) & 0xff
    for i in range(4):
        counter_block[i+4] = (nonce_sec >> i*8) & 0xff
    ctrtxt = ''
    for i in range(8):
        ctrtxt += chr(counter_block[i])
    key_schedule = key_expansion(key)
    blockcount = math.ceil(len(plaintext)/blocksize)
    ciphertext = []
    for i in range(blockcount):
        ciphertext.append(0)

    for b in range(blockcount):
        for c in range(4):
            counter_block[15-c] = (b >> c*8) & 0xff
        for c in range(4):
            counter_block[15-c-4] = (int(b/0x100000000) >> c*8)
        cipher_counter = aes_cipher(counter_block, key_schedule)
        if b < blockcount-1:
            blocklength = blocksize
        else:
            blocklength = (len(plaintext)-1) % blocksize+1
        cipher_char = []
        for i in range(blocklength):
            cipher_char.append(0)
        for i in range(blocklength):
            cipher_char[i] = cipher_counter[i] ^ ord(plaintext[b*blocksize+i])
            cipher_char[i] = chr(cipher_char[i])
        ciphertext[b] = "".join(cipher_char)
    ciphertext =  ctrtxt + "".join(ciphertext)
    return base64.urlsafe_b64encode(ciphertext.encode('latin-1')).decode()



