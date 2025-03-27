import operator
import os

from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from pwn import remote

from Tea_User import Cipher as TEA

def make_collision(key,message,IV =b'U\xb5\x0e:\xfa\xed=\x99'):
    K0,K1,K2,K3 =  [b2l(key[i:i+4]) for i in range(0, len(key), 4)]
    BITS_FLIP = 0x80000000
    KEY_0 = [K0,K1,K2,K3]
    KEY_1 = [operator.xor(K0,BITS_FLIP),operator.xor(K1,BITS_FLIP),K2,K3]
    KEY_2 = KEY_1[:2] + [operator.xor(K2,BITS_FLIP),operator.xor(K3,BITS_FLIP)]
    KEY_3 = KEY_0[:2] + KEY_2[-2:]
    m_values = set()
    KEYS = []
    for K in [KEY_0,KEY_1,KEY_2,KEY_3]:
        key_bytes =  b''.join([l2b(x) for x in K])
        m = TEA(key_bytes,IV).encrypt(message)
        m_values.add(m)
        KEYS.append(key_bytes.hex())
    assert len(m_values) == 1
    return m.hex(),KEYS

def generate_pairs(server_message):
    colliding_pairs = []
    while len(colliding_pairs) != 10:
        try:
            key = os.urandom(16)
            assert 128 or 0 not in key
            colliding_pairs.append(make_collision(key,server_message))
            print(F'Found equivalent keys for {key.hex()}')
        except:
            continue
    return colliding_pairs

def recover_iv(host,port):
    key = bytes(16)
    cipher_ecb = TEA(key)

    conn = remote(host,port)
    conn.recvuntil(b'Here is my special message: ')
    server_message = bytes.fromhex(conn.recvline().decode().strip())

    conn.sendlineafter(b'Enter your target ciphertext (in hex) : ',bytes(16).hex().encode())
    conn.sendlineafter(b'Enter your encryption key (in hex) : ',key.hex().encode())
    conn.recvuntil(b'Hmm ... close enough, but ')
    enc = bytes.fromhex(conn.recvuntil(b' ').decode().strip())

    dec_block = cipher_ecb.decrypt_block(enc[:8])
    IV = cipher_ecb._xor(dec_block,server_message[:8])

    assert TEA(key,IV).encrypt(server_message) == enc
    
    conn.close()
    return IV

host,port = '',''

IV = recover_iv(host,port)
print(f'Recovered IV : {IV.hex()}')

conn = remote(host,port)

conn.recvuntil(b'Here is my special message: ')
server_message = bytes.fromhex(conn.recvline().decode().strip())

colliding_pairs = generate_pairs(server_message)


for round in range(10):
    ct,keys = colliding_pairs[round]
    conn.sendlineafter(b'Enter your target ciphertext (in hex) : ',ct.encode())
    for i in range(4):
        conn.sendlineafter(b'Enter your encryption key (in hex) : ',keys[i].encode())


FLAG = conn.recvline().decode().strip()
print(FLAG)
