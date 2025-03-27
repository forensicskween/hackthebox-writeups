from pwn import *
import sys

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn

#https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecb/plaintext_recovery_harder.py#L10
def _get_prefix_padding(encrypt_oracle, paddings):
    check = b"\x01" * 32
    for i in range(16):
        prefix_padding = paddings[16 - i]
        c = encrypt_oracle(prefix_padding + check)
        if c[16:32] == c[32:48]:
            return prefix_padding


def attack(encrypt_oracle, unused_byte=0):
    paddings = [bytes([unused_byte] * i) for i in range(17)]
    prefix_padding = _get_prefix_padding(encrypt_oracle, paddings)
    secret = bytearray()
    while True:
        padding = paddings[15 - (len(secret) % 16)]
        p = bytearray(prefix_padding + padding + secret + b"0" + padding)
        byte_index = len(prefix_padding) + len(padding) + len(secret)
        end1 = 16 + len(padding) + len(secret) + 1
        end2 = end1 + len(padding) + len(secret) + 1
        for i in range(256):
            p[byte_index] = i
            c = encrypt_oracle(p)
            if c[end1 - 16:end1] == c[end2 - 16:end2]:
                secret.append(i)
                break
        else:
            secret.pop()
            break
    return bytes(secret)


def encrypt_oracle(msg):
    msg = msg.hex()
    conn.sendlineafter(b'> ', msg.encode())
    res = conn.recvline().decode().strip()
    return bytes.fromhex(res)

if __name__ == "__main__":
    conn = get_conn(sys.argv[1])
    flag = attack(encrypt_oracle, unused_byte=3)
    print(flag.decode())
    #HTB{7h3_br0k3n_0r@c1e!!!}




