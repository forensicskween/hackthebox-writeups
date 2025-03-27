from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
from pwn import *
import sys

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn

def encrypt(shared_secret):
    pt = b"Initialization Sequence - Code 0"
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(pt)
    return message.hex()

def solve(conn_params):
    conn = get_conn(conn_params)
    to_send = encrypt(1)
    conn.sendlineafter(b'???\n',str(1).encode())
    conn.sendlineafter(b"Calculation Complete\n\n",to_send.encode())
    conn.recvline()
    conn.interactive()


if __name__ == "__main__":
    solve(sys.argv[1])
    #DEBUG MSG - Reseting The Protocol With The New Shared Key
    #DEBUG MSG - HTB{7h15_15_cr3@t3d_by_Danb3er_@nd_h@s_c0pyr1gh7_1aws!_!}
