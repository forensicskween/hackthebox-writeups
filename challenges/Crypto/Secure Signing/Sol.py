import sys 
import string

from Crypto.Util.number import long_to_bytes as l2b
from hashlib import sha256
from pwn import *


class Sol:
    def __init__(self,host,port):
        self.conn= remote(host,port,timeout=1)
        self.known_pt = b'HTB{'
        self.ds = [self.H(b'\x00'*i) for i in range(3,32)]
        self.id_dict = sorted([i for i in string.printable.encode()])

    def send_hsh(self,msg):
        self.conn.sendlineafter(b'> ',str(1).encode())
        self.conn.sendlineafter(b"Enter your message: ",msg)
        res = self.conn.recvline(timeout=1).decode().strip().split(': ')[-1]
        return bytes.fromhex(res)

    def send_verif(self,hsh,msg):
        self.conn.sendlineafter(b'> ',str(2).encode())
        self.conn.sendlineafter(b"Enter your message: ",msg)
        self.conn.sendlineafter(b"Enter your hash: ",hsh.hex())
        res = self.conn.recvline(timeout=1).decode().strip()
        if res == '[+] Signature Validated!':
            return True
        else:
            return False

    def H(self,msg):
        return sha256(msg).digest()

    def recover_first_31(self):
        idx_ = 1
        known_pt =self.known_pt
        for _ in range(31):
            for i in self.id_dict:
                ptx = known_pt + l2b(i)
                test = sol.send_hsh(ptx)
                if test in self.ds[idx_+1:]:
                    known_pt = ptx
                    #print(known_pt)
                    idx_+=1
                    break
        self.known_pt32 = known_pt

    def recover_post_32(self):
        known_pt = self.known_pt32
        pv = 32
        for _ in range(32):
            for i in self.id_dict:
                plain_ = b'\x00'*pv
                check = self.send_hsh(plain_)
                ptx = known_pt + l2b(i)
                if self.H(ptx) == check:
                    known_pt = ptx
                    #print(known_pt)
                    pv +=1
                    break
            if known_pt[-1:] == b'}':
                break
        return known_pt

if __name__ == "__main__":
    host,port=sys.argv[1].split(":")
    sol = Sol(host,port)
    sol.recover_first_31()
    flag = sol.recover_post_32()
    print(flag.decode())
