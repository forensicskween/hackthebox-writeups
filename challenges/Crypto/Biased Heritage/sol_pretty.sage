from sage.all import *
from pwn import *
from hashlib import sha256
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
import itertools
import sys
import os
from crypto_attacks.shared.small_roots import coppersmith ##https://github.com/defund/coppersmith

class Solution:
    def __init__(self,host_port):
        host,port = host_port.split(':')
        self.conn = remote(host,port)
        self.msg1 = os.urandom(16)
        self.msg2 = os.urandom(16)
        self.msg = b'right hand'
        self.recv_params()
        self.quick_verif = lambda x: [pow(self.g, i, self.p) for i in range(x-4,x+4)]
        self.H = lambda msg: b2l(2 * sha256(msg).digest()) % self.q

    def recv_params(self):
        self.g = int(self.conn.recvline().decode().strip().split(': ')[-1])
        self.y = int(self.conn.recvline().decode().strip().split(': ')[-1])
        self.p = int(self.conn.recvline().decode().strip().split(': ')[-1])
        self.q = (self.p-1)//2
    
    def send_sig(self,msg):
        self.conn.sendlineafter(b'> ', b'S')
        self.conn.sendlineafter(b'message> ', msg.hex())
        res = eval(self.conn.recvline().decode().strip().split(': ')[-1])
        return res
    
    def send_verif(self):
        s,e = self.sign_msg()
        self.conn.sendlineafter(b'> ', b'V')
        self.conn.sendlineafter(b'message> ', self.msg.hex())
        self.conn.sendlineafter(b's> ', str(s).encode())
        self.conn.sendlineafter(b'e> ', str(e).encode())
        res = self.conn.recvline().decode().strip()
        return res
    
    def recover_private_key(self):
        s1,e1 = self.send_sig(self.msg1)
        s2,e2 = self.send_sig(self.msg2)
        Poly.<f1,f2> =  PolynomialRing(Zmod(self.q))
        bias = 2^256+1
        bounds = (2^256, 2^256)
        x1 = inverse_mod(e1,self.q)*((bias*f1)-s1)
        x2 = inverse_mod(e2,self.q)*((bias*f2)-s2)
        fx = x1-x2
        roots = coppersmith.small_roots(fx,bounds,m=8,d=3)
        x0_ = int(x1.subs(f1=roots[0][0]))
        x1_ = int(x2.subs(f2=roots[0][1]))
        verif1 = self.quick_verif(x0_)
        if x0_ == x1_:
            if self.y in verif1:
                self.x = (x0_-4) + verif1.index(self.y)
            else:
                self.x = None
        elif x0_ != x1_:
            verif2 = self.quick_verif(x1_)
            if self.y in verif1:
                self.x = (x0_-4) + verif1.index(self.y)
            elif self.y in verif2:
                self.x = (x1_-4) + verif1.index(self.y)
            else:
                self.x = None
        return self.x
    
    def sign_msg(self):
        k = self.H(self.msg + l2b(self.x))
        r = pow(self.g, k, self.p) % self.q
        e = self.H(l2b(r) + self.msg)
        s = (k - self.x * e) % self.q
        return (s, e)
    

    def solve(self):
        x = self.recover_private_key()
        if not x:
            self.conn.close()
            res = "Didn't get it!!! Try again " + "\U0001F62D"*10
            #exit(0)
        else:
            res = "GOT IT !!!! " +  ("\U0001F61C" + "\U0001F608")*5 + '\n'
            res += self.send_verif()
        return res


host_port = sys.argv[1]
sol = Solution(host_port)
flag = sol.solve()
print(flag)

