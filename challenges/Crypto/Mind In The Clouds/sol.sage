from sage.all import *
from crypto.attacks.shared.small_roots import coppersmith
import json
from Crypto.Util.number import bytes_to_long as b2l,long_to_bytes as l2b
from pwn import *
from hashlib import sha1
from random import randint
import sys

class Solver:
    def __init__(self,conn_params):
        self.conn = self.get_conn(conn_params)
        self.gen_curve_params()
    
    def get_conn(self,args):
        if 'python' in args:
            conn = process(args.split(' '))
        else:
            host,port = args.split(':')
            conn = remote(host,port)
        return conn


    def gen_curve_params(self):
        self.p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        self.E = EllipticCurve(GF(self.p),[-3,b])
        Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
        Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
        self.G = self.E(Gx,Gy)
        self.n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    def sage_sign(self,h,random_k,key):
        k = random_k%self.n
        ks = k+self.n
        kt = ks+self.n
        if ks.bit_length() == self.n.bit_length():
            p1 = kt * self.G
        else:
            p1 = ks * self.G
        r = int(p1.xy()[0]) % self.n
        s = (inverse_mod(k, self.n) * (h + (key * r) % self.n)) % self.n
        return (r,s)
    
    def sign(self,message,key):
        h = sha1(message).digest()
        nonce = randint(1, self.n - 1)
        (r,s)= self.sage_sign(b2l(h),nonce,key)
        payload = {'option': 'access', 'fname' : message.decode(), 'r' : hex(r) ,'s': hex(s)}
        return json.dumps(payload).encode()

    def get_signatures(self):
        payload = json.dumps({'option': 'list'})
        self.conn.sendlineafter(b' file\n', payload.encode())
        res = json.loads(self.conn.recvline().decode().strip())
        files = res['files']
        i = 0
        sigs = []
        for file in files:
            splits = [int(x,16) for x in file[15:].split('_')]
            namef = file[0:14]
            h = b2l(sha1(namef.encode()).digest())
            item = {'name': namef, 'h': h, 'r': splits[0], 's': splits[1], 'n': splits[2], 'nl': (14+i,-14)}
            sigs.append(item)
            i+=2
        return sigs

    def get_params(self,sigs):
        h1,r1,s1,b1 = sigs[0]['h'],sigs[0]['r'],sigs[0]['s'],sigs[0]['n']
        h2,r2,s2,b2 = sigs[1]['h'],sigs[1]['r'],sigs[1]['s'],sigs[1]['n']
        return h1,r1,s1,b1,h2,r2,s2,b2

    def recover_priv_key(self,sigs):
        order = self.n
        h1,r1,s1,b1,h2,r2,s2,b2 = self.get_params(sigs)
        P.<a1, c1, a2, c2,d> = PolynomialRing(GF(order))
        k1 = a1*2^196 + b1*2^56 + c1
        k2 = a2*2^188 + b2*2^56 + c2
        poly1 = h1 + r1*d - s1*k1
        poly2 = h2 + r2*d - s2*k2
        #poly3 = poly1.sylvester_matrix(poly2,d).determinant() 
        poly3 = poly1.subresultants(poly2,d)[0]
        new_p = poly3.parent().remove_var('d')
        poly3 = new_p(str(poly3))
        bounds = (2^56, 2^56, 2^64, 2^56)
        roots = coppersmith.small_roots(poly3, bounds, m=2, d=2)[0]
        subs_dict = {P(k):v for k,v in zip(new_p.gens(),roots)}
        d = poly1.subs(subs_dict).univariate_polynomial().monic().roots()[0][0]
        return int(d)

    def solve(self):
        sigs = self.get_signatures()
        priv_key = self.recover_priv_key(sigs)
        get_sig = self.sign(b'subject_danbeer',priv_key)
        self.conn.sendlineafter(b' file\n', get_sig)
        res = json.loads(self.conn.recvline().decode().strip())
        pt = bytes.fromhex(res['data'])
        return pt.decode()

if __name__ == "__main__":
    flag = Solver(sys.argv[1]).solve()
    print(flag)
    # HTB{m@st3r1ng_LLL_1s_n0t_3@sy_TODO}




