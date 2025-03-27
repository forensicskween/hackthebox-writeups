
import json
from hashlib import sha1
from random import randint
from Crypto.Util.number import bytes_to_long
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key, Signature
from pwn import remote
from crypto_attacks.shared.small_roots import coppersmith
import sys

fnames = [b'subject_kolhen', b'subject_stommb', b'subject_danbeer']

class ECDSA:
    def __init__(self,key=None):
        self.G = generator_256
        self.n = self.G.order()
        self.key = key if key else  randint(1, self.n - 1)
        self.pubkey = Public_key(self.G, self.key * self.G)
        self.privkey = Private_key(self.pubkey, self.key)

    def sign(self, fname):
        h = sha1(fname).digest()
        nonce = randint(1, self.n - 1)
        sig = self.privkey.sign(bytes_to_long(h), nonce)
        return {"r": hex(sig.r)[2:], "s": hex(sig.s)[2:], "nonce": hex(nonce)[2:]}

    def verify(self, fname, r, s):
        h = bytes_to_long(sha1(fname).digest())
        r = int(r, 16)
        s = int(s, 16)
        sig = Signature(r, s)

        if self.pubkey.verifies(h, sig):
            return True
        else:
            return 'Signature is not valid\n'

def load_list_payload(response,pairs):
    payload = json.loads(response)
    middle_bits = 2**(14*4)
    equations = []
    i = 0
    for idx,sig in enumerate(payload['files']):
        r,s,middle = [int(x,16) for x in sig.split('_',2)[2].split('_')]
        h = bytes_to_long(sha1(fnames[idx]).digest())
        msb_bits = 2**(256 - ((14+i)*4))
        poly_eq =  msb_bits*pairs[idx][0] + middle*middle_bits + pairs[idx][1]
        equation = ((poly_eq)*s - h)/r
        equations.append(equation)
        i+=2
    return equations

def gen_ecc_signature(fname):
    signature = ecc.sign(fname)
    signature['fname'] = fname.decode()
    signature['option'] = 'access'
    return signature

host,port = sys.argv[1].split(':')

ecc = ECDSA()
my_poly.<msb1,msb2,lsb1,lsb2> = PolynomialRing(Zmod(int(ecc.n)))
bounds = [2**57, 2**65, 2**57, 2**57]
pairs = [[msb1,lsb1],[msb2,lsb2]]

conn = remote(host,port)
conn.recvuntil(b'2.Access a file\n')
conn.sendline(json.dumps({'option':'list'}).encode())
response = conn.recvline()
equations = load_list_payload(response,pairs)
equation = equations[0]-equations[1]
roots = coppersmith.small_roots(equation,bounds,m=2,d=2)

if roots:
    poly_dict = {x:v for x,v in zip(my_poly.gens(),roots[0])}
    d = int(equations[0].subs(poly_dict))

ecc = ECDSA(d)
signatures = [ gen_ecc_signature(fname) for fname in fnames]

for sig in signatures:
    conn.recvuntil(b'2.Access a file\n')
    conn.sendline(json.dumps(sig).encode())
    result = json.loads(conn.recvline())
    if result['response'] == 'success':
        data = bytes.fromhex(result['data'])
        print(f'Data for file {sig["fname"]}\n\n')
        print(data.decode())
        print('\n\n')
