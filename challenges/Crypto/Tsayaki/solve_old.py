
from Tea_User import Cipher as TEA
import sys
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
import os
from utils import masks
from collections import Counter
from pwn import xor,remote,process
ROUNDS = 10

class Solver:
    def __init__(self,conn_params):
        self.conn  = None
        self.conn_params = conn_params
        self.host,self.port = conn_params.split(':')
        self.open_conn()
        self.after_ct = b'Enter your target ciphertext (in hex) : '
        self.after_kv = b'Enter your encryption key (in hex) : '
        self.get_srv_msg()
    
    def open_conn(self):
        if not self.conn or not sum(self.conn.closed.values()):
            self.conn = remote(self.host,self.port)
            #self.conn = process(self.conn_params)
        else:
            self.conn = self.conn 

    def get_srv_msg(self):
        self.conn.recvuntil(b'special message: ')
        self.server_message = bytes.fromhex(self.conn.recvline().decode().strip())

    def send_msg(self,key,ct,close=False):
        self.conn.sendlineafter(self.after_ct,ct.hex().encode())
        self.conn.sendlineafter(self.after_kv,key.hex().encode())
        if close:
            res = self.conn.recvline().decode().strip()
            target = bytes.fromhex(res.split(',')[-1].split(' does')[0].split(' ')[-1])
            self.conn.close()
            self.conn = None
            return target

    def recover_iv(self):
        key = bytes(16)
        ciph = TEA(key)
        ct = ciph.encrypt(self.server_message)
        target = self.send_msg(key,ct,True)
        out1 = ciph.decrypt_block(target[:8])
        iv = xor(out1,self.server_message[:8])
        check =  TEA(bytes(16),iv)
        checked = check.encrypt(self.server_message)
        assert checked == target
        self.IV = iv
        print(f'Recovered iv {iv.hex()}')
    
    def verify_collison(self,keys,ct):
        assert len(set(keys)) == 4
        for key in keys:
            cipher = TEA(key, self.IV)
            enc = cipher.encrypt(self.server_message)
            assert enc == ct 
    
    def find_collision(self):
        key = os.urandom(16)
        cipher = TEA(key, self.IV)
        enc = cipher.encrypt(self.server_message)
        founds = [xor(key,bytes(m)) for m in masks]
        setted = list(set(founds))
        encs = [TEA(key,self.IV).encrypt(self.server_message) for key in setted]
        assert Counter(encs).most_common()[0][1] == 4
        ided = Counter(encs).most_common()[0][0]
        valid_keys = [setted[i] for i,x in enumerate(encs) if x ==ided ]
        try:
            self.verify_collison(valid_keys,ided)
            return ided, valid_keys
        except:
            return None
    
    def find_it(self):
        pair = None
        while not pair:
            pair = self.find_collision()
        return pair

    def pwn_game(self):
        self.open_conn()
        self.get_srv_msg()
        pairs = [self.find_it() for _ in range(10)]
        for i in range(10):
            pair = pairs[i]
            self.conn.recvline()
            self.conn.sendlineafter(self.after_ct,pair[0].hex())
            for j in range(4):
                self.conn.sendlineafter(self.after_kv,pair[1][j].hex())
        flag =  self.conn.recvline().decode().strip()
        return flag

    def play_game(self):
        self.recover_iv()
        flag = self.pwn_game()
        print(flag)


host_port = sys.argv[1]
slv = Solver(host_port)
slv.play_game()
#Wait, really? HTB{y0u_b3tt3r_n0t_us3_t34_f0r_h4sh1ng}