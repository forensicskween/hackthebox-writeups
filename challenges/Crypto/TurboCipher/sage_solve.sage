from pwn import *
from sage.all import *
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
import sys

class Solver:
    def __init__(self,host_port):
        self.conn = remote(*host_port.split(':'))
    
    def receive_send(self,val):
        val = l2b(val)
        self.conn.sendlineafter(b"> ", str(2).encode())
        self.conn.sendlineafter(b"pt = ", val)
        ct = self.conn.recvline().decode().strip().replace('ct = ', '')
        return ct

    def fast_turbonacci(self,n,b,c,p):
        m = matrix(Zmod(p),[[b*1,1],[c*1,0]])
        return (m**n)[0][1]

    def reverse_turbocrypt(self,ct_0,ct_1,flag_ct,p):
        k = inverse_mod((ct_1-ct_0),p) * (-ct_0)
        diff = inverse_mod((ct_1-ct_0),p) *(-flag_ct)
        return l2b((k-diff)%p)

    def get_params(self):
        self.conn.recvuntil(b"Parameters:\np = ")
        p = ZZ(self.conn.recvline().decode().strip())
        b = ZZ(self.conn.recvline().decode().strip().split('= ')[-1])
        c = ZZ(self.conn.recvline().decode().strip().split('= ')[-1])
        self.conn.recvline()
        n = ZZ(self.conn.recvline().decode().strip().split('= ')[-1].split(' ')[0])
        otp = self.fast_turbonacci(n,b,c,p)
        return otp,p

    def solve_turbocrypt(self,p):
        flag_enc = ZZ(self.conn.recvline().decode().strip().split(' = ')[-1])
        ct_0 = ZZ(self.receive_send(0))
        ct_1 = ZZ(self.receive_send(1))
        pt = self.reverse_turbocrypt(ct_0,ct_1,flag_enc,p)
        if b'HTB{' in pt:
            return pt
        else:
            return "Fail"
    
    def solve(self):
        otp,p = self.get_params()
        self.conn.sendlineafter(b"OTP:", str(otp).encode())
        l1 = self.conn.recvline()
        if b'Login successful' in l1:
            self.conn.sendlineafter(b"> ", str(1).encode())
            flag =self.solve_turbocrypt(p)
            self.conn.close()
            return flag 
        else:
            return "Fail"

if __name__ == "__main__":
    flag = None
    host_param = sys.argv[1]
    while not flag:
        try:
            solver = Solver(host_param)
            flag = solver.solve()
            print(flag.decode())
        except:
            continue


#HTB{C4lcU1u5_m33t5_Cryp70_c4n_y0u_8e1i3ve_17???}




