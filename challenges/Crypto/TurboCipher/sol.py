from Crypto.Util.number import bytes_to_long, getPrime, getRandomRange,long_to_bytes
from pwn import *

import sys

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn

def matrix_square(A, mod):
    return mat_mult(A,A,mod)

def mat_mult(A,B, mod):
  if mod is not None:
    return [[((A[0][0]*B[0][0] + A[0][1]*B[1][0]))%mod, ((A[0][0]*B[0][1] + A[0][1]*B[1][1]))%mod],
            [((A[1][0]*B[0][0] + A[1][1]*B[1][0]))%mod, ((A[1][0]*B[0][1] + A[1][1]*B[1][1]))%mod]]


def matrix_pow(M, power, mod):
    #Special definition for power=0:
    if power <= 0:
      return M
    powers =  list(reversed([True if i=="1" else False for i in bin(power)[2:]])) #Order is 1,2,4,8,16,...
    matrices = [None for _ in powers]
    matrices[0] = M
    for i in range(1,len(powers)):
        matrices[i] = matrix_square(matrices[i-1], mod)
    result = None
    for matrix, power in zip(matrices, powers):
        if power:
            if result is None:
                result = matrix
            else:
                result = mat_mult(result, matrix, mod)
    return result

def fast_turbonacci(n,b,c,p):
    return matrix_pow([[b*1, 1], [c*1, 0]], n, p)[0][1]


def reverse_turbocrypt(ct_0,ct_1,flag_ct,p):
    dval = ct_1-ct_0
    inversed_d = pow(dval,-1,p)
    k = inversed_d * (-ct_0)
    diff = inversed_d*(-flag_ct)
    flag = k-diff
    return flag %p

def turbo_crypt(ct_0,ct_1,plain,p):
    dval = ct_1-ct_0
    inversed_d = pow(dval,-1,p)
    k = inversed_d * (-ct_0)
    diff = plain-k
    return (dval*diff)%p


def receive_send(t,val):
	val = long_to_bytes(val).decode()
	t.sendafter(b"> ", str(2).encode())
	t.sendafter(b"pt = ", val)
	ct = t.recvline().decode().strip().replace('ct = ', '')
	return ct

def solve(conn_params):
	t = get_conn(conn_params)
	t.recvuntil(b"Parameters:\np = ")
	p = int(t.recvuntil(b"\nb = ").decode().strip().replace("\nb =",""))
	b= int(t.recvuntil(b"\nc = ").decode().strip().replace("\nc =",""))
	c= int(t.recvuntil(b"\n\nPlease, use nonce =").decode().strip().replace("\n\nPlease, use nonce =",""))
	n = int(t.recvuntil(b" to generate").decode().strip().replace(" to generate",""))
	otp = fast_turbonacci(n,b,c,p)
	t.sendafter(b"OTP:", str(otp).encode())
	l1 = t.recvline()
	if b'Login successful' in l1:
		print("All Good!")
		t.sendafter(b"> ", str(1).encode())
		flag_enc = int(t.recvline().decode().strip().replace('ct = ', ''))
		ct_0 = int(receive_send(t,0))
		ct_1 = int(receive_send(t,1))
		flag = reverse_turbocrypt(ct_0,ct_1,flag_enc,p)
		if turbo_crypt(ct_0,ct_1,flag,p) == flag_enc:
			print("Flag Found !")
			print(long_to_bytes(flag))
			t.close()
			return

if __name__ == "__main__":
    solve(sys.argv[1])
    #All Good!
    #Flag Found !
    #b'HTB{C4lcU1u5_m33t5_Cryp70_c4n_y0u_8e1i3ve_17???}'



