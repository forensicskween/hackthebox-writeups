import json
from pwn import *
import sys
from crypto_attacks.shared.partial_integer import PartialInteger
from crypto_attacks.attacks.hnp import lattice_attack
from challenge import ECDSA

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn


def clean_apps(fname):
	with open(fname,'r') as inf:
		data = inf.read().split('\n')
	return data[1:-1]

def clean_sigs(fname):
	with open(fname,'r') as inf:
		data = inf.read().split('\n')
	sigs = [x.split(';') for x in data[1:-1]]
	hs = [int(x[0],16) for x in sigs]
	rs = [int(x[1],16) for x in sigs]
	ss = [int(x[2],16) for x in sigs]
	kk = [int(x[3],2) for x in sigs]
	kks = [PartialInteger.from_lsb(256,x,7) for x in kk]
	return hs,rs,ss,kk,kks

def recover_keys_nonces(fname):
	to_sign = b'william;yarmouth;22-11-2021;09:00'
	hs,rs,ss,kk,kks = clean_sigs(fname)
	cipher = ECDSA()
	key_,nonces = list(lattice_attack.dsa_known_lsb(cipher.n, hs, rs, ss, kks))[0]
	cipher.key = key_
	my_sig = cipher.sign(to_sign)
	verif = cipher.verify(to_sign,my_sig['r'],my_sig['s'])
	if ('HTB') in verif:
		return json.dumps({'pt' : to_sign.decode(), 'r': my_sig['r'], 's': my_sig['s']})


def solve(conn):
	to_send = recover_keys_nonces('signatures.txt')
	conn.sendlineafter(b'14 months\n> ', to_send.encode())
	res = conn.recvall().decode().strip()
	return res


if __name__ == "__main__":
	conn = get_conn(sys.argv[1])
	flag = solve(conn)
	print(flag)
#Your appointment has been confirmed, congratulations!
#Here is your flag: HTB{t3ll_m3_y0ur_s3cr37_w17h0u7_t3ll1n9_m3_y0ur_s3cr37_1fam31l}





