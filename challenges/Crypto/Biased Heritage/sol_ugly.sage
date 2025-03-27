from pwn import *
from hashlib import sha256
from Crypto.Util.number import isPrime, getPrime, long_to_bytes as l2b, bytes_to_long as b2l
import itertools
from sage.all import *
import sys

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn

#https://github.com/defund/coppersmith
def csmall_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()
    
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots



def sign_msg(g,x,p,q,msg=b'right hand',brute=False,sig=None):
    def H(msg):
        return b2l(2 * sha256(msg).digest()) % q
    if not brute:
        k =H(msg + l2b(x))
        r = pow(g, k, p) % q
        e = H(l2b(r) + msg)
        s = (k - x * e) % q
        return s, e 
    else:
        sv,ev = sig
        for i in range(x-2,x,x+2):
            k =H(msg + l2b(i))
            r = pow(g, k, p) % q
            e = H(l2b(r) + msg)
            s = (k - i * e) % q
            if (e==ev and s == sv):
                return i

def recover_x(e1,e2,s1,s2,q):
    Poly.<f1,f2> =  PolynomialRing(Zmod(q))
    bias = 2^256+1
    bounds = (2^256, 2^256)
    x1 = inverse_mod(e1,q)*((bias*f1)-s1)
    x2 = inverse_mod(e2,q)*((bias*f2)-s2)
    res_ = x1-x2
    #result_ = coppersmith.small_roots(res_,bounds,m=8,d=3)
    result_ = csmall_roots(res_,bounds,m=8,d=3)
    xv1 = x1.subs(f1=result_[0][0])
    xv2 = x2.subs(f2=result_[0][1])
    return (int(xv1),int(xv2))


def quick_verif(y,x,p):
    g = 3
    for i in range(x-4,x+4):
        yy = pow(g,i,p)
        if int(yy) == int(y):
            print('found x! ' + str(i))
            return i
        else:
            pass
    return None


def check_results(g,y,p,q,xv1,xv2):
    x0 = quick_verif(y,xv1,p)
    x1 = quick_verif(y,xv2,p)
    if x0 is not None:
        if x1 is not None:
            if x0 == x1:
                return b'right hand'.hex(), sign_msg(g,x0,p,q)
            else:
                pass
        else:
            pass
    return None


def receive_params():
    g = int(conn.recvline().decode().strip().split(': ')[-1])
    y = int(conn.recvline().decode().strip().split(': ')[-1])
    p = int(conn.recvline().decode().strip().split(': ')[-1])
    q = (p-1)//2
    return g,y,p,q

def send_sig(msg):
    conn.sendlineafter(b'> ', b'S')
    conn.sendlineafter(b'message> ', msg.hex())
    res = eval(conn.recvline().decode().strip().split(': ')[-1])
    s,e = res
    return (s,e)

def send_verif(msg,s,e):
    conn.sendlineafter(b'> ', b'V')
    conn.sendlineafter(b'message> ', msg)
    conn.sendlineafter(b's> ', str(s).encode())
    conn.sendlineafter(b'e> ', str(e).encode())
    res = conn.recvline().decode().strip()
    return res


def start(conn_params):
    global conn
    conn = get_conn(conn_params)
    g,y,p,q = receive_params()
    msg1 = os.urandom(16)
    s1,e1 = send_sig(msg1)
    msg2 = os.urandom(16)
    s2,e2 = send_sig(msg2)
    return g,y,p,q,msg1,s1,e1,msg2,s2,e2

#worked with gcd(e1,e2) = bias and gcd(s1,s2) = 1, gcd(k1/k2,xvv) = 1, gcd(k1,k2) = bias, gcd(flat1/flat2,xvv) = 1

def recover_it(conn_params):
    result = None
    while not result:
        g,y,p,q,msg1,s1,e1,msg2,s2,e2 = start(conn_params)
        xv1,xv2 = recover_x(e1,e2,s1,s2,q)
        result = check_results(g,y,p,q,xv1,xv2)
        if result:
            flag = send_verif(result[0],result[1][0],result[1][1])
            return flag
        else:
            conn.close()


if __name__ == "__main__":
    flag = recover_it(sys.argv[1])
    print(flag)

#HTB{unf027un4731y_7h3_n0nc3_1uck5_3n720py!!}



