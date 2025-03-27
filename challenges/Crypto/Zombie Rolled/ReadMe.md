
# 🔐 Crypto Challenge


## 🏷️ Name: [Zombie Rolled](https://app.hackthebox.com/challenges/629)

## 🔥 Difficulty: Hard

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description

> With the formula now in your team&#039;s possession, you face a significant challenge. The formula is constructed upon an exceedingly advanced equation that surpasses your current comprehension of mathematics. A note suggests a flaw, but the intricacies appear much too complex. It&#039;s crucial for the equation to be genuinely secure and not break in edge cases. Can you analyze this complex equation to bring an end to this tragic situation once and for all?
> 
## 📂 Provided Files:

- **Filename:** `Zombie_Rolled.zip`

- **SHA-256 Hash:** `56f77a479e55957b2b7a37cfe46f2a7f3b7c5a80ddf31446ad1024128453d093`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem
  

This is a custom Cryptosystem based on a mix of number theory and fractional exponentiaon principles.

  

We aren’t given the function to derive the public_key, but there are some hints about its property.

  

- The Private Key is a tuple of three primes of 1024 bits

  

### **1. Function Magic**

  

The function ‘magic’ is probably the most essential part of the cryptosystem, because:

  

```python

def magic(ar):

a, b, c = ar

return Fraction(a+b, b+c) + Fraction(b+c, a+c) + Fraction(a+c, a+b)

  

magic(priv) == magic(pub)

```

  

Magic is defined as:

  

$$\frac{a + c}{a + b} + \frac{a + b}{b + c} + \frac{b + c}{a + c}$$

  

Which further expands to:

  

$$\frac{(a + b)^2 (a + c) + (a + c)^2(b + c) + (a + b)(b + c)^2}{(a + b)(a + c)(b + c)}$$

  
```math
\frac{a^3 + 3a^2b + 2ab^2 + b^3 + 2a^2c + 6abc + 3b^2c + 3ac^2 + 2bc^2 + c^3}{a^2b + ab^2 + a^2c + 2abc + b^2c + ac^2 + bc^2}
```

  

The fact that \(magic(priv) == magic(pub)\) means there is **rational equality constraint** on the variables.

  

**Breaking it down:**

  

The denominator satisfies the following:

  

$$
\begin{aligned}
(a + b) &\equiv 0 \mod \gcd(D, a + b) \\
(a + c) &\equiv 0 \mod \gcd(D, a + c) \\
(c + b) &\equiv 0 \mod \gcd(D, c + b)
\end{aligned}
$$

  

This is important because D and (a+b) or whatever can hold another common factor.

  

Which further means that:

$$
\begin{aligned}
(\text{priv}_a + \text{priv}_b) &\equiv 0 \pmod{\gcd(\text{priv}_a + \text{priv}_b,\ \text{pub}_a + \text{pub}_b)} \\
(\text{priv}_a + \text{priv}_c) &\equiv 0 \pmod{\gcd(\text{priv}_a + \text{priv}_c,\ \text{pub}_a + \text{pub}_c)} \\
(\text{priv}_b + \text{priv}_c) &\equiv 0 \pmod{\gcd(\text{priv}_b + \text{priv}_c,\ \text{pub}_b + \text{pub}_c)}
\end{aligned}
$$


And this it means that :

$$
\begin{aligned}
\text{priv}_a + \text{priv}_c &\equiv 0 \pmod{\gcd\big(\gcd(D,\ \text{pub}_a + \text{pub}_c),\ \text{priv}_a + \text{priv}_c\big)} \\
\text{priv}_a + \text{priv}_b &\equiv 0 \pmod{\gcd\big(\gcd(D,\ \text{pub}_a + \text{pub}_b),\ \text{priv}_a + \text{priv}_b\big)} \\
\text{priv}_b + \text{priv}_c &\equiv 0 \pmod{\gcd\big(\gcd(D,\ \text{pub}_c + \text{pub}_b),\ \text{priv}_b + \text{priv}_c\big)}
\end{aligned}
$$


So the private key is recoverable. There are two approaches to solving this problem which I will explain further.

  

### **2. The encryption** and **signing** functions:

  

- The class is initialised with the the private key , public key and $n$ - the product of private key.

- The **public exponent** $e$ is the **numerator** of $magic(pub)$ , which is equal to $magic(priv)$.

- The **private exponen**t $d$ is calculated as the modular inverse of $e \mod phi(N)$.

  

1. **Encryption and Decryption:**

  

The encryption/decryption follow standard RSA practice.


  

Where Encryption is :

  

$$c = m^e\mod N$$

  

and Decryption is:

  

$$m = c^d\mod N$$

  

1. **Signing:**

  

The signing function is a bit more complex:

  

```python

def fraction_mod(f, n):
    return f.numerator * pow(f.denominator, -1, n) % n

nb = ((1024*3)+7)//8 # 384 (more or less)

h = bytes_to_long(sha256(m.to_bytes(nb, "big")).digest())
a,b = m,h

c = randbelow(1 << nb)

magic_abc = magic((a, b, c))
r = fraction_mod(magic_abc,n)

s1 = decrypt(r)
s2 = decrypt(c)
```

  

Breaking it down it gives us:

  

```python

h = bytes_to_long(sha256(m.to_bytes(nb, "big")).digest())
c = randbelow(1 << 384)

magic_abc_numerator = c^3 + 2*c^2*h + 3*c*h^2 + h^3 + 3*c^2*m + 6*c*h*m + 2*h^2*m + 2*c*m^2 + 3*h*m^2 + m^3
magic_abc_denominator = (c + h)*(c + m)*(h + m)

r = magic_abc_numerator * pow(magic_abc_denominator,-1,n)%n

s1 = pow(r,d,n)
s2 = pow(c,d,n)

```

  

In SageMath we actually don’t even need fraction_mod, I mean this is just a detail but helpful to know.

  

```python

def magicqq(ar):
    a,b,c = [QQ(x) for x in ar]
    return ( a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)

magicqq((m,h,c))%n == fraction_mod(key.magic((m, h, c)),n)

```

  

1. **Verifying:**

To verify a signature, it follows a logical process:

```python

s1,s2 = sig

h = bytes_to_long(sha256(m.to_bytes(nb, "big")).digest())

r,c = encrypt(s1,n),encrypt(s2,n)

r == fraction_mod(key.magic((m, h, c)),n)

```

  

### **3. The Flag Encryption:**

  

Well it doesn’t end here for us 🥲. The after signing the message, the signature is then **mixed**:

  

```python

mix = [sig[0] + sig[1], sig[0] - sig[1]]
mix = [key.encrypt(x) for x in mix]

```

  

Anyways, this is a breakdown of how this whole thing functions.

  

### ⚡ 2️⃣ Identifying Vulnerabilities

  

This problem isn’t necessarily about finding vulnerabilities, it’s more of a math problem if anything. It was actually cool for me to do this challenge, because I have literally 0 background in math, so I learned a lot of interesting things in the process.

  

The two main things for this challenge are the following:

- Recovering the private key

- Recovering the message (since we don’t know the value of $m$ and $h$ ; we have a small roots problem)


1. **Private Key Recovery**

I found two 'methods' to recover the private key. The first one is the more straightforward version, this relies on the properties of the GCD.

  

- **Bruteforce Method:**

We established that

$$priv_a+ pub_b = 0 \mod gcd(D,pub_a+pub_b)$$

BUT :

$$priv_a+priv_b \neq gcd(D,pub_a+pub_b)$$

That is because some coefficients are lost when converting the integers to Rational.

So we can get the approximate values:

```python

G1 = gcd(D,pub_a+pub_c)
G2 = gcd(D,pub_b+pub_a)
G3 = gcd(D,pub_b+pub_c)

X1 = gcd(G1,G2)
X2 = gcd(G3,G2)
X3 = gcd(G1,G3)

```

Next, to make a bruteforce attack, we can simply some things by checking the bit length of the values. We know that two primes of 1024 bits will result to approximatively 1025 bits when added together. So we can estimate what range of factors we need to perform the bruteforce attack.

Probably not the most sophisticated way to do this but it works…

```python

from itertools import product

def magicqq(ar):
    a,b,c = [QQ(x) for x in ar]
    return ( a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)


def gen_eqs(ar,pr=False):
    if pr:
        ab,bc,ac = ar
    else:
        a,b,c = ar
        ab = (a+b)
        bc =  (b+c)
        ac = (a+c)
    lcd = bc*ac*ab
    f1_exp = ab*ac*ab
    f2_exp = ab*bc*bc
    f3_exp = bc*ac*ac
    return (f1_exp,f2_exp,f3_exp,lcd)

def gen_coeffs(values):
    bls,x_values,skip =[],{},{}
    for k,v in values.items():
        target_bl = 1025-v.bit_length()
        if target_bl == 0:
            skip[k] = v
            continue
        else:
            x_values[k] = v
            bls.append(range(2**(target_bl-1),2**(target_bl+1)))
    return bls,x_values,skip


def recover_primes_bruteforce(X1,X2,X3,pub):
    map_result= {'X1':X1,'X2':X2,'X3':X3}
    coeffs,x_values,skip = gen_coeffs(map_result)
    for coeff in product(*coeffs):
        result = {k:v*y for (k,v),y in zip(x_values.items(),coeff)} | skip
        result_b = -((result['X3']-result['X2'])-result['X1'])
        if result_b%2 ==0:
            result_b = result_b//2
            result_c = result['X1'] - result_b
            result_a = result['X3'] - result_c 
            if magicqq((result_a,result_b,result_c)) == magicqq(pub):
                print(f'Recovered Private Key {(result_a,result_b,result_c)}')
                return (result_a,result_b,result_c)

```

and this actually works!

- **Elliptic Curve Method**

The actual intended I assume (or I hope) is a lot more sophisticated and *cool.*

So, the fractions are calculated and expanded into:

$$
\begin{aligned}
\text{num}_1 &= (a + b)^2 \cdot (a + c) \\
\text{num}_2 &= (a + b) \cdot (b + c)^2 \\
\text{num}_3 &= (a + c)^2 \cdot (b + c) \\
\text{num}   &= \text{num}_1 + \text{num}_2 + \text{num}_3 \\
\text{denom} &= (a + b) \cdot (a + c) \cdot (b + c)
\end{aligned}
$$


Which actually … is a lot more logical than this:

$$\frac{a}{a + b} + \frac{a}{b + c} + \frac{b}{a + c} + \frac{b}{b + c} + \frac{c}{a + b} + \frac{c}{a + c}$$

  

and can be rewritten as:

  

$$\frac{a^2 + 2ab + ac}{(a + b)(b + c)} + \frac{b^2 +2bc + ab}{(a + c)(b + c)} + \frac{c^2 + 2ac + bc}{(a + b)(a + c)}$$

  

BUTT guess what, the numerator has a degree 3; meaning it’s cubic, meaning it can be solved using Elliptic Curve.

Basically, this structure defines a **projective elliptic curve**.
Since the public key satisfies the `magic` equation, it can be interpreted as a point `G` on this elliptic curve. **Point doubling in Elliptic Curve results in another point that also lies on the curve**. This means that it will preserve the structure/'law' defined by the `magic` function.

To recover the private key using this approach:
- We take the inverse mapping of the curve and use it to return from projective coordinates to affine coordinates.  
- The defining polynomial of the elliptic curve is used to ensure that any candidate point satisfies the curve’s equation; it's also used to generate alternate representations of the point in rational form.
- The use of `division_points(2)` computes all possible points `P` such that `2·P = G`. Recovering such a `P` (and then inverting it from projective space) gives us values that satisfy the same `magic` equation — which basically reconstructs the private key.


```python

  
def magicq(a,b,c):
    return ( a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)

def gen_pub_equation(pub):
    p, q, r = map(ZZ, pub)
    rhs = magicq(p,q,r)
    P = QQ["a, b, c"]
    a, b, c = P.gens()
    eq =  rhs-magicq(a,b,c)
    f = EllipticCurve_from_cubic(eq.numerator(), [-1, 1, 1])
    fi = f.inverse()
    G = f([p, q, r])
    aa, bb, cc = fi(2 * G)
    l = lcm(lcm(aa.denom(), bb.denom()), cc.denom())
    aa, bb, cc = ZZ(aa * l), ZZ(bb * l), ZZ(cc * l)
    assert magicq(aa,bb,cc) == rhs
    pub = (int(aa), int(bb), int(cc))
    return f,fi,pub
  

def make_g2(pub,f):
    G2 = [QQ(pub[0])/QQ(pub[-1]), QQ(pub[1])/QQ(pub[-1]),QQ(pub[-1])/QQ(pub[-1])]
    PP=[x(list(G2)) for x  in f.defining_polynomials()]
    return PP


def recover_priv_key(pub):
    f,fi,_ = gen_pub_equation(pub)
    point_g2 = make_g2(pub,f)
    G2 = f(fi(point_g2))
    G2_div = G2.division_points(2,poly_only=True).roots()
    G = f.codomain().lift_x(G2_div[0][0])
    G_inv = fi(G)
    priv_key = (G_inv[0].numerator(),G_inv[1].numerator(),G_inv[1].denominator())
    _,_,pub_check = gen_pub_equation(priv_key)
    assert pub_check == pub
    return priv_key


```

  

### 🔨 3️⃣ Exploiting the Weakness

  

The second part of the challenge is to recover the message. At this point it is assumed the private key is recovered.

  

**Step 1:** *Unmix* the signature

  

The ‘mix’ was done by doing:

  

$$s1 +s2,s1-s2$$

  

Which means that:

  

$$
\begin{aligned}
s_2 &= ( \text{mix}_1 - \text{mix}_2 ) \cdot 2^{-1} \bmod N \\
s_1 &= ( \text{mix}_1 - s_2 ) \bmod N
\end{aligned}
$$


  

```python

key = PrivateKey(priv,pub,prod(priv))

unmixed = [key.decrypt(x) for x in mix]

s2 = (unmixed[0]-unmixed[1])*pow(2,-1,key.n)%key.n
s1 = (unmixed[0]-s2)%key.n

```

  

**Step 2:** Calculate the known values

  

The second part of the problem, is that m and h are unknown; and are integeral to verify the signature and how the signature was generated. We can create a polynomial to represent those in variables

  

```python

r, c = key.encrypt(s1),key.encrypt(s2)

  
poly.<a,b> = PolynomialRing(Zmod(key.n))


magic_n = a^3 + 3*a^2*b + 2*a*b^2 + b^3 + 2*a^2*c + 6*a*b*c + 3*b^2*c + 3*a*c^2 + 2*b*c^2 + c^3
magic_d = a^2*b + a*b^2 + a^2*c + 2*a*b*c + b^2*c + a*c^2 + b*c^2

```

  

Problem is in SageMath we can’t just do magic_n/magic_d over $\mathbb{Z}_N$. BUTTT rejoice, because the fraction_mod function takes the inverse of the denominator.

  

*Group Theory Recap*

  

In modular arithmetic, the **multiplicative group of units modulo** $n$ is defined as:


$$(\mathbb{Z}/n\mathbb{Z})^* = \{ x \in \mathbb{Z}/n\mathbb{Z} \mid \gcd(x, n) = 1 \}$$


  

This set forms a group under multiplication modulo $n$, satisfying the standard group axioms: closure, associativity, identity, and inverses.

  

- **Closure**: Combining two elements in the group must yield an element within the same group

- **Associativity**: Operations must be associative; so (a*b)*c == a*(b*c)

- 🚨 **Identity Element:** There’s an element $e$ in the group that satisfies:

$$a \cdot e = e \cdot a = a$$

- 🚨**Inverse Element :** For every element in the group; there must be an inverse of that element that gives us the identity element:

  

$$x^{-1}\cdot x= x \cdot x^{-1} = e$$

  

The point is, that as opposed to working in the Rational or Integer field, we are working with a group. So for our problem:

  

$$
\begin{aligned}
\text{magic}_n \cdot \text{magic}_d^{-1} &\equiv r \pmod{N} \\
r \cdot \text{magic}_d - \text{magic}_n &\equiv 0 \pmod{N}
\end{aligned}
$$

  

This is some magic lol.

  

If we knew h, (and had a much bigger m) we could’ve solved like this:

  

```python

P_1.<b> = PolynomialRing(GF(priv[0]))
P_2.<b> = PolynomialRing(GF(priv[1]))
P_3.<b> = PolynomialRing(GF(priv[2]))

fx = (r*magic_d -magic_n).subs(b=h).univariate_polynomial().monic()

f1 = fx.change_ring(P_1)
f2 = fx.change_ring(P_2)
f3 = fx.change_ring(P_3)

roots = [[ZZ(y[0]) for y in x.roots()] for x in [f1,f2,f3]]

m = int(crt([x[0] for x in roots],list(priv)))

assert key.verify(int(m),sig)

```

  

but for our target m, simply one polynomial would’ve been enough. *ANYWAYS.*

  

### 🔑 4️⃣ Recovering the Flag

  

To find the small roots (because $m$ and $h$ are in fact very small relative to $N$), we can use [defund’s coppersmith](https://github.com/defund/coppersmith/blob/master/coppersmith.sage) implementation.

  

After experimenting with a few bounds for the flag, 32 worked!

  

```python

fx = (r*magic_d -magic_n)

bounds = (2**(32*8),2**256)
roots = coppersmith.small_roots(fx,bounds)

for v in roots:
	m = int(v[0])
	if key.verify(m,(s1,s2)):
		print(m.to_bytes((m.bit_length() + 7) // 8,'big').decode())

```

  

**🚩 Final Flag: HTB{3CC_1s_m4g1c___15nt_1t?!}**
