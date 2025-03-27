# 🔐 Crypto Challenge

## 🏷️ Name: [Mind In The Clouds](https://app.hackthebox.com/challenges/348)

## 🔥 Difficulty: Hard

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Mysterious kidnappings of Longhir’s best scientists began to occur ever since Draeger gained influence in the council, a fact known to everyone in the troupe. Virgil was certain that these kidnappings had something to do with Meiro and the neuro-linked technology he helped develop. He also knew that Draeger wanted to experiment by uploading minds to the cloud and then connecting them to androids. These thoughts ran through Miyuki’s mind while she was searching for clues in the prison. After finding no signs that indicated a physical escape, she concluded that Draeger hadn’t actually escaped. Instead, he had somehow initiated a backup version of his mind, which he had downloaded into an unknown body. Upon hearing Miyuki’s conclusions, the team was in a rather charged mood. As you sit in the corner, almost paralyzed by the crippling news, you can only think of one thing: Is your father in the cloud/s too?

## 📂 Provided Files:
- **Filename:** `Mind In The Clouds.zip`

- **SHA-256 Hash:** `abfb696901f238c9bc90d495d8b418c1f7102ccdf62c0fc18227cc3597d405db`

# 🚀 Methodology  

## 🔎 1️⃣ Understanding the Cryptosystem  

This is an **ECDSA Cryptosystem** using the **P-256 curve**.  

The server provides three filenames, and we are given:  
- **Signatures** of the first two files.  
- **Partial nonces** (Middle Bits) of those signatures.  

From this, we can assume that the **goal is to find a valid signature for the third file (`subject_danbeer`)** to retrieve the flag.  

---

### **1.1 Server Functionality**  

The server offers **two main options**:  

#### **1️⃣ List Files**  
- This provides the **ECDSA signature** of a filename.  
- Also leaks **middle bits** of the nonce (but the leaked positions vary based on the filename).  

#### **2️⃣ Access Files**  
- If we can provide a **valid ECDSA signature** for a file, the server will return its contents.  

---

### **1.2 Leaked Nonce Information**  

In **ECDSA**, the nonce should be **randomly generated**:

```python
nonce_file_1 = randint(1, n-1)
nonce_1_bits = bin(nonce_file_1)[2:].rjust(256, '0')
leaked_nonce_1 = '?'*(14*4) + nonce_1_bits[14*4: -(14*4)] + '?'*(14*4)
assert int(leaked_nonce_1[14*4:-(14*4)], 2) == int(hex(nonce_file_1)[2:][14:-14], 16)
```

For the **two files**, the leaked **middle bits** are:  
- **Nonce 1:** **56.25% of bits known**  
- **Nonce 2:** **53.125% of bits known**  

Given that **`h` (hashed message) is also small (SHA-1, 160 bits)**, this should be easily solvable.

---

## ⚡ 2️⃣ Identifying Vulnerabilities  

There are multiple attacks that can be used to recover the **ECDSA nonce** in this scenario:  

### **1️⃣ Hidden Number Problem (HNP) Attack**  
A classical attack where partial nonce leaks allow us to recover the full nonce.  
- Implemented in **crypto-attacks**:  
  [HNP Lattice Attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py)  
- Based on:  
  **G. De Micheli & N. Heninger: "Recovering cryptographic keys from partial information, by example" (Section 5.2.3).**  

### **2️⃣ Coppersmith’s Small Roots Attack**  
Since **a large part of the nonce is already known**, we can solve it using **Coppersmith's method**.  
- Works efficiently when missing bits are small.  
- Can be applied to solve the **nonce recovery equation**.

---

## 🔨 3️⃣ Exploiting the Weakness  

The ECDSA equation:

$$
s = (\text{nonce}^{-1} \cdot (h + r \cdot d)) \mod n
$$

Rearrange:

$$
s \cdot \text{nonce} \mod n = (h + r \cdot d) \mod n
$$

which leads to:

$$
(r \cdot d) \mod n = (s \cdot \text{nonce} - h) \mod n
$$

Solving for **`d` (private key)**:

$$
d = \frac{(s \cdot \text{nonce} - h)}{r} \mod n
$$

---

### **Solving for `d` using Two Leaked Nonces**  

We express **nonce** in terms of **known bits**:

$$
\text{nonce} = (\text{MSB} + \text{middle bits} + \text{LSB})
$$

Rewriting `d`:

$$
d = \frac{s \cdot (\text{MSB} + \text{middle bits} + \text{LSB}) - h}{r} \mod n
$$

With two signatures and leaked nonce bits, subtracting both equations will **eliminate `d`**, allowing us to solve using **Coppersmith’s method**.

---

### **Implementing the Attack Using Coppersmith’s Small Roots**  

**Using the `coppersmith.sage` library:**  
[GitHub - Coppersmith Small Roots](https://github.com/defund/coppersmith/blob/master/coppersmith.sage)

#### **Generate the nonce equation:**
```python
def calculate_nonce_equation(pair, nonce, i):
    msb_bits, middle_bits = 2**(256 - ((14+i)*4)), 2**(14*4)

    MSB = int(hex(nonce)[2:][:(14 + i)], 16)
    MIDDLE = int(hex(nonce)[2:][(14 + i):-14], 16)
    LSB = int(hex(nonce)[2:][-14:], 16)
    
    nonce_eq = msb_bits * MSB + MIDDLE * middle_bits + LSB
    poly_dict = {k: v for k, v in zip(pair, [MSB, LSB])}
    assert nonce_eq == nonce

    poly_eq = msb_bits * pair[0] + MIDDLE * middle_bits + pair[1]
    
    assert poly_eq.subs(poly_dict) == nonce

    return poly_eq, poly_dict, 2**((14+i)*4)
```

#### **Generate values for debugging:**
```python
def generate_debug_values(fname, pair, i):
    data = ecc.sign(fname)
    h = bytes_to_long(sha1(fname).digest())
    r, s, nonce = int(data['r'], 16), int(data['s'], 16), int(data['nonce'], 16)
    poly_eq, poly_dict, msbn = calculate_nonce_equation(pair, nonce, i)
    equation = ((poly_eq) * s - h) / r
    return equation, poly_dict, msbn
```

#### **Setting up the attack:**
```python
ecc = ECDSA()
fnames = [b'subject_kolhen', b'subject_stommb']
d = ecc.privkey.secret_multiplier

my_poly.<msb1, msb2, lsb1, lsb2> = PolynomialRing(Zmod(n))

eq1, d1, msbn1 = generate_debug_values(fnames[0], [msb1, lsb1], 0)
eq2, d2, msbn2 = generate_debug_values(fnames[1], [msb2, lsb2], 2)
poly_dicts = d1 | d2
assert eq1.subs(poly_dicts) == eq2.subs(poly_dicts) == d

equation = eq2 - eq1
bounds = (msbn1, msbn2, 2**(14*4), 2**(14*4))
roots = {x: v for x, v in zip(my_poly.gens(), coppersmith.small_roots(equation, bounds, m=2, d=2)[0])}
assert eq1.subs(roots) == d
```

---

## 🔑 4️⃣ Recovering the Flag  

Once we **recover `d` (private key)**, we can **forge a valid signature** for `subject_danbeer`:

```python
ecc = ECDSA()
ecc.key = d
ecc.pubkey = Public_key(ecc.G, ecc.key * ecc.G)
ecc.privkey = Private_key(ecc.pubkey, ecc.key)

signature = ecc.sign(b'subject_danbeer')
signature['fname'] = 'subject_danbeer'
signature['option'] = 'access'
```

### **Final Step:**
Send the **forged signature** to the server, and it should **return the flag!** 

---

# 🏁 Solution & Commands

```python

from pwn import remote
from crypto_attacks.shared.small_roots import coppersmith
from source import ECDSA,fnames,Public_key,Private_key
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha1

import json

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



ecc = ECDSA()
my_poly.<msb1,msb2,lsb1,lsb2> = PolynomialRing(Zmod(int(ecc.n)))
bounds = [2**57, 2**65, 2**57, 2**57]
pairs = [[msb1,lsb1],[msb2,lsb2]]

conn = remote('94.237.59.30','48182')
conn.recvuntil(b'2.Access a file\n')
conn.sendline(json.dumps({'option':'list'}).encode())
response = conn.recvline()
equations = load_list_payload(response,pairs)
equation = equations[0]-equations[1]
roots = coppersmith.small_roots(equation,bounds,m=2,d=2)

if roots:
    poly_dict = {x:v for x,v in zip(my_poly.gens(),roots[0])}
    d = int(equations[0].subs(poly_dict))

ecc.key = d
ecc.pubkey = Public_key(ecc.G, ecc.key * ecc.G)
ecc.privkey = Private_key(ecc.pubkey, ecc.key)
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


```

**🚩 Final Flag:** `HTB{m@st3r1ng_LLL_1s_n0t_3@sy_TODO}`

