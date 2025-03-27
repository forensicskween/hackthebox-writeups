# 🔐 Crypto Challenge

## 🏷️ Name: [Waiting List](https://app.hackthebox.com/challenges/272)

## 🔥 Difficulty: Hard

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Your mechanical arm needs to be replaced. Unfortunately, Steamshake Inc which is the top mechanical arm transplants has a long waiting list. You have found a SQL injection vulnerability and recovered two tables from their database. Could you take advantage of the information in there to speed things up? Don&amp;#039;t forget, you have a date on Monday!

## 📂 Provided Files:
- **Filename:** `Waiting List.zip`

- **SHA-256 Hash:** `7831d2251a47392231b8d9c6231595b26121f8d0fd468a36e95e0e5c4fc7b41a`

# 🚀 Methodology

---

## 🔎 1️⃣ Understanding the Cryptosystem

We are given three files:
- `signatures.txt`
- `appointments.txt`
- `challenge.py`

The objective is to forge a valid **ECDSA signature** for the message:

```
'william;yarmouth;22-11-2021;09:00'
```

### **ECDSA Signing Process**
The signing process follows a typical **ECDSA** flow:

1. Compute **SHA-1 hash** of the message, interpreted as an integer:

   $$   h = \text{SHA1}(\text{message})
   \]

2. Generate a **random nonce** $k$.
3. Compute the ECDSA signature components:
   - $r = (g^k \mod n)_x$
   - $s = k^{-1} (h + d \cdot r) \mod n$
4. **Leak the 7-bit Least Significant Bits (LSB) of the nonce** $k$.
5. Output **(h, r, s, LSB(k))**.

To verify that `signatures.txt` corresponds to `appointments.txt`, we compute:

$$h_i = \text{SHA1}(\text{appointments}[i])$$

This confirms that `signatures.txt` contains valid ECDSA signatures for the listed appointments.

---

## ⚡ 2️⃣ Identifying Vulnerabilities

The vulnerability arises because the **7-bit LSB of the nonce** $k$ is leaked. This allows us to solve for the private key $d$ using a **Hidden Number Problem (HNP) attack**.

### **ECDSA Equation Breakdown**
For each signature \((r, s)\), the equation holds:

$$s_i k_i \equiv H(m_i) + d \cdot r_i \pmod{n}$$

Since the **7-bit LSB** of each $k_i$ is leaked, we rewrite:

$$k_i = k_i' + K_i$$

where:
- $K_i$ is the **known 7-bit LSB** of $k_i$.
- $k_i'$ is the **unknown upper 249 bits** of $k_i$.

Substituting into the ECDSA equation:

$$s_i (k_i' + K_i) \equiv H(m_i) + d \cdot r_i \pmod{n}$$

Expanding:

$$s_i k_i' \equiv H(m_i) + d \cdot r_i - s_i K_i \pmod{n}$$

Define:

$$v_i = H(m_i) + d \cdot r_i - s_i K_i$$

Thus, we obtain the **HNP instance**:

$$s_i k_i' \equiv v_i \pmod{n}$$

where:
- $k_i'$ is the unknown part of the nonce.
- $s_i$ and $v_i$ are known.

This structure allows us to apply **lattice reduction techniques** to recover $d$.

---

### **Estimating the Minimum Number of Required Signatures**
We use the formula:

$$m = \frac{256}{b}$$

where:
- $b = 7$ (bits leaked per nonce).
- $256$ is the full key size.

$$m = \frac{256}{7} \approx 36.57$$

Since we have **200 leaked nonces**, this is **more than enough** to solve the problem.

We verify this with:

```python
lsb_bits_list_bl = [x[-1].bit_length() for x in signatures]
avg_leaked_bits = sum(lsb_bits_list_bl) / len(lsb_bits_list_bl)
minimum_required_sigs = 256 / avg_leaked_bits
print(minimum_required_sigs)  # Output: ~42
```

---

## 🔨 3️⃣ Exploiting the Weakness

We now construct a **lattice** where solving for $d$ becomes equivalent to solving a **Bounded Distance Decoding (BDD) problem**.

We construct the lattice using:

$$v_i = H(m_i) + d \cdot r_i - s_i K_i$$

$$s_i k_i' \equiv v_i \pmod{n}$$

We represent this system in a **lattice matrix** and apply **LLL/BKZ lattice reduction** to recover a short vector corresponding to the private key.

This github repo has an attack implemented https://github.com/bitlogik/lattice-attack

```python
def create_lattice(signatures):
    num_sigs = len(signatures)
    lattice = Matrix(QQ,num_sigs + 2, num_sigs + 2)
    num_bits = 7
    k_bits = 2**7
    inverse_kbits =  pow(k_bits,-1,n)
    for i in range(num_sigs):
        h,r,s,lsb = signatures[i]
        s_inv = pow(s,-1,n)
        lattice[i, i] = 2 * k_bits * n
        lattice[num_sigs, i] = 2 * k_bits * (inverse_kbits * (r * s_inv)%n) #represents the coefficient d in our equations
        lattice[num_sigs + 1, i] = 2 * k_bits * (inverse_kbits * (lsb - h * s_inv)%n)  + n #incorporates lsb in system
    lattice[num_sigs, num_sigs] = 1
    lattice[num_sigs + 1, num_sigs + 1] = n
    return lattice


def find_potential_key(lattice,signatures):
    reduced_lattice = lattice.LLL()
    candidate = [row[-2] % n for row in reduced_lattice]
    for potential_key in set(candidate):
        if all(verify(x,potential_key) for x in signatures):
            print(f'Found Key {potential_key}')
            return potential_key
```

---

## 🔑 4️⃣ Recovering the Flag

We need to recover the private key, then generate a valid signature. Afterwards, send the siganture to the server. 


---

# 🏁 Solution & Commands

```python


from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha1
import json
from pwn import remote

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

def read_appointments():
    with open('appointments.txt','r') as inf:
        data = inf.read().strip().split('\n')
    return data[1:]

def calculate_hash(message):
    h = sha1(message).digest()
    h = bytes_to_long(h)
    h = bin(h)[2:]
    h = int(h[:len(bin(n)[2:])], 2)
    return h 

def read_signatures():
    signatures = []
    with open('signatures.txt','r') as inf:
        for line in inf.readlines():
            if line.strip() == 'h;r;s;k_lsb':
                continue
            else:
                sig_data = line.strip().split(';')
                sig_data = [int(x,16) for x in sig_data[:-1]]+[int(sig_data[-1],2)]
                signatures.append(sig_data)

    return signatures


def create_lattice(signatures):
    num_sigs = len(signatures)
    lattice = Matrix(QQ,num_sigs + 2, num_sigs + 2)
    num_bits = 7
    k_bits = 2**7
    inverse_kbits =  pow(k_bits,-1,n)
    for i in range(num_sigs):
        h,r,s,lsb = signatures[i]
        s_inv = pow(s,-1,n)
        lattice[i, i] = 2 * k_bits * n
        lattice[num_sigs, i] = 2 * k_bits * (inverse_kbits * (r * s_inv)%n) #represents the coefficient d in our equations
        lattice[num_sigs + 1, i] = 2 * k_bits * (inverse_kbits * (lsb - h * s_inv)%n)  + n #incorporates lsb in system
    lattice[num_sigs, num_sigs] = 1
    lattice[num_sigs + 1, num_sigs + 1] = n
    return lattice

def verify(sig_item,key):
    h,r,s,lsb = sig_item
    c = pow(s, -1, n)
    k = (c *(h +key*r)) %n
    return r == pow(5,k,n)


def sign(pt,priv_key):
    h = calculate_hash(pt.encode())
    k = randint(1, n-1)
    r = pow(5, k, n)
    s = (pow(k, -1, n) * (h + priv_key * r)) % n
    return {'pt':pt,'r':hex(r),'s':hex(s)}

def find_potential_key(lattice,signatures):
    reduced_lattice = lattice.LLL()
    candidate = [row[-2] % n for row in reduced_lattice]
    for potential_key in set(candidate):
        if all(verify(x,potential_key) for x in signatures):
            print(f'Found Key {potential_key}')
            return potential_key
    



appointments = read_appointments()
signatures = read_signatures()
lattice = create_lattice(signatures)
priv_key = find_potential_key(lattice,signatures)
signature = sign('william;yarmouth;22-11-2021;09:00',priv_key)

conn = remote('83.136.249.46','55277')
conn.sendlineafter(b'> ',json.dumps(signature).encode())
conn.interactive()


```

**🚩 Final Flag:** `HTB{t3ll_m3_y0ur_s3cr37_w17h0u7_t3ll1n9_m3_y0ur_s3cr37_1fam31l}`

