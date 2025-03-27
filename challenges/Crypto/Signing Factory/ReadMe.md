# 🔐 Crypto Challenge

## 🏷️ Name: [Signing Factory](https://app.hackthebox.com/challenges/641)

## 🔥 Difficulty: Medium

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> After studying about vulnerabilities on signing servers, a group of researchers gathered one night and comitted into creating a modern and more secure way of signing tokens for authentication. They are certain that their product is ready for distribution and want to do a last security audit before publicizing their work. They provided you with access to the server. Is their way of signing messages the solution to all previous attacks?

## 📂 Provided Files:
- **Filename:** `Signing Factory.zip`

- **SHA-256 Hash:** `835878a347302ec58341af5ab1c73ca89d2e966472f0fb53a5056bd2b9b5eb16`

# 🚀 Methodology

## 🔎 Step 1: Understanding the Cryptosystem

The server offers three key functionalities:

1. **Signing a username**:
   - The username must match the regex pattern `[a-zA-Z0-9]`.
   - The username is converted to an integer and must satisfy:
     ```
     username_int % golden_ratio != signer.admin % golden_ratio
     ```
   - The integer username is hashed using `hash_var`, then signed using RSA:
     ```
     token = pow(hash_var(username_int), rsa.private_key, rsa.modulus)
     ```

2. **Providing a token and username for authentication**:
   - The server hashes the numeric representation of the username.
   - If `username == signer.admin` and the token is valid, we get the flag.
   - Token verification:
     ```
     hash_var(numeric_username) == pow(provided_token, rsa.public_exponent, rsa.modulus)
     ```
     
3. **Solving equations to recover the RSA modulus (`n`)**:
   - The server provides modular equations derived from `signer.n`.
   - If we compute `hash_var(n)`, we can recover `n`.

### **Hasher Function**

The hasher is defined as:
```python
hash_var = lambda key: (((key % golden_ratio) * golden_ratio) >> 32)
```
Rewriting it:
```python
hash_var(key) = ((key % golden_ratio) * golden_ratio) // (2**32)
hash_var(key) = (key - (key // golden_ratio) * golden_ratio) * golden_ratio // (2**32)
```

The goal is to compute `hash_var(admin)` to generate a valid authentication token.

---

## ⚡ Step 2: Identifying Vulnerabilities

### Weaknesses:
1. **Golden Ratio is Too Small**: 
   - `golden_ratio = 2654435761`, which is prime but small enough to find modular collisions efficiently.

2. **Collision Exploitation**:
   - Direct hash collision is not feasible due to modulo constraints.
   - Instead, we find a collision for the **prime factors of `hash_var(admin)`**.
   - We factorize `hash_var(admin)`:
     ```
     hash_var(admin) = 67 * 16645487
     ```
   - By generating usernames that hash to these prime factors, we can forge a valid signature using the RSA signature multiplication property.
   - This method works because in RSA:
     ```
     pow(a, d, n) * pow(b, d, n) ≡ pow(a * b, d, n) (mod n)
     ```
     which allows us to reconstruct `pow(hash_var(admin), d, n)` using two separate signatures.

### **Finding Valid Usernames for Collision**
We solve for:
```python
H = (h_factor * (2**32)) // golden_ratio + i * golden_ratio + 1
```
where `i` ensures that `H` passes the regex check.

We generate valid usernames for `67` and `16645487` that hash correctly.

---

## 🔨 Step 3: Exploiting the Weakness

### **1. Recovering `n`**
```python
def parse_equation(equations):
    h_factors = []
    for eq in equations:
        rnd, result = int(eq.split(', ')[1]), int(eq.split('= ')[-1])
        h_factors.append((pow(rnd, -1, golden_ratio) * result) % golden_ratio)
    return prod(h_factors)

def recover_n():
    conn.sendlineafter(b'Option >> ', b'2')
    conn.recvuntil(b'following equations:\n')
    equations = eval(conn.recvline().decode().strip())
    h_n = parse_equation(equations)
    conn.sendlineafter(b"Enter the hash(N): ", str(h_n).encode())
    if conn.recvline().decode().strip() == '[+] Captcha successful!':
        e, n = eval(conn.recvline().decode().strip().split('=')[1])
        return e, n
    return False
```

### **2. Finding Collision for `hash_var`**
```python
def find_h_factor(h_factor):
    start_value = (h_factor * (2**32)) // golden_ratio
    for i in range(1, 2**16):
        try:
            H = (start_value + i * golden_ratio + 1)
            if hash_var(H) == h_factor:
                if not rsearch('[^a-zA-Z0-9]', l2b(H).decode()):
                    return l2b(H).decode()
        except:
            continue
```

### **3. Registering Usernames & Getting Signatures**
```python
def register(username):
    conn.sendlineafter(b'Option >> ', b'0')
    conn.sendlineafter(b"Enter a username: ", username)
    res = conn.recvline().decode().strip()
    if res.startswith('Your session token is'):
        token_int = int(base64.b64decode(res[24:-1]).decode())
        return token_int
    return False
```

### **4. Forging the Valid Token**
We use the RSA signature multiplication property:
```python
s1 = pow(hash_var(factor1), d, n)
s2 = pow(hash_var(factor2), d, n)
s3 = (s1 * s2) % n
```
Since `s3` is a valid signature for `hash_var(admin)`, we authenticate with:
```python
def login(token):
    token_b64 = base64.b64encode(str(token).encode())
    conn.sendlineafter(b'Option >> ', b'1')
    conn.sendlineafter(b"Enter your username: ", b'System_Administrator')
    conn.sendlineafter(b"Enter your authentication token: ", token_b64)
    return conn.recvline().decode().strip()
```

---

### 🔑 4️⃣ Recovering the Flag

We register both usernames for `67` and `16645487` (c1 and c2).

We multiply the signatures to get `pow(hash_var(admin),rsa.private_key,rsa.modulus)`.

We login ... 


# 🏁 Solution & Commands

```python

from pwn import remote
import base64
from Crypto.Util.number import long_to_bytes as l2b
from re import search as rsearch

golden_ratio = 2654435761
admin = int.from_bytes(b'System_Administrator','big')
hash_var = lambda key: (((key % golden_ratio) * golden_ratio) >> 32)
target_h = hash_var(admin)

def parse_equation(equations):
    h_factors = []
    for eq in equations:
        rnd,result = int(eq.split(', ')[1]),int(eq.split('= ')[-1])
        h_factors.append((pow(rnd,-1,golden_ratio)*result)%golden_ratio)
    return prod(h_factors)

def recover_n():
    conn.sendlineafter(b'Option >> ',b'2')
    conn.recvuntil(b'following equations:\n')
    equations = eval(conn.recvline().decode().strip())
    h_n = parse_equation(equations)
    conn.sendlineafter(b"Enter the hash(N): ",str(h_n).encode())
    result = conn.recvline().decode().strip()
    if result == '[+] Captcha successful!':
        e,n = eval(conn.recvline().decode().strip().split('=')[1])
        return e,n
    return False


def find_h_factor(h_factor):
    start_value = (h_factor*(2**32))//golden_ratio
    for i in range(1,2**16):
        try:
            H = (start_value+i*golden_ratio+1)
            if hash_var(H) == h_factor:
                if not rsearch('[^a-zA-Z0-9]', l2b(H).decode()):
                    return l2b(H).decode()
        except:
            continue


def register(username):
    conn.sendlineafter(b'Option >> ',b'0')
    conn.sendlineafter(b"Enter a username: ",username)
    res = conn.recvline().decode().strip()
    if res[:21]=='Your session token is':
        token_int = int(base64.b64decode(res[24:-1]).decode())
        return token_int
    return False

def login(token):
    token_b64 = base64.b64encode(str(token).encode())
    conn.sendlineafter(b'Option >> ',b'1')
    conn.sendlineafter(b"Enter your username: ",b'System_Administrator')
    conn.sendlineafter(b"Enter your authentication token: ",token_b64)
    res = conn.recvline().decode().strip()
    return res

conn = remote('94.237.59.30','55606')
e,n = recover_n()
user_names = [find_h_factor(h_factor) for h_factor in prime_factors(target_h)]
token_ints = [register(user) for user in user_names]
assert pow(prod(token_ints)%n,e,n) == target_h
result = login(prod(token_ints)%n)
print(result)


```

**🚩 Final Flag:** `HTB{sm4ll_f4c7025_619_p206l3m5}`

