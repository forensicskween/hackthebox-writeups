# 🔐 Crypto Challenge

## 🏷️ Name: [Secure Signing](https://app.hackthebox.com/challenges/509)

## 🔥 Difficulty: Easy

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Can you crack our Ultra Secure Signing Oracle?

## 📂 Provided Files:
- **Filename:** `Secure_Signing.zip`

- **SHA-256 Hash:** `d7d9d69b6c6528e72e120debdccf7d9c78322f3207c5f1fa27ccb810d6ef9dac`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

This is a **Signing algorithm** where we have two options:  
The **flag** will be referred to as `secret`.  

The hashing algorithm always follows this process:  

1. Compute the **XOR** of the chosen message and the `secret`:

   $$\text{xored message} = \text{xor}(\text{message}, \text{secret})$$
   
2. Compute the **SHA-256 hash** of the `xored_message`:

   $$H = \text{sha256}(\text{xored message}).\text{hexdigest()}$$

3. The verification step checks if:

   $$H(\text{chosen message} \oplus \text{secret}) = \text{provided hash}$$

---

### ⚡ 2️⃣ Identifying Vulnerabilities

The main vulnerability lies in the **XOR function**:  

```python
def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])
```

The issue is **`zip(a, b)` truncates to the length of the shorter iterable**.  
This means **if the message is shorter than the secret**, the XOR operation only affects a **partial** section of the secret.  

For example:  

```python
A = [1 for _ in range(2)]
B = [23 for _ in range(256)]
zip(A, B) == [(1, 23), (1, 23)]
```

This allows us to **bruteforce the secret** byte-by-byte.  
To mitigate this, the server should be **signing the other way around**—ensuring that users cannot control how much of the flag is leaked.

---


### 🔨 3️⃣ Exploiting the Weakness

This is a **bruteforce attack** since we know the **flag format** uses ASCII printable characters.  

### **Attack Strategy**
1. Start with a known flag prefix:  
   ```python
   secret = b'HTB{'
   ```
2. Since the hash function only computes over the **first few bytes** of the secret (due to truncation), we can recover it one byte at a time.
3. Use a **dictionary attack**:
   - Compute the SHA-256 hash for all possible next bytes.
   - Query the server for a hash.
   - Match the result to find the correct byte.

### **Bruteforce Implementation**
```python
from hashlib import sha256

def xor_h(message):
    hsh = H(xor(message, FLAG))
    return hsh.hex()

secret = b'HTB{'
while not secret.endswith(b'}'):
    hash_dict = {sha256(bytes(len(secret)) + bytes([s])).hexdigest(): bytes([s]) for s in range(256)}
    xor_ba = xor_h(secret + b'\x00')
    secret += hash_dict[xor_ba]
    print(secret.decode())
```

This will **reconstruct the flag** one byte at a time.

---

### 🔑 4️⃣ Recovering the Flag

To recover the flag, we need to implement the above with the server ... 

My previous solution (Sol.py) is interestingly NOT good lol. Use SolUpdate.py !


# 🏁 Solution & Commands

```python

from pwn import remote
from hashlib import sha256

def receive_hash(message):
    conn.sendlineafter(b'> ',b'1')
    conn.sendlineafter(b"Enter your message: ",message)
    return conn.recvline().decode().strip().split(': ')[1]

def verify_hash(message,hsh):
    conn.sendlineafter(b'> ',b'2')
    conn.sendlineafter(b"Enter your message: ",message)
    conn.sendlineafter(b"Enter your message: ",hsh.encode())
    result =  conn.recvline().decode().strip()
    return result

host,port = '94.237.53.146:53247'.split(':')
conn = remote(host,port)

secret = b'HTB{'
while not secret.endswith(b'}'):
    hash_dict = {sha256(bytes(len(secret)) + bytes([s])).hexdigest():bytes([s]) for s in range(256)}
    xor_ba = receive_hash(secret.decode() + '\x00')
    secret += hash_dict[xor_ba]
    print(secret.decode())


```

**🚩 Final Flag:** `HTB{r0ll1n6_0v3r_x0r_w17h_h@5h1n6_0r@cl3_15_n07_s3cur3!@#}`

