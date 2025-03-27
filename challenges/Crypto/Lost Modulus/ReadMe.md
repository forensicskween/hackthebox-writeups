# 🔐 Crypto Challenge

## 🏷️ Name: [Lost Modulus](https://app.hackthebox.com/challenges/232)

## 🔥 Difficulty: Easy

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> I encrypted a secret message with RSA but I lost the modulus. Can you help me recover it?

## 📂 Provided Files:
- **Filename:** `Lost Modulus.zip`

- **SHA-256 Hash:** `454bdbb4ddd9a9d8961ec045f02d496094acaf841d0b15d720be15755981938b`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

This is a 'normal' RSA CryptoSystem, but with a small exponent.
The encryption is textbook RSA:

$$c = m^e \mod N$$

### ⚡ 2️⃣ Identifying Vulnerabilities

Given that N is a product of large primes (512-bits), and c is small; the vulnerability is that if:

$$
 m^e < N
$$

the modulo operation is **never** applied; so $m$ is simply the 3rd root of $c$. 

### 🔑 3️⃣ Recovering the Flag

To check if this will work:

assert flag.bit_length() < 1020

# 🏁 Solution & Commands

```sage

c = 0x05c61636499a82088bf4388203a93e67bf046f8c49f62857681ec9aaaa40b4772933e0abc83e938c84ff8e67e5ad85bd6eca167585b0cc03eb1333b1b1462d9d7c25f44e53bcb568f0f05219c0147f7dc3cbad45dec2f34f03bcadcbba866dd0c566035c8122d68255ada7d18954ad604965

m = ZZ(c).nth_root(3)
flag = int(m).to_bytes((m.bit_length()//8)+1,'big').decode()
print(flag)


```

**🚩 Final Flag:** `HTB{n3v3r_us3_sm4ll_3xp0n3n7s_f0r_rs4}`

