# 🔐 Crypto Challenge

## 🏷️ Name: [Ancient Encodings](https://app.hackthebox.com/challenges/475)

## 🔥 Difficulty: Very Easy

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Your initialization sequence requires loading various programs to gain the necessary knowledge and skills for your journey. Your first task is to learn the ancient encodings used by the aliens in their communication.

## 📂 Provided Files:
- **Filename:** `Ancient Encodings.zip`

- **SHA-256 Hash:** `4f0515498a00151846cca3f3d214a31a370f6649447e3896785b0a0a4eb7242d`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem
This isn't exactly a cryptosystem ... the message is encoded as follows:

1. Base64
2. Big-endian Integer Encoding
3. Base-16 Encoding

### ⚡ 2️⃣ Identifying Vulnerabilities

Well, IMO, there technically isn't a vulnerability, since it's not a cryptosystem.
The encoding is entirely reversable.

### 🔑 3️⃣ Recovering the Flag

To recover the flag, we need to reverse the steps used to encode the flag.

1. Convert from Base-16 to Big-endian 
2. Convert from Big-endian to Bytes
3. Base64 decode

And we can actually skip Step 1/2  by converting Base-16 to bytes.


# 🏁 Solution & Commands

```python
import base64

message = '0x53465243657a467558336b7764584a66616a4231636d347a655639354d48566664326b786246397a5a544e66644767784e56396c626d4d775a4446755a334e665a58597a636e6c33614756794d33303d'

flag = base64.b64decode(bytes.fromhex(message[2:])).decode()

print(flag)
```

**🚩 Final Flag:** `HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}`

