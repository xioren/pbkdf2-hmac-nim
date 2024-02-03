Pure Nim implementation of PBKDF2-HMAC (Password-Based Key Derivation Function 2 HMAC). Currently supports SHA256 and SHA512.

```nim
let password = "password"
let salt = "salt"
  
let derivedKeySha256 = pbkdf2Hmac(password, salt, 1000, digestMod=SHA256)
let derivedKeySha512 = pbkdf2Hmac(password, salt, 1000, digestMod=SHA512)

assert derivedKeySha256.hex() == "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"
assert derivedKeySha512.hex() == "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec"
```
