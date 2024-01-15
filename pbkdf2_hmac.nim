import std/[sequtils, strutils]

import hmac


proc xorBytes(a, b: var openArray[uint8]) {.inline.} =
  for i in 0..<a.len:
    a[i] = a[i] xor b[i]


proc hex*(key: openArray[uint8]): string =
  result = newStringOfCap(key.len + key.len)
  for b in key:
    result.add(b.toHex(2).toLowerAscii())
  return result


proc pbkdf2Hmac*(password, salt: openarray[uint8],
                 iterations: int, dkLen: int = 0,
                 digestMod: DigestMod): seq[uint8] =
  
  let hLen = if digestMod == SHA256: 32 else: 64
  let derivedKeyLen = if dkLen > 0: dkLen else: hLen

  var key = newSeq[uint8](derivedKeyLen)
  var blockCount = (derivedKeyLen + hLen.pred) div hLen
  var saltSeq = salt.toSeq() & @[uint8(0), uint8(0), uint8(0), uint8(0)]
  var T = newSeq[uint8](hLen)
  var U = newSeq[uint8](hLen)
  var startIdx: int
  var endIdx: int
  var hmacCtx: HmacContext
  
  for i in 1 .. blockCount:
    # NOTE: append i the the end of salt in big endian format
    saltSeq[^4] = uint8(i shr 24 and 0xFF)
    saltSeq[^3] = uint8(i shr 16 and 0xFF)
    saltSeq[^2] = uint8(i shr 8 and 0xFF)
    saltSeq[^1] = uint8(i and 0xFF)
  
    hmacCtx = newHmacCtx(password, saltSeq, digestMod)
    U = hmacCtx.digest()

    # NOTE: first iteration result
    T = U

    # NOTE: perform additional iterations
    for _ in 1 ..< iterations:
      hmacCtx = newHmacCtx(password, U, digestMod)
      U = hmacCtx.digest()
      xorBytes(T, U)

    # NOTE: copy the block to the key
    startIdx = i.pred * hLen
    endIdx = min(startIdx + hLen, derivedKeyLen)
    for k in startIdx ..< endIdx:
      key[k] = T[k - startIdx]

  return key


proc pbkdf2Hmac*(password, salt: string,
                 iterations: int, dkLen: int = 0,
                 digestMod: DigestMod): seq[uint8] =
  
  return pbkdf2Hmac(password.toOpenArrayByte(0, password.len.pred),
                    salt.toOpenArrayByte(0, salt.len.pred),
                    iterations, dkLen, digestMod)


when isMainModule:
  let password = "password"
  let salt = "salt"
    
  let derivedKeySha256 = pbkdf2Hmac(password, salt, 1000, digestMod=SHA256)
  let derivedKeySha512 = pbkdf2Hmac(password, salt, 1000, digestMod=SHA512)

  assert derivedKeySha256.hex() == "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"
  assert derivedKeySha512.hex() == "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec"