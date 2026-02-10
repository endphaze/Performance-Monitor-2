# -*- coding: utf-8 -*-

def rot(x, k):
    return (((x << k) & 0xFFFFFFFF) | (x >> (32 - k)))

def mix(a, b, c):
    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF; c &= 0xFFFFFFFF
    a = (a - c) & 0xFFFFFFFF; a ^= rot(c, 4);  c = (c + b) & 0xFFFFFFFF
    b = (b - a) & 0xFFFFFFFF; b ^= rot(a, 6);  a = (a + c) & 0xFFFFFFFF
    c = (c - b) & 0xFFFFFFFF; c ^= rot(b, 8);  b = (b + a) & 0xFFFFFFFF
    a = (a - c) & 0xFFFFFFFF; a ^= rot(c, 16); c = (c + b) & 0xFFFFFFFF
    b = (b - a) & 0xFFFFFFFF; b ^= rot(a, 19); a = (a + c) & 0xFFFFFFFF
    c = (c - b) & 0xFFFFFFFF; c ^= rot(b, 4);  b = (b + a) & 0xFFFFFFFF
    return a, b, c

def final(a, b, c):
    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF; c &= 0xFFFFFFFF
    c ^= b; c = (c - rot(b, 14)) & 0xFFFFFFFF
    a ^= c; a = (a - rot(c, 11)) & 0xFFFFFFFF
    b ^= a; b = (b - rot(a, 25)) & 0xFFFFFFFF
    c ^= b; c = (c - rot(b, 16)) & 0xFFFFFFFF
    a ^= c; a = (a - rot(c, 4))  & 0xFFFFFFFF
    b ^= a; b = (b - rot(a, 14)) & 0xFFFFFFFF
    c ^= b; c = (c - rot(b, 24)) & 0xFFFFFFFF
    return a, b, c

def hashlittle2(data, initval=0, initval2=0):
    if isinstance(data, str):
        data = data.encode('utf-8') # ป้องกัน error ถ้าเผลอส่ง string มา
    
    length = len(data)
    lenpos = length
    a = b = c = (0xdeadbeef + length + initval) & 0xFFFFFFFF
    c = (c + initval2) & 0xFFFFFFFF

    p = 0
    # Process blocks of 12 bytes
    while lenpos > 12:
        a = (a + int.from_bytes(data[p:p+4], 'little')) & 0xFFFFFFFF
        b = (b + int.from_bytes(data[p+4:p+8], 'little')) & 0xFFFFFFFF
        c = (c + int.from_bytes(data[p+8:p+12], 'little')) & 0xFFFFFFFF
        a, b, c = mix(a, b, c)
        p += 12
        lenpos -= 12

    # Process remaining bytes (0-12 bytes)
    if lenpos > 0:
        if lenpos >= 12: c = (c + (data[p+11] << 24)) & 0xFFFFFFFF
        if lenpos >= 11: c = (c + (data[p+10] << 16)) & 0xFFFFFFFF
        if lenpos >= 10: c = (c + (data[p+9] << 8)) & 0xFFFFFFFF
        if lenpos >= 9:  c = (c + data[p+8]) & 0xFFFFFFFF
        
        if lenpos >= 8:  b = (b + (data[p+7] << 24)) & 0xFFFFFFFF
        if lenpos >= 7:  b = (b + (data[p+6] << 16)) & 0xFFFFFFFF
        if lenpos >= 6:  b = (b + (data[p+5] << 8)) & 0xFFFFFFFF
        if lenpos >= 5:  b = (b + data[p+4]) & 0xFFFFFFFF
        
        if lenpos >= 4:  a = (a + (data[p+3] << 24)) & 0xFFFFFFFF
        if lenpos >= 3:  a = (a + (data[p+2] << 16)) & 0xFFFFFFFF
        if lenpos >= 2:  a = (a + (data[p+1] << 8)) & 0xFFFFFFFF
        if lenpos >= 1:  a = (a + data[p+0]) & 0xFFFFFFFF
        
        a, b, c = final(a, b, c)

    return c, b

def hashlittle(data, initval=0):
    c, b = hashlittle2(data, initval, 0)
    return c

if __name__ == "__main__":
    # ใช้ bytes prefix (b'...')
    hashstr = b"hello every one!"

    h1, h2 = hashlittle2(hashstr, 0xdeadbeef, 0xdeadbeef) 
    print(f'Hash 64-bit: {h1:08x} {h2:08x}')

    h = hashlittle(hashstr, 0)
    print(f'Hash 32-bit: {h}')