import time
import base64
import hmac
import struct
import hashlib

def get_totp(secret):
    t = int(time.time()) / 30
    
    secret = base64.b32decode(secret)
    counter = struct.pack(">!Q", t)
    
    hash = hmac.new(secret, counter, hashlib.sha256).digest()
    offset = ord(hash[19]) & 0xF
    part = hash[offset:offset + 4]
    
    totp = (struct.unpack(">I", part)[0] & 0x7FFFFFFF) % 1000000
    
    return str(totp).zfill(6)


