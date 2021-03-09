from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import struct
import random
import time
import string
import json
from multiprocessing import cpu_count

# documentation for the AES library
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

# the used mode is OCB since it has built in validation
mode = AES.MODE_CTR

def encryptAES(data, key):
    cipher = AES.new(key, mode)
    if isinstance(data, bytes):
        pass
    else:
        data = bytes(data, 'utf-8')

    ciphertext = cipher.encrypt(data)
    json_k = ['n', 'ct']
    json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext)]
    encrypted = json.dumps(dict(zip(json_k, json_v)))
    return encrypted


def decryptAES(data, key):
    b64 = json.loads(data)
    json_k = ['n', 'ct']
    jv = {k: b64decode(b64[k]) for k in json_k}

    cipher = AES.new(key, mode, nonce=jv['n'])

    try:
        decrypted = cipher.decrypt(jv['ct'])
    except ValueError:
        return False
    except KeyError:
        return False

    return decrypted


def genAESKey(size=256):
    key = b''
    if size != 128 and size != 192 and size != 256:
        raise ValueError("The key size must be 128, 192, or 256!")

    itera = size / 64
    i = 0

    while itera > i:
        key = key + struct.pack("Q", random.getrandbits(64))
        i += 1
    return key
