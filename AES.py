from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from compression import *
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


if __name__ == "__main__":
    # data = "This is a test string that will be repeated a few times\n" * 3000000

    start = time.time()
    data = ''.join(random.choice(string.ascii_letters) for j in range(1024 * 1024)) * 10
    data = bytes(data, 'utf-8')

    print("It took {:.2f} seconds to generate the data".format((time.time() - start)))

    print("The message is {:.2f} MB large".format(len(data) / 1024 / 1024))

    key = genAESKey()

    start = time.time()
    compressed = compress(data)
    print("Compression took {:.2f} seconds".format((time.time() - start)))
    print("The compressed message is {:.2f} MB large".format(len(compressed) / 1024 / 1024))

    start = time.time()
    encrypted = encryptAllAES([compressed], key)[0]
    print("Encryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    print("The encrypted message is {:.2f} MB large".format(len(encrypted) / 1024 / 1024))

    start = time.time()
    decrypted = decryptAllAES([encrypted], key)[0]
    print("Decryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    start = time.time()
    decompressed = decompress(decrypted)  # decrypted and compressed should be the same
    print("Decompression took {:.2f} seconds".format((time.time() - start)))

    print("It is", data == decompressed, "that the output is the same as the input")
