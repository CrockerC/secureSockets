from Crypto.Cipher import PKCS1_OAEP as RSAc
from Crypto.PublicKey import RSA
import time
import random
import string
from multiprocessing import cpu_count
import threading
import math


class rsaGenerator:
    def __init__(self, keySize=3072):
        self.pad = 48
        self.keySize = keySize
        self.blockLength = (self.keySize // 8) - self.pad
        self.cores = cpu_count()

        self.got_key = threading.Event()
        self.protectMem = threading.Semaphore()

        self.numThreads = self.cores

        self.key = None

    def generate(self):

        # this must be a thread, otherwise the threads will not exit until each one has found a key
        # since the only way to force a thread to close is to set it as a daemon and then exit the parent thread
        threading.Thread(target=self.syncEns).start()

        self.got_key.wait()
        self.protectMem.acquire()
        key = self.key
        self.protectMem.release()
        RSAprivKey = RSA.import_key(key)
        RSApubKey = RSAprivKey.publickey()

        return RSAprivKey, RSApubKey

    def syncEns(self):
        for i in range(self.numThreads):
            threading.Thread(target=self.getKey, daemon=True).start()

        self.got_key.wait()

    def getKey(self):
        key = RSA.generate(self.keySize)

        if self.got_key.is_set():
            return

        self.protectMem.acquire()
        self.got_key.set()
        self.key = key.export_key()
        self.protectMem.release()


class cypherData:
    def __init__(self):
        self.data = {}


class threadRSAcrypto:
    def __init__(self):
        self.hashLen = 48
        self.cores = cpu_count()
        # this function takes a long time, so make sure to only create the object once in the code
        self.numThreads = self.cores

    def encrypt(self, data, key, keySize):
        if not isinstance(data, bytes):
            raise TypeError("You must pass bytes into the encryption function")

        blockLength = (keySize // 8) - self.hashLen
        pad = blockLength - (len(data) % blockLength)
        data += (b'\x00' * pad)

        numBlocks = len(data) // blockLength
        blocksPerThread = math.ceil(numBlocks / self.numThreads)
        bytesPerThread = blockLength * blocksPerThread
        offset = 0
        encDict = cypherData()

        threads = []
        id = 0
        cipher = RSAc.new(key)
        while offset < len(data):
            block = data[offset:offset + bytesPerThread]
            threads.append(threading.Thread(target=self.encThread, args=(block, cipher, keySize, id, encDict)))
            id += 1
            offset += bytesPerThread

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        dictKeys = list(encDict.data.keys())
        dictKeys.sort()

        encrypted = b''
        for key in dictKeys:
            encrypted += encDict.data[key]

        encDict.data.clear()
        del encDict

        return encrypted

    def decrypt(self, data, key, keySize):
        if not isinstance(data, bytes):
            raise TypeError("You must pass bytes into the encryption function")

        blockLength = (keySize // 8) - self.hashLen
        numBlocks = len(data) // (blockLength + self.hashLen)
        blocksPerThread = math.ceil(numBlocks / self.numThreads)
        bytesPerThread = (blockLength + self.hashLen) * blocksPerThread

        offset = 0
        decDict = cypherData()

        threads = []
        id = 0
        cipher = RSAc.new(key)
        while offset < len(data):
            block = data[offset:offset + bytesPerThread]
            threads.append(threading.Thread(target=self.decThread, args=(block, cipher, keySize, id, decDict)))
            id += 1
            offset += bytesPerThread

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        dictKeys = list(decDict.data.keys())
        dictKeys.sort()

        decrypted = b''
        for key in dictKeys:
            decrypted += decDict.data[key]

        decDict.data.clear()
        del decDict

        return decrypted.rstrip(b'\x00')

    def encThread(self, data, cipher, keySize, tID, encDict):
        blockLength = (keySize // 8) - self.hashLen
        encrypted = b''

        offset = 0
        while offset < len(data):
            block = data[offset:offset + blockLength]
            block = cipher.encrypt(block)
            encrypted += block
            offset += blockLength

        encDict.data.update({tID: encrypted})

    def decThread(self, data, cipher, keySize, tID, decDict):
        blockLength = keySize // 8
        encrypted = b''

        offset = 0
        while offset < len(data):
            block = data[offset:offset + blockLength]
            block = cipher.decrypt(block)
            encrypted += block
            offset += blockLength

        decDict.data.update({tID: encrypted})


def encryptRSAsingle(data, key, keySize=3072):
    hashLen = 48
    blockLength = keySize // 8 - hashLen
    encrypted = b''
    if isinstance(data, bytes):
        pass
    else:
        data = bytes(data, 'utf-8')
    pad = blockLength - (len(data) % blockLength)
    data += (b'\x00' * pad)
    offset = 0
    cipher = RSAc.new(key)

    while offset < len(data):
        block = data[offset:offset + blockLength]
        block = cipher.encrypt(block)
        encrypted += block
        offset += blockLength

    return encrypted


def decryptRSAsingle(data, key, keySize=3072):
    # key should be your private key object
    # except if you are doing authentication, then it should be the sender's public key
    hashLen = 48
    blockLength = keySize // 8 - hashLen

    decrypted = b''
    offset = 0
    cipher = RSAc.new(key)

    while offset < len(data):
        block = data[offset:offset + blockLength + hashLen]
        decrypted += cipher.decrypt(block)
        offset += blockLength + hashLen

    return decrypted.rstrip(b'\x00')


if __name__ == "__main__":
    # data = "This is a test string that will be repeated a few times\n" * 3000000
    keySize = 3072
    # keySize must be  1024, 2048 or 3072
    tobj = threadRSAcrypto()
    start = time.time()
    privKey, pubKey = rsaGenerator(keySize).generate()
    print("Generating the key took {:.2f} seconds".format((time.time() - start)))

    start = time.time()
    data = ''.join(random.choice(string.ascii_letters) for j in range(1024)) * 100
    data = bytes(data, 'utf-8')

    print("It took {:.2f} milliseconds to generate the data".format((time.time() - start) * 1000))

    print("The message is {:.2f} KB large".format(len(data) / 1024))

    start = time.time()
    sEncrypted = encryptRSAsingle(data, pubKey, keySize)
    print("Single-threaded encryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    start = time.time()
    encrypted = tobj.encrypt(data, pubKey, keySize)
    print("Multi-threaded encryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    start = time.time()
    sDecrypted = decryptRSAsingle(encrypted, privKey, keySize)
    print("Single-threaded decryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    start = time.time()
    decrypted = tobj.decrypt(encrypted, privKey, keySize)
    print("Multi-threaded decryption took {:.2f} milliseconds".format((time.time() - start) * 1000))

    print("It is", data == decrypted, "that the output is the same as the input")
