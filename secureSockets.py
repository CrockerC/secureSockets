import socket
from RSAenc import *
from AES import *
import sys
from typing import Any, Iterable, Tuple, List, Optional, Union, overload, TypeVar, Text

_Address = Union[tuple, str]
_RetAddress = Any

keySize = 3072


# todo, make this save the key to a file to save time so that a new key doesnt have to be generated each time
PRIVRSA, PUBRSA = rsaGenerator(keySize).generate()


# todo, add udp support
# todo, add more socket functions


class secureSocket(socket.socket):
    def __init__(self, *args):
        super(secureSocket, self).__init__()
        self.pubRSAKey = None
        self.secKey = None

    def connect_sec(self, address: Union[_Address, bytes]) -> None:
        self.connect(address)
        self.__sendRSA()
        self.pubRSAKey = self.__getRSA()
        self.secKey, _ = self.__genSendSecKey()

    def connect_ex_sec(self, address: Union[_Address, bytes]) -> int:
        suc = self.connect_ex(address)
        if suc:
            return suc
        self.__sendRSA()
        self.pubRSAKey = self.__getRSA()
        self.secKey, _ = self.__genSendSecKey()

        return suc

    def accept_sec(self) -> Tuple[socket, _RetAddress]:
        ret = self.accept()
        self.pubRSAKey = self.__getRSA()
        self.__sendRSA()
        self.secKey = self.__getSecKey()

        return ret

    def sendall_sec(self, data: bytes, flags: int = ...) -> None:
        encrypted = encryptAES(data, self.secKey)
        self.sendall(self.__addLen(encrypted), flags)

    def recv_sec(self, timeout: int = None, st: bool = False, flags: int = ...,) -> bytes:
        data = self.__recv_data(flags, timeout, st)
        return decryptAES(data, self.secKey)

    def __recv_data(self, flags, timeout=None, st=False):
        if timeout is not None:
            self.settimeout(timeout)
        lenData = self.__recvall(4, flags)
        if not lenData:
            return False
        lenData = struct.unpack('>I', lenData)[0]
        data = bytes(self.__recvall(lenData, flags))
        if timeout is not None:
            self.settimeout(None)
        if st:
            return data, lenData + 4  # lenData+4 in bytes
        else:
            return data

    def __recvall(self, n, flags):
        data = bytearray()
        while len(data) < n:
            packet = self.recv(n - len(data), flags)
            if not packet:
                return False
            data.extend(packet)
        return data

    def __addLen(self, data):
        return struct.pack('>I', len(data)) + data

    def __sendRSA(self):
        if self.fileno() != -1:
            self.sendall(self.__addLen(b'\x00' + PUBRSA.export_key()))
            return True
        return False

    def __getRSA(self):
        hello = self.__recv_data(3)
        if not hello:
            return False
        if hello[0:1] == b'\x00':
            hello = hello[1:]
            RSAkey = RSA.import_key(hello)
            return RSAkey
        else:
            return False

    def __genSendSecKey(self):
        key = genAESKey()
        data = encryptRSAsingle(key, self.pubRSAKey)
        self.sendall(self.__addLen(b'\x01' + data))

        return key, data

    def __getSecKey(self):
        secKey = self.__recv_data(3)
        if secKey is False:
            return False
        if secKey[0:1] == b'\x01':
            return decryptRSAsingle(secKey[1:], PRIVRSA)
