import socket
from RSAenc import *
from AES import *
from typing import Any, Tuple, Union

_Address = Union[tuple, str]
_RetAddress = Any

keySize = 3072

lock = threading.Lock()

# todo, make this save the key to a file to save time so that a new key doesnt have to be generated each time
PRIVRSA, PUBRSA = rsaGenerator(keySize).generate()


# todo, add udp support
# todo, add more socket functions
# todo, figure out how to make accepted socks secureSockets instead of having them be secureSockets containing normal sockets
# todo, maybe not make the secureSocket inherit the socket class, just contain one?

class secureSocket(socket.socket):
    def __init__(self, *args):
        super(secureSocket, self).__init__()
        self.pubRSAKey = None
        self.secKey = None
        self.sock = self

    def connect_sec(self, address: Union[_Address, bytes]) -> None:
        self.connect(address)
        self.__sendRSA()
        self.pubRSAKey = self.__getRSA()
        self.secKey = self.__genSendSecKey()

    def connect_ex_sec(self, address: Union[_Address, bytes]) -> int:
        suc = self.connect_ex(address)
        if suc:
            return suc
        self.__sendRSA()
        self.pubRSAKey = self.__getRSA()
        self.secKey = self.__genSendSecKey()
        return suc

    def accept_sec(self) -> Tuple[socket.socket, _RetAddress]:
        sock, addr = self.accept()
        nSock = secureSocket(sock)
        nSock.sock = sock

        nSock.pubRSAKey = nSock.__getRSA()
        nSock.__sendRSA()
        nSock.secKey = nSock.__getSecKey()
        return nSock, addr

    def sendall_sec(self, data: bytes, flags: int = 0) -> None:
        encrypted = bytes(encryptAES(data, self.secKey), 'utf-8')
        self.sock.sendall(self.__addLen(encrypted), flags)

    def recv_sec(self, timeout: int = None, st: bool = False, flags: int = 0) -> bytes:
        data = self.__recv_data(timeout, st, flags)
        return decryptAES(data, self.secKey)

    def __recv_data(self, timeout=None, st=False, flags: int = 0):
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
            packet = self.sock.recv(n - len(data), flags)
            if not packet:
                return False
            data.extend(packet)
        return data

    @staticmethod
    def __addLen(data):
        return struct.pack('>I', len(data)) + data

    def __sendRSA(self):
        if self.fileno() != -1:
            self.sock.sendall(self.__addLen(b'\x00' + PUBRSA.export_key()))
            return True
        return False

    def __getRSA(self):

        data = self.__recv_data(3)

        if not data:
            return False
        if data[0:1] == b'\x00':
            RSAkey = RSA.import_key(data[1:])
            return RSAkey
        else:
            return False

    def __genSendSecKey(self):
        key = genAESKey()
        data = encryptRSAsingle(key, self.pubRSAKey)
        self.sock.sendall(self.__addLen(b'\x01' + data))
        return key

    def __getSecKey(self):
        secKey = self.__recv_data(3)
        if secKey is False:
            return False
        if secKey[0:1] == b'\x01':
            return decryptRSAsingle(secKey[1:], PRIVRSA)


def __test1(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', 10000))
    sock.listen(1)
    sock1, addr = sock.accept_sec()

    data = str(sock1.recv_sec(), 'utf-8')
    print(data)

    sock1.sendall_sec(bytes("Success 2!", 'utf-8'))


def __test2(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect_sec(('localhost', 10000))

    sock.sendall_sec(bytes("Success 1!", 'utf-8'))

    data = str(sock.recv_sec(), 'utf-8')
    print(data)


if __name__ == "__main__":
    import threading

    s1 = secureSocket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = secureSocket(socket.AF_INET, socket.SOCK_STREAM)

    threading.Thread(target=__test1, args=(s1,)).start()
    threading.Thread(target=__test2, args=(s2,)).start()
