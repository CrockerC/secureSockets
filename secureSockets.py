import socket
from RSAenc import *
from AES import *
from typing import Any, Tuple, Union

_Address = Union[tuple, str]
_RetAddress = Any

# todo, make this save the key to a file to save time so that a new key doesnt have to be generated each time
PRIVRSA, PUBRSA = rsaGenerator(3072).generate()


# todo, add udp support
# todo, add more socket functions

class secureSocket(socket.socket):
    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        socket.socket.__init__(self, family=family, type=type, proto=proto, fileno=fileno)
        self.pubRSAKey = None
        self.secKey = None
        self.sock = None

    def connect_sec(self, address: Union[_Address, bytes]) -> None:
        self.connect(address)
        self._sendRSA()
        self.pubRSAKey = self._getRSA()
        self.secKey = self._genSendSecKey()

    def connect_ex_sec(self, address: Union[_Address, bytes]) -> int:
        suc = self.connect_ex(address)
        if suc:
            return suc
        self._sendRSA()
        self.pubRSAKey = self._getRSA()
        self.secKey = self._genSendSecKey()
        return suc

    def accept_sec(self) -> Tuple[socket.socket, _RetAddress]:
        sock, addr = self.accept()
        sSock = secureSocket(sock.family, sock.type, sock.proto, fileno=sock.fileno())
        sSock.pubRSAKey = sSock._getRSA()
        sSock._sendRSA()
        sSock.secKey = sSock._getSecKey()
        sSock.sock = sock
        return sSock, addr

    def sendall_sec(self, data: bytes, flags: int = 0) -> None:
        encrypted = bytes(encryptAES(data, self.secKey), 'utf-8')
        self.sendall(self._addLen(encrypted), flags)

    def recv_sec(self, timeout: int = None, st: bool = False, flags: int = 0) -> bytes:
        data = self._recv_data(timeout, st, flags)
        return decryptAES(data, self.secKey)

    def _recv_data(self, timeout=None, st=False, flags: int = 0):
        if timeout is not None:
            self.settimeout(timeout)
        lenData = self._recvall(4, flags)
        if not lenData:
            return False
        lenData = struct.unpack('>I', lenData)[0]
        data = bytes(self._recvall(lenData, flags))
        if timeout is not None:
            self.settimeout(None)
        if st:
            return data, lenData + 4  # lenData+4 in bytes
        else:
            return data

    def _recvall(self, n, flags):
        data = bytearray()
        while len(data) < n:
            packet = self.recv(n - len(data), flags)
            if not packet:
                return False
            data.extend(packet)
        return data

    @staticmethod
    def _addLen(data):
        return struct.pack('>I', len(data)) + data

    def _sendRSA(self):
        if self.fileno() != -1:
            self.sendall(self._addLen(b'\x00' + PUBRSA.export_key()))
            return True
        return False

    def _getRSA(self):
        data = self._recv_data(3)
        if not data:
            return False
        if data[0:1] == b'\x00':
            RSAkey = RSA.import_key(data[1:])
            return RSAkey
        else:
            return False

    def _genSendSecKey(self):
        key = genAESKey()
        data = encryptRSAsingle(key, self.pubRSAKey)
        self.sendall(self._addLen(b'\x01' + data))
        return key

    def _getSecKey(self):
        secKey = self._recv_data(3)
        if secKey is False:
            return False
        if secKey[0:1] == b'\x01':
            return decryptRSAsingle(secKey[1:], PRIVRSA)


def _test1(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', 10000))
    sock.listen(1)
    sock1, addr = sock.accept_sec()

    data = str(sock1.recv_sec(), 'utf-8')
    print(data, sock1)

    sock1.sendall_sec(bytes("Success 2!", 'utf-8'))


def _test2(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect_sec(('localhost', 10000))

    sock.sendall_sec(bytes("Success 1!", 'utf-8'))

    data = str(sock.recv_sec(), 'utf-8')
    print(data, sock)


if __name__ == "__main__":
    import threading

    s1 = secureSocket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = secureSocket(socket.AF_INET, socket.SOCK_STREAM)

    threading.Thread(target=_test1, args=(s1,)).start()
    threading.Thread(target=_test2, args=(s2,)).start()
