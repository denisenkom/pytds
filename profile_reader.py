import struct
import cProfile
import pstats
import pytds.tds


BUFSIZE = 4096
HEADER = struct.Struct('>BBHHBx')


class Sock:
    def __init__(self):
        self._read_pos = 0
        self._seq = 1
        self._buf = bytearray(b'\x00' * BUFSIZE)
        HEADER.pack_into(self._buf, 0, 0, 0, BUFSIZE, 0, 0)

    def sendall(self, data, flags=0):
        pass

    def recv_into(self, buffer, size=0):
        if size == 0:
            size = len(buffer)
        res = self.recv(size)
        buffer[:len(res)] = res[:]
        return len(res)

    def recv(self, size):
        if self._read_pos >= len(self._buf):
            self._seq += 1
            HEADER.pack_into(self._buf, 0, 0, 0, BUFSIZE, 0, 0)
            self._read_pos = 0
        res = self._buf[self._read_pos:self._read_pos + size]
        self._read_pos += len(res)
        return res

    def close(self):
        pass


class Session:
    def __init__(self):
        self._transport = Sock()


sess = Session()

rdr = pytds.tds._TdsReader(sess)
pr = cProfile.Profile()
pr.enable()
for _ in range(50000):
    rdr.read_whole_packet()
pr.disable()
sortby = 'tottime'
ps = pstats.Stats(pr).sort_stats(sortby)
ps.print_stats()
