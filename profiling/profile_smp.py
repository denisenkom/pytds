import struct
import cProfile
import pstats
import io

import pytds.smp

transport = None

bufsize = 512
smp_header = struct.Struct("<BBHLLL")


class Sock:
    def __init__(self):
        self._read_pos = 0
        self._seq = 1
        self._buf = bytearray(b"\x00" * bufsize)
        smp_header.pack_into(self._buf, 0, 0x53, 0x8, 0, bufsize, self._seq, 4)

    def sendall(self, data, flags=0):
        pass

    def recv_into(self, buffer, size=0):
        if size == 0:
            size = len(buffer)
        res = self.recv(size)
        buffer[: len(res)] = res[:]
        return len(res)

    def recv(self, size):
        if self._read_pos >= len(self._buf):
            self._seq += 1
            smp_header.pack_into(self._buf, 0, 0x53, 0x8, 0, bufsize, self._seq, 4)
            self._read_pos = 0
        res = self._buf[self._read_pos : self._read_pos + size]
        self._read_pos += len(res)
        return res

    def close(self):
        pass


sock = Sock()
mgr = pytds.smp.SmpManager(transport=sock)
sess = mgr.create_session()
pr = cProfile.Profile()
pr.enable()
buf = bytearray(b"\x00" * bufsize)
for _ in range(50000):
    sess.recv_into(buf)
pr.disable()
sortby = "tottime"
ps = pstats.Stats(pr).sort_stats(sortby)
ps.print_stats()
