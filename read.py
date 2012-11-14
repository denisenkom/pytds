import struct
from StringIO import StringIO
from net import *

def tds_get_byte(tds):
    while tds.in_pos >= tds.in_len:
        tds_read_packet(tds)
    result = tds.in_buf[tds.in_pos]
    tds.in_pos += 1
    return result

#
# Unget will always work as long as you don't call it twice in a row.  It
# it may work if you call it multiple times as long as you don't backup
# over the beginning of network packet boundary which can occur anywhere in
# the token stream.
#
def tds_unget_byte(tds):
    # this is a one trick pony...don't call it twice
    tds.in_pos -= 1

def tds_get_smallint(tds):
    buf = tds_get_n(tds, 2)
    if tds_conn(tds).emul_little_endian:
        return struct.unpack('<h', bytes(buf))[0]
    else:
        return struct.unpack('>h', bytes(buf))[0]

def tds_get_int(tds):
    buf = tds_get_n(tds, 4)
    if tds_conn(tds).emul_little_endian:
        return struct.unpack('<l', bytes(buf))[0]
    else:
        return struct.unpack('>l', bytes(buf))[0]

def tds_get_string(tds, size):
    buf = tds_get_n(tds, size*2)
    return buf.decode('utf16')

def tds_get_n(tds, need):
    result = StringIO()
    pos = 0
    while True:
        have = tds.in_len - tds.in_pos
        if need <= have:
            break
        result.write(tds.in_buf[tds.in_pos:tds.in_pos+have])
        pos += have
        need -= have
        tds_read_packet(tds)
    if need > 0:
        result.write(tds.in_buf[tds.in_pos:tds.in_pos+need])
        tds.in_pos += need
    return result.getvalue()
