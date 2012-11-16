import struct
from net import tds_write_packet
from tds import tds_conn

def tds_put_smallint(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<h', value))
    else:
        tds_put_s(tds, struct.pack('>h', value))

def tds_put_s(tds, value):
    tds.out_buf[tds.out_pos:tds.out_pos+len(value)] = value
    tds.out_pos += len(value)

def tds_put_string(tds, value):
    value = value.encode('utf16')[2:]
    tds_put_s(tds, value)

def tds_put_byte(tds, value):
    tds.out_buf[tds.out_pos] = value
    tds.out_pos += 1

TDS_PUT_BYTE = tds_put_byte

def tds_put_int(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<l', value))
    else:
        tds_put_s(tds, struct.pack('>l', value))

TDS_PUT_INT = tds_put_int

def tds_put_int8(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<q', value))
    else:
        tds_put_s(tds, struct.pack('>q', value))

TDS_PUT_SMALLINT = tds_put_smallint

def tds_flush_packet(tds):
    if tds.is_dead():
        raise Exception('is dead')
    return tds_write_packet(tds, 0x01)

def tds_init_write_buf(tds):
    tds.out_pos = 8
