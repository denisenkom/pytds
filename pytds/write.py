import struct
from tds import tds_conn

def tds_put_smallint(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<h', value))
    else:
        tds_put_s(tds, struct.pack('>h', value))

def tds_put_smallint_be(tds, value):
    tds_put_s(tds, struct.pack('>h', value))

def tds_put_s(tds, value):
    tds._writer.write(value)

def tds_put_string(tds, value):
    value = value.encode('utf16')[2:]
    tds_put_s(tds, value)

def tds_put_byte(tds, value):
    tds._writer.put_byte(value)

TDS_PUT_BYTE = tds_put_byte

def tds_put_int(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<l', value))
    else:
        tds_put_s(tds, struct.pack('>l', value))

def tds_put_uint(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<L', value))
    else:
        tds_put_s(tds, struct.pack('>L', value))

def tds_put_int_be(tds, value):
    tds_put_s(tds, struct.pack('>l', value))

TDS_PUT_INT = tds_put_int

def tds_put_int8(tds, value):
    if tds_conn(tds).emul_little_endian:
        tds_put_s(tds, struct.pack('<q', value))
    else:
        tds_put_s(tds, struct.pack('>q', value))

TDS_PUT_SMALLINT = tds_put_smallint
