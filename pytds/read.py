import struct
from StringIO import StringIO
from net import *
from iconv import *

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

def tds_peek(tds):
    result = tds_get_byte(tds)
    if tds.in_pos > 0:
        tds.in_pos -= 1
    return result

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

def tds_get_int_be(tds):
    buf = tds_get_n(tds, 4)
    return struct.unpack('>l', bytes(buf))[0]

def tds_get_uint_be(tds):
    buf = tds_get_n(tds, 4)
    return struct.unpack('>L', bytes(buf))[0]

def tds_get_int8(tds):
    buf = tds_get_n(tds, 8)
    if tds_conn(tds).emul_little_endian:
        return struct.unpack('<q', bytes(buf))[0]
    else:
        return struct.unpack('>q', bytes(buf))[0]

def tds_get_string(tds, size):
    buf = tds_get_n(tds, size*2)
    return buf.decode('utf16')

def tds_skip_n(tds, need):
    pos = 0
    while True:
        have = tds.in_len - tds.in_pos
        if need <= have:
            break
        pos += have
        need -= have
        tds_read_packet(tds)
    if need > 0:
        tds.in_pos += need

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

#
# Fetch character data the wire.
# Output is NOT null terminated.
# If \a char_conv is not NULL, convert data accordingly.
# \param tds         state information for the socket and the TDS protocol
# \param wire_size   size to read from wire (in bytes)
# \param curcol      column information
# \return TDS_SUCCESS or TDS_FAIL (probably memory error on text data)
# \todo put a TDSICONV structure in every TDSCOLUMN
#
def tds_get_char_data(tds, wire_size, curcol):
    #
    # dest is usually a column buffer, allocated when the column's metadata are processed 
    # and reused for each row.  
    # For blobs, dest is blob->textvalue, and can be reallocated or freed
    # TODO: reallocate if blob and no space 
    #
    # silly case, empty string
    if wire_size == 0:
        return ''

    if curcol.char_conv:
        #
        # TODO The conversion should be selected from curcol and tds version
        # TDS7.1/single -> use curcol collation
        # TDS7/single -> use server single byte
        # TDS7+/unicode -> use server (always unicode)
        # TDS5/4.2 -> use server 
        # TDS5/UTF-8 -> use server
        # TDS5/UTF-16 -> use UTF-16
        #
        result = read_and_convert(tds, curcol.char_conv, wire_size)
        return result
    else:
        return tds_get_n(tds, wire_size)

#
# For UTF-8 and similar, tds_iconv() may encounter a partial sequence when the chunk boundary
# is not aligned with the character boundary.  In that event, it will return an error, and
# some number of bytes (less than a character) will remain in the tail end of temp[].  They are  
# moved to the beginning, ptemp is adjusted to point just behind them, and the next chunk is read.
#
def read_and_convert(tds, char_conv, wire_size):
    #
    # temp (above) is the "preconversion" buffer, the place where the UCS-2 data 
    # are parked before converting them to ASCII.  It has to have a size, 
    # and there's no advantage to allocating dynamically.
    # This also avoids any memory allocation error.
    #

    # read a chunk of data
    buf = tds_get_n(tds, wire_size)

    # Convert chunk and write to dest.
    return tds_iconv(tds, char_conv, to_client, buf)
