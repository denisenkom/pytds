import logging
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from dateutil.tz import tzoffset, tzutc
import uuid
import six
from six.moves import map, reduce
from .tds import *
from .tds import _Column
from .tdsproto import *

logger = logging.getLogger(__name__)


def _applytz(dt, tz):
    if not tz:
        return dt
    dt = dt.replace(tzinfo=tz)
    return dt


def make_param(tds, name, value):
    column = _Column()
    column.column_name = name
    column.flags = 0
    if isinstance(value, output):
        column.flags |= fByRefValue
        value = value.value
    if value is default:
        column.flags = fDefaultValue
        value = None
    if value is None:
        handler = DefaultHandler
    elif isinstance(value, six.integer_types):
        if -2 ** 63 <= value <= 2 ** 63 - 1:
            handler = DefaultHandler
        elif -10 ** 38 + 1 <= value <= 10 ** 38 - 1:
            value = Decimal(value)
            handler = NumericHandler
        else:
            raise DataError('Numeric value out or range')
    elif isinstance(value, float):
        handler = DefaultHandler
    elif isinstance(value, Binary):
        handler = DefaultHandler
    elif isinstance(value, six.string_types):
        handler = DefaultHandler
    elif isinstance(value, six.binary_type):
        handler = DefaultHandler
    elif isinstance(value, datetime):
        if IS_TDS73_PLUS(tds):
            handler = MsDatetimeHandler
        else:
            handler = DatetimeHandler
    elif isinstance(value, date):
        if IS_TDS73_PLUS(tds):
            handler = MsDatetimeHandler
        else:
            handler = DatetimeHandler
    elif isinstance(value, time):
        if not IS_TDS73_PLUS(tds):
            raise DataError('Time type is not supported on MSSQL 2005 and lower')
        handler = MsDatetimeHandler
    elif isinstance(value, Decimal):
        handler = NumericHandler
    elif isinstance(value, uuid.UUID):
        handler = DefaultHandler
    else:
        raise DataError('Parameter type is not supported: {0}'.format(repr(value)))
    column.funcs = handler
    column.value = column.funcs.from_python(tds, column, value)
    return column


class DefaultHandler(object):
    @staticmethod
    def _tds72_get_varmax(tds, curcol, codec):
        r = tds._reader
        size = r.get_int8()

        # NULL
        if size == -1:
            return None

        decoder = None
        if codec:
            decoder = codec.incrementaldecoder()
            chunk_handler = MemoryStrChunkedHandler()
        else:
            chunk_handler = tds.chunk_handler
        chunk_handler.begin(curcol, size)
        while True:
            chunk_len = r.get_int()
            if chunk_len <= 0:
                if decoder:
                    val = decoder.decode(b'', True)
                    chunk_handler.new_chunk(val)
                return chunk_handler.end()
            left = chunk_len
            while left:
                val = r.read(left)
                left -= len(val)
                if decoder:
                    val = decoder.decode(val)
                chunk_handler.new_chunk(val)

    @staticmethod
    def from_python(tds, col, value):
        if value is None:
            col.column_type = XSYBVARCHAR
            col.column_size = 1
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, six.integer_types):
            col.column_type = SYBINTN
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                col.column_size = 4
            elif -2 ** 63 <= value <= 2 ** 63 - 1:
                col.column_size = 8
            else:
                raise DataError('Numeric value out or range')
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, float):
            col.column_type = SYBFLTN
            col.column_size = 8
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, Binary):
            if len(value) > 8000:
                if IS_TDS72_PLUS(tds):
                    col.column_type = XSYBVARBINARY
                    col.column_varint_size = 8  # nvarchar(max)
                else:
                    col.column_type = SYBIMAGE
                    col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            else:
                col.column_type = XSYBVARBINARY
                col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            col.column_size = len(value)
        elif isinstance(value, six.string_types + (six.binary_type,)):
            if len(value) > 4000:
                if IS_TDS72_PLUS(tds):
                    col.column_type = XSYBNVARCHAR
                    col.column_varint_size = 8  # nvarchar(max)
                else:
                    col.column_type = SYBNTEXT
                    col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            else:
                col.column_type = XSYBNVARCHAR
                col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            col.column_size = len(value) * 2
            col.char_codec = ucs2_codec
        elif isinstance(value, uuid.UUID):
            col.column_type = SYBUNIQUE
            col.column_size = 16
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        return value

    @staticmethod
    def get_declaration(tds, col):
        max_len = 8000 if IS_TDS7_PLUS(tds) else 255
        t = col.column_type
        if t in (XSYBCHAR, SYBCHAR):
            return "CHAR(%d)" % col.size
        elif t in (SYBVARCHAR, XSYBVARCHAR):
            if col.column_varint_size == 8:
                return "VARCHAR(MAX)"
            else:
                return "VARCHAR(%d)" % col.column_size
        elif t == SYBINT1:
            return "TINYINT"
        elif t == SYBINT2:
            return "SMALLINT"
        elif t == SYBINT4 or t == SYBINTN and col.column_size == 4:
            return "INT"
        elif t == SYBINT8 or t == SYBINTN and col.column_size == 8:
            # TODO even for Sybase ??
            return "BIGINT"
        elif t == SYBFLT8 or t == SYBFLTN and col.column_size == 8:
            return "FLOAT"
        elif t == SYBBIT:
            return "BIT"
        elif t == SYBTEXT:
            return "TEXT"
        elif t == (SYBLONGBINARY,  # TODO correct ??
                   SYBIMAGE):
            return "IMAGE"
        elif t == SYBMONEY4:
            return "SMALLMONEY"
        elif t == SYBMONEY:
            return "MONEY"
        elif t == SYBREAL:
            return "REAL"
        elif t in (SYBBINARY, XSYBBINARY):
            return "BINARY(%d)" % min(size, max_len)
        elif t in (SYBVARBINARY, XSYBVARBINARY):
            if col.column_varint_size == 8:
                return "VARBINARY(MAX)"
            else:
                return "VARBINARY(%u)" % min(col.column_size, max_len)
        elif t == SYBUNIQUE:
            if IS_TDS7_PLUS(tds):
                return "UNIQUEIDENTIFIER"
        elif t == SYBNTEXT:
            if IS_TDS7_PLUS(tds):
                return "NTEXT"
        elif t in (SYBNVARCHAR, XSYBNVARCHAR):
            if col.column_varint_size == 8:
                return "NVARCHAR(MAX)"
            elif IS_TDS7_PLUS(tds):
                return "NVARCHAR(%u)" % max(col.column_size // 2, 1)
        elif t == XSYBNCHAR:
            if IS_TDS7_PLUS(tds):
                return "NCHAR(%u)" % min(col.column_size // 2, 4000)
        elif t == SYBVARIANT:
            if IS_TDS7_PLUS(tds):
                return "SQL_VARIANT"
        # nullable types should not occur here...
        elif t in (SYBMONEYN, SYBDATETIMN, SYBBITN):
            assert False
            # TODO...
        else:
            raise Exception("Unknown type %d", t)

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        size = tds_fix_column_size(tds, col)
        vs = col.column_varint_size
        if vs == 0:
            pass
        elif vs == 1:
            w.put_byte(size)
        elif vs == 2:
            w.put_smallint(size)
        elif vs in (4, 5):
            w.put_int(size)
        elif vs == 8:
            w.put_smallint(-1)

        # TDS7.1 output collate information
        if IS_TDS71_PLUS(tds) and is_collate_type(col.column_type):
            w.put_collation(tds.conn.collation)

    @staticmethod
    def put_data(tds, curcol):
        w = tds._writer
        #logger.debug("tds_data_put")
        if curcol.value is None:
            #logger.debug("tds_data_put: null param")
            vs = curcol.column_varint_size
            if vs == 5:
                w.put_int(0)
            elif vs == 4:
                w.put_int(-1)
            elif vs == 2:
                w.put_smallint(-1)
            elif vs == 8:
                w.put_int8(-1)
            else:
                assert curcol.column_varint_size
                # FIXME not good for SYBLONGBINARY/SYBLONGCHAR (still not supported)
                w.put_byte(0)
            return

        size = tds_fix_column_size(tds, curcol)

        # convert string if needed
        value = curcol.value
        if curcol.char_codec:
            # we need to convert data before
            # TODO this can be a waste of memory...
            value = tds_convert_string(tds, curcol.char_codec, value)
            colsize = len(value)
        else:
            colsize = curcol.column_size

        #
        # TODO here we limit data sent with MIN, should mark somewhere
        # and inform client ??
        # Test proprietary behavior
        #
        if IS_TDS7_PLUS(tds):
            #logger.debug("tds_data_put: not null param varint_size = %d",
            #             curcol.column_varint_size)

            vs = curcol.column_varint_size
            if vs == 8:
                w.put_int8(colsize)
                w.put_int(colsize)
            elif vs == 4:  # It's a BLOB...
                colsize = min(colsize, size)
                # mssql require only size
                w.put_int(colsize)
            elif vs == 2:
                colsize = min(colsize, size)
                w.put_smallint(colsize)
            elif vs == 1:
                w.put_byte(size)
            elif vs == 0:
                # TODO should be column_size
                colsize = tds_get_size_by_type(curcol.column_type)

            # put real data
            column_type = curcol.column_type
            if column_type == SYBINTN and size == 4 or column_type == SYBINT4:
                w.put_int(value)
            elif column_type == SYBINTN and size == 8 or column_type == SYBINT8:
                w.put_int8(value)
            elif column_type in (XSYBNVARCHAR, XSYBNCHAR):
                w.write(value)
            elif column_type in (XSYBVARBINARY, XSYBBINARY):
                w.write(value)
            elif column_type == SYBFLTN and size == 8 or column_type == SYBFLT8:
                w.write(_SYBFLT8_STRUCT.pack(value))
            elif column_type == SYBNTEXT:
                w.write(value)
            elif column_type == SYBUNIQUE:
                w.write(value.bytes_le)
            else:
                raise Exception('not implemented')
            # finish chunk for varchar/varbinary(max)
            if curcol.column_varint_size == 8 and colsize:
                w.put_int(0)
        else:
            raise Exception('not implemented')

_SYBFLT8_STRUCT = struct.Struct('d')
_ubyte_struct = struct.Struct('B')
_sbyte_struct = struct.Struct('b')
_sshort_struct = struct.Struct('<h')
_slong_struct = struct.Struct('<l')
_slong8_struct = struct.Struct('<q')
_flt4_struct = struct.Struct('f')
_money8_struct = struct.Struct('<lL')
_simple_types = {SYBVARCHAR, SYBCHAR, SYBTEXT, SYBBINARY,
                 SYBNVARCHAR, XSYBVARCHAR, XSYBNVARCHAR, XSYBCHAR, XSYBNCHAR,
                 XSYBVARBINARY, XSYBBINARY, SYBVARBINARY}


def to_python(tds, data, type, length):
    #logger.debug("to_python()")

    if type == SYBBIT or type == SYBBITN:
        return bool(_ubyte_struct.unpack(data)[0])

    elif type == SYBINT1 or type == SYBINTN and length == 1:
        return _sbyte_struct.unpack(data)[0]

    elif type == SYBINT2 or type == SYBINTN and length == 2:
        return _sshort_struct.unpack(data)[0]

    elif type == SYBINT4 or type == SYBINTN and length == 4:
        return _slong_struct.unpack(data)[0]

    elif type == SYBINT8 or type == SYBINTN and length == 8:
        return _slong8_struct.unpack(data)[0]

    elif type == SYBREAL or type == SYBFLTN and length == 4:
        return _flt4_struct.unpack(data)[0]

    elif type == SYBFLT8 or type == SYBFLTN and length == 8:
        return _SYBFLT8_STRUCT.unpack(data)[0]

    elif type in (SYBMONEY, SYBMONEY4, SYBMONEYN):
        if length == 8:
            hi, lo = _money8_struct.unpack(data)
            val = hi * (2 ** 32) + lo
        elif length == 4:
            val, = _slong_struct.unpack(data)
        else:
            raise Exception('unsupported size of money type')
        val = Decimal(val) / 10000
        return val

    #elif type in (SYBVARCHAR, SYBCHAR, SYBTEXT, SYBBINARY,\
    #        SYBNVARCHAR, XSYBVARCHAR, XSYBNVARCHAR, XSYBCHAR, XSYBNCHAR,\
    #        XSYBVARBINARY, XSYBBINARY, SYBVARBINARY):
    elif type in _simple_types:

        return data

    elif type == SYBUNIQUE:
        return uuid.UUID(bytes_le=data)

    else:
        raise Exception('unknown type {0}'.format(type))


if sys.version_info[0] >= 3:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + val, reversed(buf), 0)
else:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + ord(val), reversed(buf), 0)


class NumericHandler(object):
    MAX_NUMERIC = 33

    @staticmethod
    def ms_parse_numeric(positive, buf, scale):
        val = _decode_num(buf)
        val = Decimal(val)
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            val /= 10 ** scale
        return val

    @classmethod
    def get_data(cls, tds, curcol):
        r = tds._reader
        colsize = r.get_byte()

        # set NULL flag in the row buffer
        if colsize <= 0:
            return None

        #
        # Since these can be passed around independent
        # of the original column they came from, we embed the TDS_NUMERIC datatype in the row buffer
        # instead of using the wire representation, even though it uses a few more bytes.
        #
        # TODO perhaps it would be fine to change format ??
        #num.precision = curcol.column_prec
        scale = curcol.column_scale

        # server is going to crash freetds ??
        # TODO close connection it server try to do so ??
        if colsize > cls.MAX_NUMERIC:
            raise Exception('TDS_FAIL')
        positive = r.get_byte()
        buf = readall(r, colsize - 1)

        if IS_TDS7_PLUS(tds):
            return cls.ms_parse_numeric(positive, buf, scale)
        else:
            raise Exception('not supported')

    tds_numeric_bytes_per_prec = [
        #
        # precision can't be 0 but using a value > 0 assure no
        # core if for some bug it's 0...
        #
        1,
        2, 2, 3, 3, 4, 4, 4, 5, 5,
        6, 6, 6, 7, 7, 8, 8, 9, 9, 9,
        10, 10, 11, 11, 11, 12, 12, 13, 13, 14,
        14, 14, 15, 15, 16, 16, 16, 17, 17, 18,
        18, 19, 19, 19, 20, 20, 21, 21, 21, 22,
        22, 23, 23, 24, 24, 24, 25, 25, 26, 26,
        26, 27, 27, 28, 28, 28, 29, 29, 30, 30,
        31, 31, 31, 32, 32, 33, 33, 33
        ]

    @staticmethod
    def from_python(tds, col, value):
        if not (-10 ** 38 + 1 <= value <= 10 ** 38 - 1):
            raise DataError('Decimal value is out of range')
        value = value.normalize()
        col.column_type = SYBDECIMAL
        _, digits, exp = value.as_tuple()
        if exp > 0:
            col.column_scale = 0
            col.column_prec = len(digits) + exp
        else:
            col.column_scale = -exp
            col.column_prec = max(len(digits), col.column_scale)
        if col.column_prec > 38:
            raise DataError('Precision of decimal value is out of range')
        return value

    @staticmethod
    def get_declaration(tds, col):
        if col.column_type == SYBNUMERIC:
            return "NUMERIC(%d,%d)" % (col.column_prec, col.column_scale)
        elif col.column_type == SYBDECIMAL:
            return "DECIMAL(%d,%d)" % (col.column_prec, col.column_scale)

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        w.put_byte(NumericHandler.tds_numeric_bytes_per_prec[col.column_prec])
        w.put_byte(col.column_prec)
        w.put_byte(col.column_scale)

    @staticmethod
    def put_data(tds, col):
        w = tds._writer
        scale = col.column_scale
        size = NumericHandler.tds_numeric_bytes_per_prec[col.column_prec]
        w.put_byte(size)
        val = col.value
        positive = 1 if val > 0 else 0
        w.put_byte(positive)  # sign
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            size -= 1
            val = val * (10 ** scale)
        for i in range(size):
            w.put_byte(int(val % 256))
            val //= 256
        assert val == 0


#
# This strange type has following structure
# 0 len (int32) -- NULL
# len (int32), type (int8), data -- ints, date, etc
# len (int32), type (int8), 7 (int8), collation, column size (int16) -- [n]char, [n]varchar, binary, varbinary
# BLOBS (text/image) not supported
#
class VariantHandler(object):
    @staticmethod
    def get_data(tds, curcol):
        r = tds._reader
        colsize = r.get_int()

        # NULL
        try:
            if colsize < 2:
                r.skip(colsize)
                return None

            type = r.get_byte()
            info_len = r.get_byte()
            colsize -= 2
            if info_len > colsize:
                raise Exception('TDS_FAIL')
            if is_collate_type(type):
                if Collation.wire_size > info_len:
                    raise Exception('TDS_FAIL')
                curcol.collation = collation = r.get_collation()
                colsize -= Collation.wire_size
                info_len -= Collation.wire_size
                curcol.char_codec = ucs2_codec if is_unicode_type(type) else\
                    collation.get_codec()
            # special case for numeric
            if is_numeric_type(type):
                if info_len != 2:
                    raise Exception('TDS_FAIL')
                curcol.precision = r.get_byte()
                curcol.scale = scale = r.get_byte()
                colsize -= 2
                # FIXME check prec/scale, don't let server crash us
                if colsize > NumericHandler.MAX_NUMERIC:
                    raise Exception('TDS_FAIL')
                positive = r.get_byte()
                buf = readall(r, colsize - 1)
                return NumericHandler.ms_parse_numeric(positive, buf, scale)
            varint = 0 if type == SYBUNIQUE else tds_get_varint_size(tds, type)
            if varint != info_len:
                raise Exception('TDS_FAIL')
            if varint == 0:
                size = tds_get_size_by_type(type)
            elif varint == 1:
                size = r.get_byte()
            elif varint == 2:
                size = r.get_smallint()
            else:
                raise Exception('TDS_FAIL')
            colsize -= info_len
            if colsize:
                if curcol.char_codec:
                    data = tds_get_char_data(tds, colsize, curcol)
                else:
                    data = readall(r, colsize)
            colsize = 0
            return to_python(tds, data, type, colsize)
        except:
            r.skip(colsize)
            raise


def gen_get_varint_size():
    table = '''\
name	vendor	varint	fixed	nullable	variable	blob	numeric	unicode	ascii	size	nullable type
SYB5INT8	SYB	0	1	0	0	0	0	0	0	8	SYBINTN
SYBBINARY	ALL	1	0	1	1	0	0	0	0	-1	0
SYBBIT	ALL	0	1	0	0	0	0	0	0	1	SYBBITN
SYBBITN	MS	1	0	1	0	0	0	0	0	1	0	# Sybase bit is not nullable
SYBBLOB	SYB	??	0	1	1	1	0	Depend	Depend	-1	0
SYBBOUNDARY	SYB	1	0	1	1	0	0	0	1	-1	0
SYBCHAR	ALL	1	0	1	1	0	0	0	1	-1	0
SYBDATE	SYB	0	1	0	0	0	0	0	0	4	SYBDATEN
SYBDATEN	SYB	1	0	1	0	0	0	0	0	4	0
SYBDATETIME	ALL	0	1	0	0	0	0	0	0	8	SYBDATETIMN
SYBDATETIME4	ALL	0	1	0	0	0	0	0	0	4	SYBDATETIMN
SYBDATETIMN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBMSDATE	MS	1	0	1	0	0	0	0	0	4	0
SYBMSTIME	MS	1	0	1	0	0	0	0	0	-1	0
SYBMSDATETIME2	MS	1	0	1	0	0	0	0	0	-1	0
SYBMSDATETIMEOFFSET	MS	1	0	1	0	0	0	0	0	-1	0
SYBDECIMAL	ALL	1	0	1	0	0	1	0	0	-1	0
SYBFLT8	ALL	0	1	0	0	0	0	0	0	8	SYBFLTN
SYBFLTN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBIMAGE	ALL	4	0	1	1	1	0	0	0	-1	0
SYBINT1	ALL	0	1	0	0	0	0	0	0	1	SYBINTN
SYBINT2	ALL	0	1	0	0	0	0	0	0	2	SYBINTN
SYBINT4	ALL	0	1	0	0	0	0	0	0	4	SYBINTN
SYBINT8	MS	0	1	0	0	0	0	0	0	8	SYBINTN
SYBINTERVAL	SYB	0	1	0	0	0	0	0	0	8	0
SYBINTN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBLONGBINARY	SYB	5	0	1	1	1	0	Depend	Depend	-1	0
SYBLONGCHAR	SYB	5	0	1	1	1	0	??	??	-1	0
SYBMONEY	ALL	0	1	0	0	0	0	0	0	8	SYBMONEYN
SYBMONEY4	ALL	0	1	0	0	0	0	0	0	4	SYBMONEYN
SYBMONEYN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBMSUDT	MS	??	0	1	1	??	0	??	??	-1	0
SYBMSXML	MS	8	0	1	1	1	0	1	0	-1	0
SYBNTEXT	MS	4	0	1	1	1	0	1	0	-1	0
SYBNUMERIC	ALL	1	0	1	0	0	1	0	0	-1	0
SYBNVARCHAR	MS	??	0	1	1	0	0	1	0	-1	0	# Same as XSYBNVARCHAR ??
SYBREAL	ALL	0	1	0	0	0	0	0	0	4	SYBFLTN
SYBSENSITIVITY	SYB	1	0	1	1	0	0	0	1	-1	0
SYBSINT1	SYB	0	1	0	0	0	0	0	0	1	0
SYBTEXT	ALL	4	0	1	1	1	0	0	1	-1	0
SYBTIME	SYB	0	1	0	0	0	0	0	0	4	SYBTIMEN
SYBTIMEN	SYB	1	0	1	0	0	0	0	0	4	0
SYBUINT1	SYB	0	1	0	0	0	0	0	0	1	SYBUINTN
SYBUINT2	SYB	0	1	0	0	0	0	0	0	2	SYBUINTN
SYBUINT4	SYB	0	1	0	0	0	0	0	0	4	SYBUINTN
SYBUINT8	SYB	0	1	0	0	0	0	0	0	8	SYBUINTN
SYBUINTN	SYB	1	0	1	0	0	0	0	0	-1	0
SYBUNIQUE	MS	1	0	1	0	0	0	0	0	16	0	# have size but is nullable
SYBUNITEXT	SYB	4	0	1	1	1	0	1	0	-1	0	# UTF-16
SYBVARBINARY	ALL	1	0	1	1	0	0	0	0	-1	0
SYBVARCHAR	ALL	1	0	1	1	0	0	0	1	-1	0
SYBVARIANT	MS	4	0	1	1	0	0	Depend	Depend	-1	0	# varint ok ?
SYBVOID	MS ??	0	1	0	0	0	0	0	0	0	0
SYBXML	SYB	4	0	1	1	1	0	??	??	-1	0
XSYBBINARY	MS	2	0	1	1	0	0	0	0	-1	0
XSYBCHAR	MS	2	0	1	1	0	0	0	1	-1	0
XSYBNCHAR	MS	2	0	1	1	0	0	1	0	-1	0
XSYBNVARCHAR	MS	2	0	1	1	0	0	1	0	-1	0
XSYBVARBINARY	MS	2	0	1	1	0	0	0	0	-1	0
XSYBVARCHAR	MS	2	0	1	1	0	0	0	1	-1	0

# XSYBVARCHAR blob se TDS9 ??
# char if ascii or unicode
# there are some type that allow size 0 or a constants (SYBDATEN, SYBUNIQUE)
# some type (BITN, DATEN, UNIQUE, MSDATE) have size but are nullable
# tds_get_conversion_type from nullable to not nullable

# $Id: types.txt,v 1.5 2011/05/12 19:40:57 freddy77 Exp $
'''
    lines = list(map(lambda l: l.split('\t'), filter(lambda l: l and not l.startswith('#'), table.split('\n'))))
    header = lines[0]
    data = lines[1:]
    hd = dict((b, a) for a, b in enumerate(header))
    h = lambda l, name: l[hd[name]]
    from itertools import groupby

    gen_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() not in ('MS', 'SYB')]
    ms_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() == 'MS']
    syb_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() == 'SYB']
    types_sizes = [(h(l, 'name'), h(l, 'size')) for l in data]
    fmt = '''\
def tds_get_varint_size(tds, datatype):
{0}
    if IS_TDS7_PLUS(tds):
{1}
    elif IS_TDS50(tds):
{2}
    return 1

def tds_get_size_by_type(servertype):
{3}

def tds_get_conversion_type(srctype, colsize):
    raise Exception('not implemented')
'''
    keyfunc = lambda val: val[1]
    code = fmt.format(
        '\n'.join('    if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(gen_varint, key=keyfunc), keyfunc)),
        '\n'.join('        if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(ms_varint, key=keyfunc), keyfunc)),
        '\n'.join('        if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(syb_varint, key=keyfunc), keyfunc)),
        '\n'.join('    if servertype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(types_sizes, key=keyfunc), keyfunc)),
        )
    return compile(code, 'autogenerated_types', 'exec')

exec(gen_get_varint_size())


#
# Get column size for wire
#
def tds_fix_column_size(tds, curcol):
    size = curcol.column_size

    if not size:
        size = curcol.column_size
        if is_unicode_type(curcol.column_type):
            size *= 2

    vs = curcol.column_varint_size
    if vs == 0:
        return size
    elif vs == 1:
        size = max(min(size, 255), 1)
    elif vs == 2:
        if curcol.column_type in (XSYBNVARCHAR, XSYBNCHAR):
            mn = 2
        else:
            mn = 1
        size = max(min(size, 8000), mn)
    elif vs == 4:
        if curcol.column_type == SYBNTEXT:
            size = max(min(size, 0x7ffffffe), 2)
        else:
            size = max(min(size, 0x7fffffff), 1)
    return size


def tds_convert_string(tds, char_codec, s):
    if isinstance(s, bytes):
        s = s.decode('utf8')
    return char_codec.encode(s)[0]
    #return char_codec.encode(s)[0]

_utc = tzutc()


class MsDatetimeHandler(object):
    @staticmethod
    def get_info(tds, col):
        r = tds._reader
        col.scale = col.prec = 0
        if col.column_type != SYBMSDATE:
            col.scale = col.prec = r.get_byte()
            if col.prec > 7:
                raise Exception('TDS_FAIL')

    @staticmethod
    def get_data(tds, col):
        r = tds._reader
        size = r.get_byte()
        if size == 0:
            return None

        if col.column_type == SYBMSDATETIMEOFFSET:
            size -= 2
        if col.column_type != SYBMSTIME:
            size -= 3
        if size < 0:
            raise Exception('TDS_FAIL')

        # get time part
        nanoseconds = 0
        if col.column_type != SYBMSDATE:
            assert size >= 3 and size <= 5
            if size < 3 or size > 5:
                raise Exception('TDS_FAIL')
            time_buf = readall(r, size)
            val = _decode_num(time_buf)
            val *= 10 ** (7 - col.prec)
            nanoseconds = val * 100

        # get date part
        days = 0
        if col.column_type != SYBMSTIME:
            date_buf = readall(r, 3)
            days = _decode_num(date_buf)

        # get time offset
        if col.column_type == SYBMSTIME:
            hours = nanoseconds // 1000000000 // 60 // 60
            nanoseconds -= hours * 60 * 60 * 1000000000
            minutes = nanoseconds // 1000000000 // 60
            nanoseconds -= minutes * 60 * 1000000000
            seconds = nanoseconds // 1000000000
            nanoseconds -= seconds * 1000000000
            return time(hours, minutes, seconds, nanoseconds // 1000)
        elif col.column_type == SYBMSDATE:
            return _applytz(date(1, 1, 1) + timedelta(days=days), tds.use_tz)
        elif col.column_type == SYBMSDATETIME2:
            return _applytz(datetime(1, 1, 1) + timedelta(days=days, microseconds=nanoseconds // 1000), tds.use_tz)
        elif col.column_type == SYBMSDATETIMEOFFSET:
            offset = r.get_smallint()
            if offset > 840 or offset < -840:
                raise Exception('TDS_FAIL')
            tz = tzoffset('', offset * 60)
            return (datetime(1, 1, 1, tzinfo=_utc) + timedelta(days=days, microseconds=nanoseconds // 1000)).astimezone(tz)

    @staticmethod
    def from_python(tds, col, value):
        if isinstance(value, datetime):
            if value.tzinfo and not tds.use_tz:
                col.column_type = SYBMSDATETIMEOFFSET
            else:
                col.column_type = SYBMSDATETIME2
            col.prec = col.scale = 6
        elif isinstance(value, date):
            col.column_type = SYBMSDATE
        elif isinstance(value, time):
            if value.tzinfo and not tds.use_tz:
                col.column_type = SYBMSDATETIMEOFFSET
            else:
                col.column_type = SYBMSTIME
            col.prec = col.scale = 6
        return value

    @staticmethod
    def get_declaration(tds, col):
        t = col.column_type
        if t == SYBMSTIME:
            return "TIME({0})".format(col.scale)
        elif t == SYBMSDATE:
            return "DATE"
        elif t == SYBMSDATETIME2:
            return "DATETIME2({0})".format(col.scale)
        elif t == SYBMSDATETIMEOFFSET:
            return "DATETIMEOFFSET({0})".format(col.scale)

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        if col.column_type != SYBMSDATE:
            w.put_byte(col.prec)

    _base_date2 = datetime(1, 1, 1)
    _base_date2_utc = datetime(1, 1, 1, tzinfo=_utc)

    _precision_to_len = {
        0: 3,
        1: 3,
        2: 3,
        3: 4,
        4: 4,
        5: 5,
        6: 5,
        7: 5,
        }

    @staticmethod
    def put_data(tds, col):
        w = tds._writer
        if col.value is None:
            w.put_byte(0)
            return

        value = col.value
        tzinf = getattr(value, 'tzinfo', None)
        utcoffset = None
        if tzinf:
            utcoffset = value.utcoffset()
            if tds.use_tz:
                value = value.astimezone(tds.use_tz).replace(tzinfo=None)
            else:
                value = value.astimezone(_utc).replace(tzinfo=None)
        parts = []
        if col.column_type != SYBMSDATE:
            # Encoding time part
            t = value
            secs = t.hour * 60 * 60 + t.minute * 60 + t.second
            val = (secs * 10 ** 7 + t.microsecond * 10) // (10 ** (7 - col.prec))
            parts.append(struct.pack('<Q', val)[:MsDatetimeHandler._precision_to_len[col.prec]])
        if col.column_type != SYBMSTIME:
            # Encoding date part
            if type(value) == date:
                value = datetime.combine(value, time(0, 0, 0))
            days = (value - MsDatetimeHandler._base_date2).days
            buf = struct.pack('<l', days)[:3]
            parts.append(buf)
        if col.column_type == SYBMSDATETIMEOFFSET:
            # Encoding timezone part
            assert utcoffset is not None
            parts.append(struct.pack('<h', int(utcoffset.total_seconds()) // 60))
        size = reduce(lambda a, b: a + len(b), parts, 0)
        w.put_byte(size)
        for part in parts:
            w.write(part)


class DatetimeHandler(object):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    @classmethod
    def from_python(cls, tds, col, value):
        col.column_type = SYBDATETIMN
        col.size = 8
        Datetime.validate(value)
        return value

    @staticmethod
    def get_declaration(tds, col):
        t = col.column_type
        if t == SYBDATETIME or t == SYBDATETIMN and col.size == 8:
            return "DATETIME"
        elif t == SYBDATETIME4 or t == SYBDATETIMN and col.size == 4:
            return "SMALLDATETIME"

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        if col.column_type == SYBDATETIMN:
            w.put_byte(col.size)

    @classmethod
    def put_data(cls, tds, col):
        w = tds._writer
        value = col.value
        if col.column_type == SYBDATETIMN:
            if value is None:
                w.put_byte(0)
                return
            else:
                w.put_byte(col.size)

        if col.column_type == SYBDATETIME or col.column_type == SYBDATETIMN and col.size == 8:
            w.write(Datetime.encode(value))
        elif col.column_type == SYBDATETIME4 or col.column_type == SYBDATETIMN and col.size == 4:
            raise NotImplementedError
        else:
            assert False


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
    r = tds._reader
    #
    # dest is usually a column buffer, allocated when the column's metadata are processed
    # and reused for each row.
    # For blobs, dest is blob->textvalue, and can be reallocated or freed
    # TODO: reallocate if blob and no space
    #
    # silly case, empty string
    if wire_size == 0:
        return ''

    if curcol.char_codec:
        #
        # TODO The conversion should be selected from curcol and tds version
        # TDS7.1/single -> use curcol collation
        # TDS7/single -> use server single byte
        # TDS7+/unicode -> use server (always unicode)
        # TDS5/4.2 -> use server
        # TDS5/UTF-8 -> use server
        # TDS5/UTF-16 -> use UTF-16
        #
        return curcol.char_codec.decode(readall(r, wire_size))[0]
    else:
        return readall(r, wire_size)


class Datetime:
    base_date = datetime(1900, 1, 1)
    min = datetime(1753, 1, 1, 0, 0, 0)
    max = datetime(9999, 12, 31, 23, 59, 59, 997000)
    size = 8

    @classmethod
    def validate(cls, value):
        if not (cls.min <= value <= cls.max):
            raise DataError('Date is out of range')

    @classmethod
    def encode(cls, value):
        cls.validate(value)
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - cls.base_date).days
        ms = value.microsecond // 1000
        tm = (value.hour * 60 * 60 + value.minute * 60 + value.second) * 300 + int(round(ms * 3 / 10.0))
        return TDS_DATETIME.pack(days, tm)

    @classmethod
    def decode(cls, days, time):
        ms = int(round(time % 300 * 10 / 3.0))
        secs = time // 300
        return cls.base_date + timedelta(days=days, seconds=secs, milliseconds=ms)
