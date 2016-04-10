from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
import struct
import re
import uuid

from six.moves import reduce

from .tds_base import *
from .collate import ucs2_codec, Collation, lcid2charset, raw_collation
from . import tz


_flt4_struct = struct.Struct('f')
_flt8_struct = struct.Struct('d')
_utc = tz.utc


def _applytz(dt, tz):
    if not tz:
        return dt
    dt = dt.replace(tzinfo=tz)
    return dt


def _decode_num(buf):
    """ Decodes little-endian integer from buffer

    Buffer can be of any size
    """
    return reduce(lambda acc, val: acc * 256 + ord(val), reversed(buf), 0)


class PlpReader(object):
    """ Partially length prefixed reader

    Spec: http://msdn.microsoft.com/en-us/library/dd340469.aspx
    """
    def __init__(self, r):
        """
        :param r: An instance of :class:`_TdsReader`
        """
        self._rdr = r
        size = r.get_uint8()
        self._size = size

    def is_null(self):
        """
        :return: True if stored value is NULL
        """
        return self._size == PLP_NULL

    def is_unknown_len(self):
        """
        :return: True if total size is unknown upfront
        """
        return self._size == PLP_UNKNOWN

    def size(self):
        """
        :return: Total size in bytes if is_uknown_len and is_null are both False
        """
        return self._size

    def chunks(self):
        """ Generates chunks from stream, each chunk is an instace of bytes.
        """
        if self.is_null():
            return
        total = 0
        while True:
            chunk_len = self._rdr.get_uint()
            if chunk_len == 0:
                if not self.is_unknown_len() and total != self._size:
                    msg = "PLP actual length (%d) doesn't match reported length (%d)" % (total, self._size)
                    self._rdr.session.bad_stream(msg)

                return

            total += chunk_len
            left = chunk_len
            while left:
                buf = self._rdr.read(left)
                yield buf
                left -= len(buf)


class BaseType(object):
    """ Base type for TDS data types.

    All TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    """
    def get_typeid(self):
        """ Returns type identifier of type. """
        return self.type

    def get_declaration(self):
        """ Returns SQL declaration for this type.

        Examples are: NVARCHAR(10), TEXT, TINYINT
        Should be implemented in actual types.
        """
        raise NotImplementedError

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        """ Class method that parses declaration and returns a type instance.

        :param declaration: type declaration string
        :param nullable: true if type have to be nullable, false otherwise
        :param connection: instance of :class:`_TdsSocket`
        :return: If declaration is parsed, returns type instance,
                 otherwise returns None.

        Should be implemented in actual types.
        """
        raise NotImplementedError

    @classmethod
    def from_stream(cls, r):
        """ Class method that reads and returns a type instance.

        :param r: An instance of :class:`_TdsReader` to read type from.

        Should be implemented in actual types.
        """
        raise NotImplementedError

    def write_info(self, w):
        """ Writes type info into w stream.

        :param w: An instance of :class:`_TdsWriter` to write into.

        Should be symmetrical to from_stream method.
        Should be implemented in actual types.
        """
        raise NotImplementedError

    def write(self, w, value):
        """ Writes type's value into stream

        :param w: An instance of :class:`_TdsWriter` to write into.
        :param value: A value to be stored, should be compatible with the type

        Should be implemented in actual types.
        """
        raise NotImplementedError

    def read(self, r):
        """ Reads value from the stream.

        :param r: An instance of :class:`_TdsReader` to read value from.
        :return: A read value.

        Should be implemented in actual types.
        """
        raise NotImplementedError


class BasePrimitiveType(BaseType):
    """ Base type for primitive TDS data types.

    Primitive type is a fixed size type with no type arguments.
    All primitive TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    - declaration - class variable storing name of sql type
    - isntance - class variable storing instance of class
    """

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if not nullable and declaration == cls.declaration:
            return cls.instance

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def write_info(self, w):
        pass


class BaseTypeN(BaseType):
    """ Base type for nullable TDS data types.

    All nullable TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    - subtypes - class variable storing dict {subtype_size: subtype_instance}
    """

    def __init__(self, size):
        assert size in self.subtypes
        self._size = size
        self._current_subtype = self.subtypes[size]

    def get_typeid(self):
        return self._current_subtype.get_typeid()

    def get_declaration(self):
        return self._current_subtype.get_declaration()

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if nullable:
            for size, subtype in cls.subtypes.items():
                inst = subtype.from_declaration(declaration, False, connection)
                if inst:
                    return cls(size)

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in cls.subtypes:
            raise InterfaceError('Invalid %s size' % cls.type, size)
        return cls(size)

    def write_info(self, w):
        w.put_byte(self._size)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size not in self.subtypes:
            raise r.session.bad_stream('Invalid %s size' % self.type, size)
        return self.subtypes[size].read(r)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
            return
        w.put_byte(self._size)
        self._current_subtype.write(w, val)

class Bit(BasePrimitiveType):
    type = SYBBIT
    declaration = 'BIT'

    def write(self, w, value):
        w.put_byte(1 if value else 0)

    def read(self, r):
        return bool(r.get_byte())

Bit.instance = Bit()


class BitN(BaseTypeN):
    type = SYBBITN
    subtypes = {1 : Bit.instance}

BitN.instance = BitN(1)


class TinyInt(BasePrimitiveType):
    type = SYBINT1
    declaration = 'TINYINT'

    def write(self, w, val):
        w.put_byte(val)

    def read(self, r):
        return r.get_byte()

TinyInt.instance = TinyInt()


class SmallInt(BasePrimitiveType):
    type = SYBINT2
    declaration = 'SMALLINT'

    def write(self, w, val):
        w.put_smallint(val)

    def read(self, r):
        return r.get_smallint()

SmallInt.instance = SmallInt()


class Int(BasePrimitiveType):
    type = SYBINT4
    declaration = 'INT'

    def write(self, w, val):
        w.put_int(val)

    def read(self, r):
        return r.get_int()

Int.instance = Int()


class BigInt(BasePrimitiveType):
    type = SYBINT8
    declaration = 'BIGINT'

    def write(self, w, val):
        w.put_int8(val)

    def read(self, r):
        return r.get_int8()

BigInt.instance = BigInt()


class IntN(BaseTypeN):
    type = SYBINTN

    subtypes = {
        1: TinyInt.instance,
        2: SmallInt.instance,
        4: Int.instance,
        8: BigInt.instance,
    }


class Real(BasePrimitiveType):
    type = SYBREAL
    declaration = 'REAL'

    def write(self, w, val):
        w.pack(_flt4_struct, val)

    def read(self, r):
        return r.unpack(_flt4_struct)[0]

Real.instance = Real()


class Float(BasePrimitiveType):
    type = SYBFLT8
    declaration = 'FLOAT'

    def write(self, w, val):
        w.pack(_flt8_struct, val)

    def read(self, r):
        return r.unpack(_flt8_struct)[0]

Float.instance = Float()


class FloatN(BaseTypeN):
    type = SYBFLTN

    subtypes = {
        4: Real.instance,
        8: Float.instance,
    }


class VarChar70(BaseType):
    type = XSYBVARCHAR

    def __init__(self, size, codec):
        #if size <= 0 or size > 8000:
        #    raise DataError('Invalid size for VARCHAR field')
        self._size = size
        self._codec = codec

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        return cls(size, codec=r._session.conn.server_codec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.server_codec)

    def get_declaration(self):
        return 'VARCHAR({0})'.format(self._size)

    def write_info(self, w):
        w.put_smallint(self._size)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_smallint(len(val))
            #w.put_smallint(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_smallint()
        if size < 0:
            return None
        return r.read_str(size, self._codec)


class VarChar71(VarChar70):
    def __init__(self, size, collation):
        super(VarChar71, self).__init__(size, codec=collation.get_codec())
        self._collation = collation

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)

    def write_info(self, w):
        super(VarChar71, self).write_info(w)
        w.put_collation(self._collation)


class VarChar72(VarChar71):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        if size == 0xffff:
            return VarCharMax(collation)
        return cls(size, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'VARCHAR(MAX)':
            return VarCharMax(connection.collation)
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)


class VarCharMax(VarChar72):
    def __init__(self, collation):
        super(VarChar72, self).__init__(0, collation)

    def get_declaration(self):
        return 'VARCHAR(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)
        w.put_collation(self._collation)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_int8(len(val))
            if len(val) > 0:
                w.put_int(len(val))
                w.write(val)
            w.put_int(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        return ''.join(iterdecode(r.chunks(), self._codec))


class NVarChar70(BaseType):
    type = XSYBNVARCHAR

    def __init__(self, size):
        #if size <= 0 or size > 4000:
        #    raise DataError('Invalid size for NVARCHAR field')
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        return cls(size / 2)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'NVARCHAR({0})'.format(self._size)

    def write_info(self, w):
        w.put_usmallint(self._size * 2)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_usmallint(0xffff)
        else:
            if isinstance(val, bytes):
                val = force_unicode(val)
            buf, _ = ucs2_codec.encode(val)
            l = len(buf)
            w.put_usmallint(l)
            w.write(buf)

    def read(self, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return None
        return r.read_str(size, ucs2_codec)


class NVarChar71(NVarChar70):
    def __init__(self, size, collation=raw_collation):
        super(NVarChar71, self).__init__(size)
        self._collation = collation

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        return cls(size / 2, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)

    def write_info(self, w):
        super(NVarChar71, self).write_info(w)
        w.put_collation(self._collation)


class NVarChar72(NVarChar71):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        if size == 0xffff:
            return NVarCharMax(size, collation)
        return cls(size / 2, collation=collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'NVARCHAR(MAX)':
            return VarCharMax(connection.collation)
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)


class NVarCharMax(NVarChar72):
    def get_typeid(self):
        return SYBNTEXT

    def get_declaration(self):
        return 'NVARCHAR(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)
        w.put_collation(self._collation)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            if isinstance(val, bytes):
                val = force_unicode(val)
            val, _ = ucs2_codec.encode(val)
            w.put_uint8(len(val))
            if len(val) > 0:
                w.put_uint(len(val))
                w.write(val)
            w.put_uint(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        res = ''.join(iterdecode(r.chunks(), ucs2_codec))
        return res


class Xml(NVarCharMax):
    type = SYBMSXML
    declaration = 'XML'

    def __init__(self, schema={}):
        super(Xml, self).__init__(0)
        self._schema = schema

    def get_typeid(self):
        return self.type

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        has_schema = r.get_byte()
        schema = {}
        if has_schema:
            schema['dbname'] = r.read_ucs2(r.get_byte())
            schema['owner'] = r.read_ucs2(r.get_byte())
            schema['collection'] = r.read_ucs2(r.get_smallint())
        return cls(schema)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def write_info(self, w):
        if self._schema:
            w.put_byte(1)
            w.put_byte(len(self._schema['dbname']))
            w.write_ucs2(self._schema['dbname'])
            w.put_byte(len(self._schema['owner']))
            w.write_ucs2(self._schema['owner'])
            w.put_usmallint(len(self._schema['collection']))
            w.write_ucs2(self._schema['collection'])
        else:
            w.put_byte(0)


class Text70(BaseType):
    type = SYBTEXT
    declaration = 'TEXT'

    def __init__(self, size=0, table_name='', codec=None):
        self._size = size
        self._table_name = table_name
        self._codec = codec

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, codec=r.session.conn.server_codec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def get_declaration(self):
        return self.declaration

    def write_info(self, w):
        w.put_int(self._size)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_int(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        readall(r, size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, self._codec)


class Text71(Text70):
    def __init__(self, size=0, table_name='', collation=raw_collation):
        self._size = size
        self._collation = collation
        self._codec = collation.get_codec()
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, collation)

    def write_info(self, w):
        w.put_int(self._size)
        w.put_collation(self._collation)


class Text72(Text71):
    def __init__(self, size=0, table_name_parts=[], collation=raw_collation):
        super(Text72, self).__init__(size, '.'.join(table_name_parts), collation)
        self._table_name_parts = table_name_parts

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_smallint()))
        return cls(size, parts, collation)


class NText70(BaseType):
    type = SYBNTEXT
    declaration = 'NTEXT'

    def __init__(self, size=0, table_name=''):
        self._size = size
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def get_declaration(self):
        return self.declaration

    def read(self, r):
        textptr_size = r.get_byte()
        if textptr_size == 0:
            return None
        readall(r, textptr_size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, ucs2_codec)

    def write_info(self, w):
        w.put_int(self._size * 2)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)


class NText71(NText70):
    def __init__(self, size=0, table_name='', collation=raw_collation):
        self._size = size
        self._collation = collation
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, collation)

    def write_info(self, w):
        w.put_int(self._size)
        w.put_collation(self._collation)

    def read(self, r):
        textptr_size = r.get_byte()
        if textptr_size == 0:
            return None
        readall(r, textptr_size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, ucs2_codec)


class NText72(NText71):
    def __init__(self, size=0, table_name_parts=[], collation=raw_collation):
        self._size = size
        self._collation = collation
        self._table_name_parts = table_name_parts

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_smallint()))
        return cls(size, parts, collation)


class VarBinary(BaseType):
    type = XSYBVARBINARY

    def __init__(self, size):
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        return cls(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARBINARY\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'VARBINARY({0})'.format(self._size)

    def write_info(self, w):
        w.put_usmallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_usmallint(0xffff)
        else:
            w.put_usmallint(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return None
        return readall(r, size)


class VarBinary72(VarBinary):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return VarBinaryMax()
        return cls(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'VARBINARY(MAX)':
            return VarBinaryMax()
        m = re.match(r'VARBINARY\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))


class VarBinaryMax(VarBinary):
    def __init__(self):
        super(VarBinaryMax, self).__init__(0)

    def get_declaration(self):
        return 'VARBINARY(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            w.put_uint8(len(val))
            if val:
                w.put_uint(len(val))
                w.write(val)
            w.put_uint(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        return b''.join(r.chunks())


class Image70(BaseType):
    type = SYBIMAGE
    declaration = 'IMAGE'

    def __init__(self, size=0, table_name=''):
        self._table_name = table_name
        self._size = size

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def read(self, r):
        size = r.get_byte()
        if size == 16:  # Jeff's hack
            readall(r, 16)  # textptr
            readall(r, 8)  # timestamp
            colsize = r.get_int()
            return readall(r, colsize)
        else:
            return None

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
            return
        w.put_int(len(val))
        w.write(val)

    def write_info(self, w):
        w.put_int(self._size)


class Image72(Image70):
    def __init__(self, size=0, parts=[]):
        self._parts = parts
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_usmallint()))
        return Image72(size, parts)


class BaseDateTime(BaseType):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)


class SmallDateTime(BasePrimitiveType, BaseDateTime):
    type = SYBDATETIME4
    declaration = 'SMALLDATETIME'

    _max_date = datetime(2079, 6, 6, 23, 59, 0)
    _struct = struct.Struct('<HH')

    def write(self, w, val):
        if val.tzinfo:
            if not w.session.use_tz:
                raise DataError('Timezone-aware datetime is used without specifying use_tz')
            val = val.astimezone(w.session.use_tz).replace(tzinfo=None)
        days = (val - self._base_date).days
        minutes = val.hour * 60 + val.minute
        w.pack(self._struct, days, minutes)

    def read(self, r):
        days, minutes = r.unpack(self._struct)
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return (self._base_date + timedelta(days=days, minutes=minutes)).replace(tzinfo=tzinfo)

SmallDateTime.instance = SmallDateTime()


class DateTime(BasePrimitiveType, BaseDateTime):
    type = SYBDATETIME
    declaration = 'DATETIME'

    _struct = struct.Struct('<ll')

    def write(self, w, val):
        if val.tzinfo:
            if not w.session.use_tz:
                raise DataError('Timezone-aware datetime is used without specifying use_tz')
            val = val.astimezone(w.session.use_tz).replace(tzinfo=None)
        w.write(self.encode(val))

    def read(self, r):
        days, t = r.unpack(self._struct)
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return _applytz(self.decode(days, t), tzinfo)

    @classmethod
    def validate(cls, value):
        if not (cls._min_date <= value <= cls._max_date):
            raise DataError('Date is out of range')

    @classmethod
    def encode(cls, value):
        #cls.validate(value)
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - cls._base_date).days
        ms = value.microsecond // 1000
        tm = (value.hour * 60 * 60 + value.minute * 60 + value.second) * 300 + int(round(ms * 3 / 10.0))
        return cls._struct.pack(days, tm)

    @classmethod
    def decode(cls, days, time):
        ms = int(round(time % 300 * 10 / 3.0))
        secs = time // 300
        return cls._base_date + timedelta(days=days, seconds=secs, milliseconds=ms)

DateTime.instance = DateTime()


class DateTimeN(BaseTypeN, BaseDateTime):
    type = SYBDATETIMN
    subtypes = {
        4: SmallDateTime.instance,
        8: DateTime.instance,
    }


class BaseDateTime73(BaseType):
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

    _base_date = datetime(1, 1, 1)

    def _write_time(self, w, t, prec):
        secs = t.hour * 60 * 60 + t.minute * 60 + t.second
        val = (secs * 10 ** 7 + t.microsecond * 10) // (10 ** (7 - prec))
        w.write(struct.pack('<Q', val)[:self._precision_to_len[prec]])

    def _read_time(self, r, size, prec, use_tz):
        time_buf = readall(r, size)
        val = _decode_num(time_buf)
        val *= 10 ** (7 - prec)
        nanoseconds = val * 100
        hours = nanoseconds // 1000000000 // 60 // 60
        nanoseconds -= hours * 60 * 60 * 1000000000
        minutes = nanoseconds // 1000000000 // 60
        nanoseconds -= minutes * 60 * 1000000000
        seconds = nanoseconds // 1000000000
        nanoseconds -= seconds * 1000000000
        return time(hours, minutes, seconds, nanoseconds // 1000, tzinfo=use_tz)

    def _write_date(self, w, value):
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - self._base_date).days
        buf = struct.pack('<l', days)[:3]
        w.write(buf)

    def _read_date(self, r):
        days = _decode_num(readall(r, 3))
        return (self._base_date + timedelta(days=days)).date()


class MsDate(BasePrimitiveType, BaseDateTime73):
    type = SYBMSDATE
    declaration = 'DATE'

    MIN = date(1, 1, 1)
    MAX = date(9999, 12, 31)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            w.put_byte(3)
            self._write_date(w, value)

    def read_fixed(self, r):
        return self._read_date(r)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self._read_date(r)

MsDate.instance = MsDate()


class MsTime(BaseDateTime73):
    type = SYBMSTIME

    def __init__(self, prec):
        self._prec = prec
        self._size = self._precision_to_len[prec]

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'TIME\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'TIME({0})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not w.session.use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(w.session.use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)

    def read_fixed(self, r, size):
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return self._read_time(r, size, self._prec, tzinfo)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class DateTime2(BaseDateTime73):
    type = SYBMSDATETIME2

    def __init__(self, prec=7):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 3

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    def get_declaration(self):
        return 'DATETIME2({0})'.format(self._prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DATETIME2':
            return cls()
        m = re.match(r'DATETIME2\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not w.session.use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(w.session.use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)
            self._write_date(w, value)

    def read_fixed(self, r, size):
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        time = self._read_time(r, size - 3, self._prec, tzinfo)
        date = self._read_date(r)
        return datetime.combine(date, time)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class DateTimeOffset(BaseDateTime73):
    type = SYBMSDATETIMEOFFSET

    def __init__(self, prec=7):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 5

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DATETIMEOFFSET':
            return cls()
        m = re.match(r'DATETIMEOFFSET\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'DATETIMEOFFSET({0})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            utcoffset = value.utcoffset()
            value = value.astimezone(_utc).replace(tzinfo=None)

            w.put_byte(self._size)
            self._write_time(w, value, self._prec)
            self._write_date(w, value)
            w.put_smallint(int(total_seconds(utcoffset)) // 60)

    def read_fixed(self, r, size):
        time = self._read_time(r, size - 5, self._prec, _utc)
        date = self._read_date(r)
        offset = r.get_smallint()
        tzinfo_factory = r._session.tzinfo_factory
        if tzinfo_factory is None:
            from .tz import FixedOffsetTimezone
            tzinfo_factory = FixedOffsetTimezone
        tz = tzinfo_factory(offset)
        return datetime.combine(date, time).astimezone(tz)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class MsDecimal(BaseType):
    type = SYBDECIMAL

    _max_size = 17

    _bytes_per_prec = [
        #
        # precision can't be 0 but using a value > 0 assure no
        # core if for some bug it's 0...
        #
        1,
        5, 5, 5, 5, 5, 5, 5, 5, 5,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        13, 13, 13, 13, 13, 13, 13, 13, 13,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    ]

    _info_struct = struct.Struct('BBB')

    @property
    def scale(self):
        return self._scale

    @property
    def precision(self):
        return self._prec

    def __init__(self, scale=0, prec=18):
        if prec > 38:
            raise DataError('Precision of decimal value is out of range')
        self._scale = scale
        self._prec = prec
        self._size = self._bytes_per_prec[prec]

    @classmethod
    def from_value(cls, value):
        if not (-10 ** 38 + 1 <= value <= 10 ** 38 - 1):
            raise DataError('Decimal value is out of range')
        value = value.normalize()
        _, digits, exp = value.as_tuple()
        if exp > 0:
            scale = 0
            prec = len(digits) + exp
        else:
            scale = -exp
            prec = max(len(digits), scale)
        return cls(scale=scale, prec=prec)

    @classmethod
    def from_stream(cls, r):
        size, prec, scale = r.unpack(cls._info_struct)
        return cls(scale=scale, prec=prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DECIMAL':
            return cls()
        m = re.match(r'DECIMAL\((\d+),\s*(\d+)\)', declaration)
        if m:
            return cls(int(m.group(2)), int(m.group(1)))

    def get_declaration(self):
        return 'DECIMAL({0},{1})'.format(self._prec, self._scale)

    def write_info(self, w):
        w.pack(self._info_struct, self._size, self._prec, self._scale)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
            return
        if not isinstance(value, Decimal):
            value = Decimal(value)
        value = value.normalize()
        scale = self._scale
        size = self._size
        w.put_byte(size)
        val = value
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

    def _decode(self, positive, buf):
        val = _decode_num(buf)
        val = Decimal(val)
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            val /= 10 ** self._scale
        return val

    def read_fixed(self, r, size):
        positive = r.get_byte()
        buf = readall(r, size - 1)
        return self._decode(positive, buf)

    def read(self, r):
        size = r.get_byte()
        if size <= 0:
            return None
        return self.read_fixed(r, size)


class Money4(BasePrimitiveType):
    type = SYBMONEY4
    declaration = 'SMALLMONEY'

    def read(self, r):
        return Decimal(r.get_int()) / 10000

    def write(self, w, val):
        val = int(val * 10000)
        w.put_int(val)

Money4.instance = Money4()


class Money8(BasePrimitiveType):
    type = SYBMONEY
    declaration = 'MONEY'

    _struct = struct.Struct('<lL')

    def read(self, r):
        hi, lo = r.unpack(self._struct)
        val = hi * (2 ** 32) + lo
        return Decimal(val) / 10000

    def write(self, w, val):
        val = val * 10000
        hi = int(val // (2 ** 32))
        lo = int(val % (2 ** 32))
        w.pack(self._struct, hi, lo)

Money8.instance = Money8()


class MoneyN(BaseTypeN):
    type = SYBMONEYN

    subtypes = {
        4: Money4.instance,
        8: Money8.instance,
    }


class MsUnique(BaseType):
    type = SYBUNIQUE
    declaration = 'UNIQUEIDENTIFIER'

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size != 16:
            raise InterfaceError('Invalid size of UNIQUEIDENTIFIER field')
        return cls.instance

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls.instance

    def get_declaration(self):
        return self.declaration

    def write_info(self, w):
        w.put_byte(16)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            w.put_byte(16)
            w.write(value.bytes_le)

    def read_fixed(self, r, size):
        return uuid.UUID(bytes_le=readall(r, size))

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size != 16:
            raise InterfaceError('Invalid size of UNIQUEIDENTIFIER field')
        return self.read_fixed(r, size)
MsUnique.instance = MsUnique()


def _variant_read_str(r, size):
    collation = r.get_collation()
    r.get_usmallint()
    return r.read_str(size, collation.get_codec())


def _variant_read_nstr(r, size):
    r.get_collation()
    r.get_usmallint()
    return r.read_str(size, ucs2_codec)


def _variant_read_decimal(r, size):
    prec, scale = r.unpack(Variant._decimal_info_struct)
    return MsDecimal(prec=prec, scale=scale).read_fixed(r, size)


def _variant_read_binary(r, size):
    r.get_usmallint()
    return readall(r, size)


class Variant(BaseType):
    type = SYBVARIANT
    declaration = 'SQL_VARIANT'

    _decimal_info_struct = struct.Struct('BB')

    _type_map = {
        GUIDTYPE: lambda r, size: MsUnique.instance.read_fixed(r, size),
        BITTYPE: lambda r, size: Bit.instance.read(r),
        INT1TYPE: lambda r, size: TinyInt.instance.read(r),
        INT2TYPE: lambda r, size: SmallInt.instance.read(r),
        INT4TYPE: lambda r, size: Int.instance.read(r),
        INT8TYPE: lambda r, size: BigInt.instance.read(r),
        DATETIMETYPE: lambda r, size: DateTime.instance.read(r),
        DATETIM4TYPE: lambda r, size: SmallDateTime.instance.read(r),
        FLT4TYPE: lambda r, size: Real.instance.read(r),
        FLT8TYPE: lambda r, size: Float.instance.read(r),
        MONEYTYPE: lambda r, size: Money8.instance.read(r),
        MONEY4TYPE: lambda r, size: Money4.instance.read(r),
        DATENTYPE: lambda r, size: MsDate.instance.read_fixed(r),

        TIMENTYPE: lambda r, size: MsTime(prec=r.get_byte()).read_fixed(r, size),
        DATETIME2NTYPE: lambda r, size: DateTime2(prec=r.get_byte()).read_fixed(r, size),
        DATETIMEOFFSETNTYPE: lambda r, size: DateTimeOffset(prec=r.get_byte()).read_fixed(r, size),

        BIGVARBINTYPE: _variant_read_binary,
        BIGBINARYTYPE: _variant_read_binary,

        NUMERICNTYPE: _variant_read_decimal,
        DECIMALNTYPE: _variant_read_decimal,

        BIGVARCHRTYPE: _variant_read_str,
        BIGCHARTYPE: _variant_read_str,
        NVARCHARTYPE: _variant_read_nstr,
        NCHARTYPE: _variant_read_nstr,

    }

    def __init__(self, size):
        self._size = size

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        return Variant(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls(0)

    def write_info(self, w):
        w.put_int(self._size)

    def read(self, r):
        size = r.get_int()
        if size == 0:
            return None

        type_id = r.get_byte()
        prop_bytes = r.get_byte()
        type_factory = self._type_map.get(type_id)
        if not type_factory:
            r.session.bad_stream('Variant type invalid', type_id)
        return type_factory(r, size - prop_bytes - 2)

    def write(self, w, val):
        if val is None:
            w.put_int(0)
            return
        raise NotImplementedError


class TableValue(object):
    def __init__(self, columns, rows):
        self._columns = columns
        self._rows = rows

    def get_columns(self):
        return self._columns


class Table(BaseType):
    """
    Used to represent table valued parameter metadata

    spec: https://msdn.microsoft.com/en-us/library/dd304813.aspx
    """

    type = TVPTYPE

    def read(self, r):
        """ According to spec TDS does not support output TVP values """
        raise NotImplementedError

    def get_declaration(self):
        raise NotImplementedError

    @classmethod
    def from_stream(cls, r):
        """ According to spec TDS does not support output TVP values """
        raise NotImplementedError

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        raise NotImplementedError

    def __init__(self, typ_dbname, typ_schema, typ_name, columns):
        """
        @param typ_dbname: Database where TVP type defined
        @param typ_schema: Schema where TVP type defined
        @param typ_name: Name of TVP type
        @param columns: List of column types
        """
        if len(typ_dbname) > 128:
            raise ValueError("typ_dbname should not be longer that 128 characters")
        if len(typ_schema) > 128:
            raise ValueError("typ_schema should not be longer that 128 characters")
        if len(typ_name) > 128:
            raise ValueError("typ_name should not be longer that 128 characters")
        self._typ_dbname = typ_dbname
        self._typ_schema = typ_schema
        self._typ_name = typ_name
        self._columns = columns

    def write_info(self, w):
        """
        Writes TVP_TYPENAME structure

        spec: https://msdn.microsoft.com/en-us/library/dd302994.aspx
        @param w: TdsWriter
        @return:
        """
        w.write_b_varchar(self._typ_dbname)
        w.write_b_varchar(self._typ_schema)
        w.write_b_varchar(self._typ_name)

    def write(self, w, val):
        """
        Writes remaining part of TVP_TYPE_INFO structure, resuming from TVP_COLMETADATA

        specs:
        https://msdn.microsoft.com/en-us/library/dd302994.aspx
        https://msdn.microsoft.com/en-us/library/dd305261.aspx
        https://msdn.microsoft.com/en-us/library/dd303230.aspx

        @param w: TdsWriter
        @param val: TableValue or None
        @return:
        """
        if val is None:
            w.put_usmallint(TVP_NULL_TOKEN)
            return
        columns = val.get_columns()
        w.put_usmallint(len(columns))
        for column in columns:
            w.put_uint(column.column_usertype)

            w.put_byte(column.flags)

            # TYPE_INFO structure: https://msdn.microsoft.com/en-us/library/dd358284.aspx
            w.put_byte(column.type.type)
            column.type.write_info(w)

            w.write_b_varchar('')  # ColName, must be empty in TVP according to spec

        # here can optionally send TVP_ORDER_UNIQUE and TVP_COLUMN_ORDERING
        # https://msdn.microsoft.com/en-us/library/dd305261.aspx

        # terminating optional metadata
        w.put_byte(TVP_END_TOKEN)

        # now sending rows using TVP_ROW
        # https://msdn.microsoft.com/en-us/library/dd305261.aspx
        for row in val.get_rows():
            w.put_byte(TVP_ROW_TOKEN)
            for i, col in columns:
                if not col.flags & TVP_COLUMN_DEFAULT_FLAG:
                    col.type.write(w, row[i])

        # terminating rows
        w.put_byte(TVP_END_TOKEN)
