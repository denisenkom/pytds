import struct
import codecs
from contextlib import contextmanager
import logging
import socket
import sys
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from . import tz
import re
import uuid
import six
import types
from six.moves import xrange
try:
    import ssl
except:
    encryption_supported = False
else:
    encryption_supported = True
from .collate import ucs2_codec, Collation, lcid2charset, raw_collation
from .tds_base import *
from .tds_types import *

logger = logging.getLogger()

USE_CORK = hasattr(socket, 'TCP_CORK')

_header = struct.Struct('>BBHHBx')

_byte = struct.Struct('B')
_smallint_le = struct.Struct('<h')
_smallint_be = struct.Struct('>h')
_usmallint_le = struct.Struct('<H')
_usmallint_be = struct.Struct('>H')
_int_le = struct.Struct('<l')
_int_be = struct.Struct('>l')
_uint_le = struct.Struct('<L')
_uint_be = struct.Struct('>L')
_int8_le = struct.Struct('<q')
_int8_be = struct.Struct('>q')
_uint8_le = struct.Struct('<Q')
_uint8_be = struct.Struct('>Q')


class SimpleLoadBalancer(object):
    def __init__(self, hosts):
        self._hosts = hosts

    def choose(self):
        for host in self._hosts:
            yield host


# stored procedure output parameter
class output(object):
    @property
    def type(self):
        """
        This is either the sql type declaration or python type instance
        of the parameter.
        """
        return self._type

    @property
    def value(self):
        """
        This is the value of the parameter.
        """
        return self._value

    def __init__(self, value=None, param_type=None):
        """ Creates procedure output parameter.

        :param param_type: either sql type declaration or python type
        :param value: value to pass into procedure
        """
        if param_type is None:
            if value is None or value is default:
                raise ValueError('Output type cannot be autodetected')
        elif isinstance(param_type, type) and value is not None:
            if value is not default and not isinstance(value, param_type):
                raise ValueError('value should match param_type', value, param_type)
        self._type = param_type
        self._value = value


class _Default(object):
    pass

default = _Default()


def tds7_crypt_pass(password):
    """ Mangle password according to tds rules

    :param password: Password str
    :returns: Byte-string with encoded password
    """
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4) & 0xff | (ch >> 4)) ^ 0xA5
    return encoded


class _TdsEnv:
    pass


class _TdsReader(object):
    """ TDS stream reader

    Provides stream-like interface for TDS packeted stream.
    Also provides convinience methods to decode primitive data like
    different kinds of integers etc.
    """
    def __init__(self, session):
        self._buf = ''
        self._pos = 0  # position in the buffer
        self._have = 0  # number of bytes read from packet
        self._size = 0  # size of current packet
        self._session = session
        self._transport = session._transport
        self._type = None
        self._status = None

    @property
    def session(self):
        """ Link to :class:`_TdsSession` object
        """
        return self._session

    @property
    def packet_type(self):
        """ Type of current packet

        Possible values are TDS_QUERY, TDS_LOGIN, etc.
        """
        return self._type

    def read_fast(self, size):
        """ Faster version of read

        Instead of returning sliced buffer it returns reference to internal
        buffer and the offset to this buffer.

        :param size: Number of bytes to read
        :returns: Tuple of bytes buffer, and offset in this buffer
        """
        if self._pos >= len(self._buf):
            if self._have >= self._size:
                self._read_packet()
            else:
                self._buf = self._transport.read(self._size - self._have)
                self._pos = 0
                self._have += len(self._buf)
        offset = self._pos
        self._pos += size
        return self._buf, offset

    def unpack(self, struct):
        """ Unpacks given structure from stream

        :param struct: A struct.Struct instance
        :returns: Result of unpacking
        """
        buf, offset = readall_fast(self, struct.size)
        return struct.unpack_from(buf, offset)

    def get_byte(self):
        """ Reads one byte from stream """
        return self.unpack(_byte)[0]

    def get_smallint(self):
        """ Reads 16bit signed integer from the stream """
        return self.unpack(_smallint_le)[0]

    def get_usmallint(self):
        """ Reads 16bit unsigned integer from the stream """
        return self.unpack(_usmallint_le)[0]

    def get_int(self):
        """ Reads 32bit signed integer from the stream """
        return self.unpack(_int_le)[0]

    def get_uint(self):
        """ Reads 32bit unsigned integer from the stream """
        return self.unpack(_uint_le)[0]

    def get_uint_be(self):
        """ Reads 32bit unsigned big-endian integer from the stream """
        return self.unpack(_uint_be)[0]

    def get_uint8(self):
        """ Reads 64bit unsigned integer from the stream """
        return self.unpack(_uint8_le)[0]

    def get_int8(self):
        """ Reads 64bit signed integer from the stream """
        return self.unpack(_int8_le)[0]

    def read_ucs2(self, num_chars):
        """ Reads num_chars UCS2 string from the stream """
        buf = readall(self, num_chars * 2)
        return ucs2_codec.decode(buf)[0]

    def read_str(self, size, codec):
        """ Reads byte string from the stream and decodes it

        :param size: Size of string in bytes
        :param codec: Instance of codec to decode string
        :returns: Unicode string
        """
        return codec.decode(readall(self, size))[0]

    def get_collation(self):
        """ Reads :class:`Collation` object from stream """
        buf = readall(self, Collation.wire_size)
        return Collation.unpack(buf)

    def unget_byte(self):
        """ Returns one last read byte to stream

        Can only be called once per read byte.
        """
        # this is a one trick pony...don't call it twice
        assert self._pos > 0
        self._pos -= 1

    def peek(self):
        """ Returns next byte from stream without consuming it
        """
        res = self.get_byte()
        self.unget_byte()
        return res

    def read(self, size):
        """ Reads size bytes from buffer

        May return fewer bytes than requested
        :param size: Number of bytes to read
        :returns: Bytes buffer, possibly shorter than requested,
                  returns empty buffer in case of EOF
        """
        buf, offset = self.read_fast(size)
        return buf[offset:offset + size]

    def _read_packet(self):
        """ Reads next TDS packet from the underlying transport

        If timeout is happened during reading of packet's header will
        cancel current request.
        Can only be called when transport's read pointer is at the begining
        of the packet.
        """
        try:
            header = readall(self._transport, _header.size)
        except TimeoutError:
            self._session._put_cancel()
            raise
        self._pos = 0
        self._type, self._status, self._size, self._session._spid, _ = _header.unpack(header)
        self._have = _header.size
        assert self._size > self._have, 'Empty packet doesn make any sense'
        self._buf = self._transport.read(self._size - self._have)
        self._have += len(self._buf)

    def read_whole_packet(self):
        """ Reads single packet and returns bytes payload of the packet

        Can only be called when transport's read pointer is at the beginning
        of the packet.
        """
        self._read_packet()
        return readall(self, self._size - _header.size)


class _TdsWriter(object):
    """ TDS stream writer

    Handles splitting of incoming data into TDS packets according to TDS protocol.
    Provides convinience methods for writing primitive data types.
    """
    def __init__(self, session, bufsize):
        self._session = session
        self._tds = session
        self._transport = session
        self._pos = 0
        self._buf = bytearray(bufsize)
        self._packet_no = 0

    @property
    def session(self):
        """ Back reference to parent :class:`_TdsSession` object """
        return self._session

    @property
    def bufsize(self):
        """ Size of the buffer """
        return len(self._buf)

    @bufsize.setter
    def bufsize(self, bufsize):
        if len(self._buf) == bufsize:
            return

        if bufsize > len(self._buf):
            self._buf.extend(b'\0' * (bufsize - len(self._buf)))
        else:
            self._buf = self._buf[0:bufsize]

    def begin_packet(self, packet_type):
        """ Starts new packet stream

        :param packet_type: Type of TDS stream, e.g. TDS_PRELOGIN, TDS_QUERY etc.
        """
        self._type = packet_type
        self._pos = 8

    def pack(self, struct, *args):
        """ Packs and writes structure into stream """
        self.write(struct.pack(*args))

    def put_byte(self, value):
        """ Writes single byte into stream """
        self.pack(_byte, value)

    def put_smallint(self, value):
        """ Writes 16-bit signed integer into the stream """
        self.pack(_smallint_le, value)

    def put_usmallint(self, value):
        """ Writes 16-bit unsigned integer into the stream """
        self.pack(_usmallint_le, value)

    def put_smallint_be(self, value):
        """ Writes 16-bit signed big-endian integer into the stream """
        self.pack(_smallint_be, value)

    def put_usmallint_be(self, value):
        """ Writes 16-bit unsigned big-endian integer into the stream """
        self.pack(_usmallint_be, value)

    def put_int(self, value):
        """ Writes 32-bit signed integer into the stream """
        self.pack(_int_le, value)

    def put_uint(self, value):
        """ Writes 32-bit unsigned integer into the stream """
        self.pack(_uint_le, value)

    def put_int_be(self, value):
        """ Writes 32-bit signed big-endian integer into the stream """
        self.pack(_int_be, value)

    def put_uint_be(self, value):
        """ Writes 32-bit unsigned big-endian integer into the stream """
        self.pack(_uint_be, value)

    def put_int8(self, value):
        """ Writes 64-bit signed integer into the stream """
        self.pack(_int8_le, value)

    def put_uint8(self, value):
        """ Writes 64-bit unsigned integer into the stream """
        self.pack(_uint8_le, value)

    def put_collation(self, collation):
        """ Writes :class:`Collation` structure into the stream """
        self.write(collation.pack())

    def write(self, data):
        """ Writes given bytes buffer into the stream

        Function returns only when entire buffer is written
        """
        data_off = 0
        while data_off < len(data):
            left = len(self._buf) - self._pos
            if left <= 0:
                self._write_packet(final=False)
            else:
                to_write = min(left, len(data) - data_off)
                self._buf[self._pos:self._pos + to_write] = data[data_off:data_off + to_write]
                self._pos += to_write
                data_off += to_write

    def write_b_varchar(self, s):
        self.put_byte(len(s))
        self.write_ucs2(s)

    def write_ucs2(self, s):
        """ Write string encoding it in UCS2 into stream """
        self.write_string(s, ucs2_codec)

    def write_string(self, s, codec):
        """ Write string encoding it with codec into stream """
        for i in xrange(0, len(s), self.bufsize):
            chunk = s[i:i + self.bufsize]
            buf, consumed = codec.encode(chunk)
            assert consumed == len(chunk)
            self.write(buf)

    def flush(self):
        """ Closes current packet stream """
        return self._write_packet(final=True)

    def _write_packet(self, final):
        """ Writes single TDS packet into underlying transport.

        Data for the packet is taken from internal buffer.

        :param final: True means this is the final packet in substream.
        """
        status = 1 if final else 0
        _header.pack_into(self._buf, 0, self._type, status, self._pos, 0, self._packet_no)
        self._packet_no = (self._packet_no + 1) % 256
        self._transport.send(self._buf[:self._pos], final)
        self._pos = 8


class MemoryChunkedHandler(object):
    def begin(self, column, size):
        self.size = size
        self._chunks = []

    def new_chunk(self, val):
        #logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self._chunks.append(val)

    def end(self):
        return b''.join(self._chunks)


class MemoryStrChunkedHandler(object):
    def begin(self, column, size):
        self.size = size
        self._chunks = []

    def new_chunk(self, val):
        #logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self._chunks.append(val)

    def end(self):
        return ''.join(self._chunks)


def _create_exception_by_message(msg, custom_error_msg = None):
    msg_no = msg['msgno']
    if custom_error_msg is not None:
        error_msg = custom_error_msg
    else:
        error_msg = msg['message']
    if msg_no in prog_errors:
        ex = ProgrammingError(error_msg)
    elif msg_no in integrity_errors:
        ex = IntegrityError(error_msg)
    else:
        ex = OperationalError(error_msg)
    ex.msg_no = msg['msgno']
    ex.text = msg['message']
    ex.srvname = msg['server']
    ex.procname = msg['proc_name']
    ex.number = msg['msgno']
    ex.severity = msg['severity']
    ex.state = msg['state']
    ex.line = msg['line_number']
    return ex


class _TdsSession(object):
    """ TDS session

    Represents a single TDS session within MARS connection, when MARS enabled there could be multiple TDS sessions
    within one connection.
    """
    def __init__(self, tds, transport, tzinfo_factory):
        self.out_pos = 8
        self.res_info = None
        self.in_cancel = False
        self.wire_mtx = None
        self.param_info = None
        self.has_status = False
        self.ret_status = None
        self.skipped_to_status = False
        self._transport = transport
        self._reader = _TdsReader(self)
        self._reader._transport = transport
        self._writer = _TdsWriter(self, tds._bufsize)
        self._writer._transport = transport
        self.in_buf_max = 0
        self.state = TDS_IDLE
        self._tds = tds
        self.messages = []
        self.chunk_handler = tds.chunk_handler
        self.rows_affected = -1
        self.use_tz = tds.use_tz
        self._spid = 0
        self.tzinfo_factory = tzinfo_factory

    def __repr__(self):
        fmt = "<_TdsSession state={} tds={} messages={} rows_affected={} use_tz={} spid={} in_cancel={}>"
        res = fmt.format(repr(self.state), repr(self._tds), repr(self.messages),
                         repr(self.rows_affected), repr(self.use_tz), repr(self._spid),
                         self.in_cancel)
        return res

    def raise_db_exception(self):
        """ Raises exception from last server message

        This function will skip messages: The statement has been terminated
        """
        if not self.messages:
            raise Error("Request failed, server didn't send error message")
        while True:
            msg = self.messages[-1]
            if msg['msgno'] == 3621:  # the statement has been terminated
                self.messages = self.messages[:-1]
            else:
                break

        error_msg = ' '.join(msg['message'] for msg in self.messages)
        ex = _create_exception_by_message(msg, error_msg)
        raise ex

    def get_type_info(self, curcol):
        """ Reads TYPE_INFO structure (http://msdn.microsoft.com/en-us/library/dd358284.aspx)

        :param curcol: An instance of :class:`Column` that will receive read information
        """
        r = self._reader
        # User defined data type of the column
        curcol.column_usertype = r.get_uint() if IS_TDS72_PLUS(self) else r.get_usmallint()
        curcol.flags = r.get_usmallint()  # Flags
        curcol.column_nullable = curcol.flags & Column.fNullable
        curcol.column_writeable = (curcol.flags & Column.fReadWrite) > 0
        curcol.column_identity = (curcol.flags & Column.fIdentity) > 0
        type_id = r.get_byte()
        type_class = self._tds._type_factory.get_type_class(type_id)
        curcol.type = type_class.from_stream(r)

    def tds7_process_result(self):
        """ Reads and processes COLMETADATA stream

        This stream contains a list of returned columns.
        Stream format link: http://msdn.microsoft.com/en-us/library/dd357363.aspx
        """
        r = self._reader
        #logger.debug("processing TDS7 result metadata.")

        # read number of columns and allocate the columns structure

        num_cols = r.get_smallint()

        # This can be a DUMMY results token from a cursor fetch

        if num_cols == -1:
            #logger.debug("no meta data")
            return

        self.param_info = None
        self.has_status = False
        self.ret_status = None
        self.skipped_to_status = False
        self.rows_affected = TDS_NO_COUNT
        self.more_rows = True
        self.row = [None] * num_cols
        self.res_info = info = _Results()

        #
        # loop through the columns populating COLINFO struct from
        # server response
        #
        #logger.debug("setting up {0} columns".format(num_cols))
        header_tuple = []
        for col in range(num_cols):
            curcol = Column()
            info.columns.append(curcol)
            self.get_type_info(curcol)

            #
            # under 7.0 lengths are number of characters not
            # number of bytes... read_ucs2 handles this
            #
            curcol.column_name = r.read_ucs2(r.get_byte())
            precision = curcol.type.precision if hasattr(curcol.type, 'precision') else None
            scale = curcol.type.scale if hasattr(curcol.type, 'scale') else None
            size = curcol.type._size if hasattr(curcol.type, '_size') else None
            header_tuple.append((curcol.column_name, curcol.type.get_typeid(), None, size, precision, scale, curcol.column_nullable))
        info.description = tuple(header_tuple)
        return info

    def process_param(self):
        """ Reads and processes RETURNVALUE stream.

        This stream is used to send OUTPUT parameters from RPC to client.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303881.aspx
        """
        r = self._reader
        if IS_TDS72_PLUS(self):
            ordinal = r.get_usmallint()
        else:
            r.get_usmallint()  # ignore size
            ordinal = self._out_params_indexes[self.return_value_index]
        name = r.read_ucs2(r.get_byte())
        r.get_byte()  # 1 - OUTPUT of sp, 2 - result of udf
        param = Column()
        param.column_name = name
        self.get_type_info(param)
        param.value = param.type.read(r)
        self.output_params[ordinal] = param
        self.return_value_index += 1

    def process_cancel(self):
        """
        Process the incoming token stream until it finds
        an end token DONE with the cancel flag set.
        At that point the connection should be ready to handle a new query.

        In case when no cancel request is pending this function does nothing.
        """
        # silly cases, nothing to do
        if not self.in_cancel:
            return

        while True:
            token_id = self.get_token_id()
            self.process_token(token_id)
            if not self.in_cancel:
                return

    def process_msg(self, marker):
        """ Reads and processes ERROR/INFO streams

        Stream formats:

        - ERROR: http://msdn.microsoft.com/en-us/library/dd304156.aspx
        - INFO: http://msdn.microsoft.com/en-us/library/dd303398.aspx

        :param marker: TDS_ERROR_TOKEN or TDS_INFO_TOKEN
        """
        r = self._reader
        r.get_smallint()  # size
        msg = {}
        msg['marker'] = marker
        msg['msgno'] = r.get_int()
        msg['state'] = r.get_byte()
        msg['severity'] = r.get_byte()
        msg['sql_state'] = None
        has_eed = False
        if marker == TDS_EED_TOKEN:
            if msg['severity'] <= 10:
                msg['priv_msg_type'] = 0
            else:
                msg['priv_msg_type'] = 1
            len_sqlstate = r.get_byte()
            msg['sql_state'] = readall(r, len_sqlstate)
            has_eed = r.get_byte()
            # junk status and transaction state
            r.get_smallint()
        elif marker == TDS_INFO_TOKEN:
            msg['priv_msg_type'] = 0
        elif marker == TDS_ERROR_TOKEN:
            msg['priv_msg_type'] = 1
        else:
            logger.error('tds_process_msg() called with unknown marker "{0}"'.format(marker))
        #logger.debug('tds_process_msg() reading message {0} from server'.format(msg['msgno']))
        msg['message'] = r.read_ucs2(r.get_smallint())
        # server name
        msg['server'] = r.read_ucs2(r.get_byte())
        # stored proc name if available
        msg['proc_name'] = r.read_ucs2(r.get_byte())
        msg['line_number'] = r.get_int() if IS_TDS72_PLUS(self) else r.get_smallint()
        if not msg['sql_state']:
            #msg['sql_state'] = tds_alloc_lookup_sqlstate(self, msg['msgno'])
            pass
        # in case extended error data is sent, we just try to discard it
        if has_eed:
            while True:
                next_marker = r.get_byte()
                if next_marker in (TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN, TDS5_PARAMS_TOKEN):
                    self.process_token(next_marker)
                else:
                    break
            r.unget_byte()

        # special case
        self.messages.append(msg)

    def process_row(self):
        """ Reads and handles ROW stream.

        This stream contains list of values of one returned row.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd357254.aspx
        """
        r = self._reader
        info = self.res_info
        info.row_count += 1
        for i, curcol in enumerate(info.columns):
            curcol.value = self.row[i] = curcol.type.read(r)

    def process_nbcrow(self):
        """ Reads and handles NBCROW stream.

        This stream contains list of values of one returned row in a compressed way,
        introduced in TDS 7.3.B
        Stream format url: http://msdn.microsoft.com/en-us/library/dd304783.aspx
        """
        r = self._reader
        info = self.res_info
        if not info:
            self.bad_stream('got row without info')
        assert len(info.columns) > 0
        info.row_count += 1

        # reading bitarray for nulls, 1 represent null values for
        # corresponding fields
        nbc = readall(r, (len(info.columns) + 7) // 8)
        for i, curcol in enumerate(info.columns):
            if ord(nbc[i // 8]) & (1 << (i % 8)):
                value = None
            else:
                value = curcol.type.read(r)
            self.row[i] = value

    def process_tabname(self):
        r = self._reader
        total_length = r.get_smallint()
        if not IS_TDS71_PLUS(self):
            name_length = r.get_smallint()
        skipall(r, total_length)

    def process_colinfo(self):
        r = self._reader
        total_length = r.get_smallint()
        skipall(r, total_length)

    def process_orderby(self):
        """ Reads and processes ORDER stream

        Used to inform client by which column dataset is ordered.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303317.aspx
        """
        r = self._reader
        skipall(r, r.get_smallint())

    def process_orderby2(self):
        r = self._reader
        skipall(r, r.get_int())

    def process_end(self, marker):
        """ Reads and processes DONE/DONEINPROC/DONEPROC streams

        Stream format urls:

        - DONE: http://msdn.microsoft.com/en-us/library/dd340421.aspx
        - DONEINPROC: http://msdn.microsoft.com/en-us/library/dd340553.aspx
        - DONEPROC: http://msdn.microsoft.com/en-us/library/dd340753.aspx

        :param marker: Can be TDS_DONE_TOKEN or TDS_DONEINPROC_TOKEN or TDS_DONEPROC_TOKEN
        """
        self.more_rows = False
        r = self._reader
        status = r.get_usmallint()
        r.get_usmallint()  # cur_cmd
        more_results = status & TDS_DONE_MORE_RESULTS != 0
        was_cancelled = status & TDS_DONE_CANCELLED != 0
        #error = status & TDS_DONE_ERROR != 0
        done_count_valid = status & TDS_DONE_COUNT != 0
        #logger.debug(
        #    'process_end: more_results = {0}\n'
        #    '\t\twas_cancelled = {1}\n'
        #    '\t\terror = {2}\n'
        #    '\t\tdone_count_valid = {3}'.format(more_results, was_cancelled, error, done_count_valid))
        if self.res_info:
            self.res_info.more_results = more_results
        rows_affected = r.get_int8() if IS_TDS72_PLUS(self) else r.get_int()
        #logger.debug('\t\trows_affected = {0}'.format(rows_affected))
        if was_cancelled or (not more_results and not self.in_cancel):
            #logger.debug('process_end() state set to TDS_IDLE')
            self.in_cancel = False
            self.set_state(TDS_IDLE)
        if done_count_valid:
            self.rows_affected = rows_affected
        else:
            self.rows_affected = -1
        self.done_flags = status
        if self.done_flags & TDS_DONE_ERROR and not was_cancelled and not self.in_cancel:
            self.raise_db_exception()

    def process_env_chg(self):
        """ Reads and processes ENVCHANGE stream.

        Stream info url: http://msdn.microsoft.com/en-us/library/dd303449.aspx
        """
        r = self._reader
        size = r.get_smallint()
        type = r.get_byte()
        #logger.debug("process_env_chg: type: {0}".format(type))
        if type == TDS_ENV_SQLCOLLATION:
            size = r.get_byte()
            #logger.debug("process_env_chg(): {0} bytes of collation data received".format(size))
            #logger.debug("self.collation was {0}".format(self.conn.collation))
            self.conn.collation = r.get_collation()
            skipall(r, size - 5)
            #tds7_srv_charset_changed(tds, tds.conn.collation)
            #logger.debug("self.collation now {0}".format(self.conn.collation))
            # discard old one
            skipall(r, r.get_byte())
        elif type == TDS_ENV_BEGINTRANS:
            size = r.get_byte()
            # TODO: parse transaction
            self.conn.tds72_transaction = r.get_uint8()
            skipall(r, r.get_byte())
        elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
            self.conn.tds72_transaction = 0
            skipall(r, r.get_byte())
            skipall(r, r.get_byte())
        elif type == TDS_ENV_PACKSIZE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            new_block_size = int(newval)
            if new_block_size >= 512:
                #logger.info("changing block size from {0} to {1}".format(oldval, new_block_size))
                #
                # Is possible to have a shrink if server limits packet
                # size more than what we specified
                #
                # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
                self._writer.bufsize = new_block_size
        elif type == TDS_ENV_DATABASE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.database = newval
        elif type == TDS_ENV_LANG:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.language = newval
        elif type == TDS_ENV_CHARSET:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            #logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
            self.conn.env.charset = newval
            remap = {'iso_1': 'iso8859-1'}
            self.conn.server_codec = codecs.lookup(remap.get(newval, newval))
            #tds_srv_charset_changed(self, newval)
        elif type == TDS_ENV_DB_MIRRORING_PARTNER:
            r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
        elif type == TDS_ENV_LCID:
            lcid = int(r.read_ucs2(r.get_byte()))
            self.conn.server_codec = codecs.lookup(lcid2charset(lcid))
            r.read_ucs2(r.get_byte())
        else:
            logger.warning("unknown env type: {0}, skipping".format(type))
            # discard byte values, not still supported
            skipall(r, size - 1)

    def process_auth(self):
        """ Reads and processes SSPI stream.

        Stream info: http://msdn.microsoft.com/en-us/library/dd302844.aspx
        """
        r = self._reader
        w = self._writer
        pdu_size = r.get_smallint()
        if not self.authentication:
            raise Error('Got unexpected token')
        packet = self.authentication.handle_next(readall(r, pdu_size))
        if packet:
            w.write(packet)
            w.flush()

    def is_connected(self):
        """
        :return: True if transport is connected
        """
        return self._transport.is_connected()

    def bad_stream(self, msg):
        """ Called when input stream contains unexpected data.

        Will close stream and raise :class:`InterfaceError`
        :param msg: Message for InterfaceError exception.
        :return: Never returns, always raises exception.
        """
        self.close()
        raise InterfaceError(msg)

    @property
    def tds_version(self):
        """ Returns integer encoded current TDS protocol version
        """
        return self._tds.tds_version

    @property
    def conn(self):
        """ Reference to owning :class:`_TdsSocket`
        """
        return self._tds

    def close(self):
        self._transport.close()

    def set_state(self, state):
        """ Switches state of the TDS session.

        It also does state transitions checks.
        :param state: New state, one of TDS_PENDING/TDS_READING/TDS_IDLE/TDS_DEAD/TDS_QUERING
        """
        prior_state = self.state
        if state == prior_state:
            return state
        if state == TDS_PENDING:
            if prior_state in (TDS_READING, TDS_QUERYING):
                self.state = TDS_PENDING
            else:
                raise InterfaceError('logic error: cannot chage query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
        elif state == TDS_READING:
            # transition to READING are valid only from PENDING
            if self.state != TDS_PENDING:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            else:
                self.state = state
        elif state == TDS_IDLE:
            if prior_state == TDS_DEAD:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            self.state = state
        elif state == TDS_DEAD:
            self.state = state
        elif state == TDS_QUERYING:
            if self.state == TDS_DEAD:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            elif self.state != TDS_IDLE:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            else:
                self.rows_affected = TDS_NO_COUNT
                self.internal_sp_called = 0
                self.state = state
        else:
            assert False
        return self.state

    @contextmanager
    def querying_context(self, packet_type):
        """ Context manager for querying.

        Sets state to TDS_QUERYING, and reverts it to TDS_IDLE if exception happens inside managed block,
        and to TDS_PENDING if managed block succeeds and flushes buffer.
        """
        if self.set_state(TDS_QUERYING) != TDS_QUERYING:
            raise Error("Couldn't switch to state")
        self._writer.begin_packet(packet_type)
        try:
            yield
        except:
            if self.state != TDS_DEAD:
                self.set_state(TDS_IDLE)
            raise
        else:
            self.set_state(TDS_PENDING)
            self._writer.flush()


    def make_param(self, name, value):
        """ Generates instance of :class:`Column` from value and name

        Value can also be of a special types:

        - An instance of :class:`Column`, in which case it is just returned.
        - An instance of :class:`output`, in which case parameter will become
          an output parameter.
        - A singleton :var:`default`, in which case default value will be passed
          into a stored proc.

        :param name: Name of the parameter, will populate column_name property of returned column.
        :param value: Value of the parameter, also used to guess the type of parameter.
        :return: An instance of :class:`Column`
        """
        if isinstance(value, Column):
            value.column_name = name
            return value
        column = Column()
        column.column_name = name
        column.flags = 0
        
        if isinstance(value, output):
            column.flags |= fByRefValue
            if isinstance(value.type, six.string_types):
                column.type = self.conn._type_factory.type_by_declaration(declaration=value.type, nullable=True, connection=self._tds)
            elif value.type:
                column.type = self.conn._type_inferrer.from_class(value.type)
            value = value.value

        if value is default:
            column.flags |= fDefaultValue
            value = None

        column.value = value
        if column.type is None:
            column.type = self.conn._type_inferrer.from_value(value)
        return column

    def _convert_params(self, parameters):
        """ Converts a dict of list of parameters into a list of :class:`Column` instances.

        :param parameters: Can be a list of parameter values, or a dict of parameter names to values.
        :return: A list of :class:`Column` instances.
        """
        if isinstance(parameters, dict):
            return [self.make_param(name, value)
                    for name, value in parameters.items()]
        else:
            params = []
            for parameter in parameters:
                params.append(self.make_param('', parameter))
            return params

    def cancel_if_pending(self):
        """ Cancels current pending request.

        Does nothing if no request is pending, otherwise sends cancel request,
        and waits for response.
        """
        if self.state == TDS_IDLE:
            return
        if not self.in_cancel:
            self._put_cancel()
        self.process_cancel()

    def submit_rpc(self, rpc_name, params, flags):
        """ Sends an RPC request.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd357576.aspx

        :param rpc_name: Name of the RPC to call, can be an instance of :class:`InternalProc`
        :param params: Stored proc parameters, should be a list of :class:`Column` instances.
        :param flags: See spec for possible flags.
        """
        self.messages = []
        self.output_params = {}
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.querying_context(TDS_RPC):
            self._START_QUERY()
            if IS_TDS71_PLUS(self) and isinstance(rpc_name, InternalProc):
                w.put_smallint(-1)
                w.put_smallint(rpc_name.proc_id)
            else:
                if isinstance(rpc_name, InternalProc):
                    rpc_name = rpc_name.name
                w.put_smallint(len(rpc_name))
                w.write_ucs2(rpc_name)
            #
            # TODO support flags
            # bit 0 (1 as flag) in TDS7/TDS5 is "recompile"
            # bit 1 (2 as flag) in TDS7+ is "no metadata" bit this will prevent sending of column infos
            #
            w.put_usmallint(flags)
            self._out_params_indexes = []
            for i, param in enumerate(params):
                if param.flags & fByRefValue:
                    self._out_params_indexes.append(i)
                w.put_byte(len(param.column_name))
                w.write_ucs2(param.column_name)
                #
                # TODO support other flags (use defaul null/no metadata)
                # bit 1 (2 as flag) in TDS7+ is "default value" bit
                # (what's the meaning of "default value" ?)
                #
                w.put_byte(param.flags)

                # TYPE_INFO structure: https://msdn.microsoft.com/en-us/library/dd358284.aspx
                w.put_byte(param.type.type)
                param.type.write_info(w)

                param.type.write(w, param.value)

    def submit_plain_query(self, operation):
        """ Sends a plain query to server.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd358575.aspx

        :param operation: A string representing sql statement.
        """
        #logger.debug('submit_plain_query(%s)', operation)
        self.messages = []
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.querying_context(TDS_QUERY):
            self._START_QUERY()
            w.write_ucs2(operation)

    def submit_bulk(self, metadata, rows):
        """ Sends insert bulk command.

        Spec: http://msdn.microsoft.com/en-us/library/dd358082.aspx

        :param metadata: A list of :class:`Column` instances.
        :param rows: A collection of rows, each row is a collection of values.
        :return:
        """
        num_cols = len(metadata)
        w = self._writer
        with self.querying_context(TDS_BULK):
            w.put_byte(TDS7_RESULT_TOKEN)
            w.put_usmallint(num_cols)
            for col in metadata:
                if IS_TDS72_PLUS(self):
                    w.put_uint(col.column_usertype)
                else:
                    w.put_usmallint(col.column_usertype)
                w.put_usmallint(col.flags)
                w.put_byte(col.type.type)
                col.type.write_info(w)
                w.put_byte(len(col.column_name))
                w.write_ucs2(col.column_name)
            for row in rows:
                w.put_byte(TDS_ROW_TOKEN)
                for i, col in enumerate(metadata):
                    col.type.write(w, row[i])

            w.put_byte(TDS_DONE_TOKEN)
            w.put_usmallint(TDS_DONE_FINAL)
            w.put_usmallint(0)  # curcmd
            if IS_TDS72_PLUS(self):
                w.put_int8(0)
            else:
                w.put_int(0)

    def _put_cancel(self):
        """ Sends a cancel request to the server.

        Switches connection to IN_CANCEL state.
        """
        self._writer.begin_packet(TDS_CANCEL)
        self._writer.flush()
        self.in_cancel = 1

    _begin_tran_struct_72 = struct.Struct('<HBB')

    def begin_tran(self, isolation_level=0):
        self.submit_begin_tran(isolation_level=isolation_level)
        self.process_simple_request()

    def submit_begin_tran(self, isolation_level=0):
        #logger.debug('submit_begin_tran()')
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
                self._start_query()
                w.pack(self._begin_tran_struct_72,
                    5,  # TM_BEGIN_XACT
                    isolation_level,
                    0,  # new transaction name
                    )
        else:
            self.submit_plain_query("BEGIN TRANSACTION")
            self.conn.tds72_transaction = 1

    _commit_rollback_tran_struct72_hdr = struct.Struct('<HBB')
    _continue_tran_struct72 = struct.Struct('<BB')

    def rollback(self, cont, isolation_level=0):
        self.submit_rollback(cont, isolation_level=isolation_level)
        prev_timeout = self._tds._sock.gettimeout()
        self._tds._sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds._sock.settimeout(prev_timeout)

    def submit_rollback(self, cont, isolation_level=0):
        #logger.debug('submit_rollback(%s, %s)', id(self), cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
                self._start_query()
                flags = 0
                if cont:
                    flags |= 1
                w.pack(self._commit_rollback_tran_struct72_hdr,
                    8,  # TM_ROLLBACK_XACT
                    0,  # transaction name
                    flags,
                    )
                if cont:
                    w.pack(self._continue_tran_struct72,
                        isolation_level,
                        0,  # new transaction name
                        )
        else:
            self.submit_plain_query("IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")
            self.conn.tds72_transaction = 1 if cont else 0

    def commit(self, cont, isolation_level=0):
        self.submit_commit(cont, isolation_level=isolation_level)
        prev_timeout = self._tds._sock.gettimeout()
        self._tds._sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds._sock.settimeout(prev_timeout)

    def submit_commit(self, cont, isolation_level=0):
        #logger.debug('submit_commit(%s)', cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
                self._start_query()
                flags = 0
                if cont:
                    flags |= 1
                w.pack(self._commit_rollback_tran_struct72_hdr,
                    7,  # TM_COMMIT_XACT
                    0,  # transaction name
                    flags,
                    )
                if cont:
                    w.pack(self._continue_tran_struct72,
                        isolation_level,
                        0,  # new transaction name
                        )
        else:
            self.submit_plain_query("IF @@TRANCOUNT > 0 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")
            self.conn.tds72_transaction = 1 if cont else 0

    def _START_QUERY(self):
        if IS_TDS72_PLUS(self):
            self._start_query()

    _tds72_query_start = struct.Struct('<IIHQI')

    def _start_query(self):
        w = self._writer
        w.pack(_TdsSession._tds72_query_start,
               0x16,  # total length
               0x12,  # length
               2,  # type
               self.conn.tds72_transaction,
               1,  # request count
               )

    VERSION = 0
    ENCRYPTION = 1
    INSTOPT = 2
    THREADID = 3
    MARS = 4
    TRACEID = 5
    TERMINATOR = 0xff

    def _send_prelogin(self, login):
        instance_name = login.instance_name or 'MSSQLServer'
        instance_name = instance_name.encode('ascii')
        encryption_level = login.encryption_level
        if len(instance_name) > 65490:
            raise ValueError('Instance name is too long')
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise NotSupportedError('Client requested encryption but it is not supported')
        if IS_TDS72_PLUS(self):
            START_POS = 26
            buf = struct.pack(
                b'>BHHBHHBHHBHHBHHB',
                #netlib version
                self.VERSION, START_POS, 6,
                #encryption
                self.ENCRYPTION, START_POS + 6, 1,
                #instance
                self.INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
                # thread id
                self.THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
                # MARS enabled
                self.MARS, START_POS + 6 + 1 + len(instance_name) + 1 + 4, 1,
                # end
                self.TERMINATOR
                )
        else:
            START_POS = 21
            buf = struct.pack(
                b'>BHHBHHBHHBHHB',
                #netlib version
                self.VERSION, START_POS, 6,
                #encryption
                self.ENCRYPTION, START_POS + 6, 1,
                #instance
                self.INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
                # thread id
                self.THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
                # end
                self.TERMINATOR
                )
        assert START_POS == len(buf)
        w = self._writer
        w.begin_packet(TDS71_PRELOGIN)
        w.write(buf)
        from . import intversion
        w.put_uint_be(intversion)
        w.put_usmallint_be(0)  # build number
        # encryption
        if ENCRYPTION_ENABLED and encryption_supported:
            w.put_byte(1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
        else:
            # not supported
            w.put_byte(2)
        w.write(instance_name)
        w.put_byte(0)  # zero terminate instance_name
        w.put_int(0)  # TODO: change this to thread id
        if IS_TDS72_PLUS(self):
            # MARS (1 enabled)
            w.put_byte(1 if login.use_mars else 0)
        w.flush()

    def _process_prelogin(self, login):
        p = self._reader.read_whole_packet()
        size = len(p)
        if size <= 0 or self._reader.packet_type != 4:
            self.bad_stream('Invalid packet type: {0}, expected PRELOGIN(4)'.format(self._reader.packet_type))
        # default 2, no certificate, no encryptption
        crypt_flag = 2
        i = 0
        byte_struct = struct.Struct('B')
        off_len_struct = struct.Struct('>HH')
        prod_version_struct = struct.Struct('>LH')
        while True:
            if i >= size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            type, = byte_struct.unpack_from(p, i)
            if type == 0xff:
                break
            if i + 4 > size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            off, l = off_len_struct.unpack_from(p, i + 1)
            if off > size or off + l > size:
                self.bad_stream('Invalid offset in PRELOGIN structure')
            if type == self.VERSION:
                self.conn.server_library_version = prod_version_struct.unpack_from(p, off)
            elif type == self.ENCRYPTION and l >= 1:
                crypt_flag, = byte_struct.unpack_from(p, off)
            elif type == self.MARS:
                self.conn._mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
            elif type == self.INSTOPT:
                # ignore instance name mismatch
                pass
            i += 5
        # if server do not has certificate do normal login
        if crypt_flag == 2:
            if login.encryption_level >= TDS_ENCRYPTION_REQUIRE:
                raise Error('Server required encryption but it is not supported')
            return
        self._sock = ssl.wrap_socket(self._sock, ssl_version=ssl.PROTOCOL_SSLv3)

    def tds7_send_login(self, login):
        option_flag2 = login.option_flag2
        user_name = login.user_name
        if len(user_name) > 128:
            raise ValueError('User name should be no longer that 128 characters')
        if len(login.password) > 128:
            raise ValueError('Password should be not longer than 128 characters')
        if len(login.change_password) > 128:
            raise ValueError('Password should be not longer than 128 characters')
        if len(login.client_host_name) > 128:
            raise ValueError('Host name should be not longer than 128 characters')
        if len(login.app_name) > 128:
            raise ValueError('App name should be not longer than 128 characters')
        if len(login.server_name) > 128:
            raise ValueError('Server name should be not longer than 128 characters')
        if len(login.database) > 128:
            raise ValueError('Database name should be not longer than 128 characters')
        if len(login.language) > 128:
            raise ValueError('Language should be not longer than 128 characters')
        if len(login.attach_db_file) > 260:
            raise ValueError('File path should be not longer than 260 characters')
        w = self._writer
        w.begin_packet(TDS7_LOGIN)
        self.authentication = None
        current_pos = 86 + 8 if IS_TDS72_PLUS(self) else 86
        client_host_name = login.client_host_name
        login.client_host_name = client_host_name
        packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) + len(login.library) + len(login.language) + len(login.database)) * 2
        if login.auth:
            self.authentication = login.auth
            auth_packet = login.auth.create_packet()
            packet_size += len(auth_packet)
        else:
            auth_packet = ''
            packet_size += (len(user_name) + len(login.password)) * 2
        w.put_int(packet_size)
        w.put_uint(login.tds_version)
        w.put_int(w.bufsize)
        from . import intversion
        w.put_uint(intversion)
        w.put_int(login.pid)
        w.put_uint(0)  # connection id
        option_flag1 = TDS_SET_LANG_ON | TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL
        if not login.bulk_copy:
            option_flag1 |= TDS_DUMPLOAD_OFF
        w.put_byte(option_flag1)
        if self.authentication:
            option_flag2 |= TDS_INTEGRATED_SECURITY_ON
        w.put_byte(option_flag2)
        type_flags = 0
        if login.readonly:
            type_flags |= (2 << 5)
        w.put_byte(type_flags)
        option_flag3 = TDS_UNKNOWN_COLLATION_HANDLING
        w.put_byte(option_flag3 if IS_TDS73_PLUS(self) else 0)
        mins_fix = int(total_seconds(login.client_tz.utcoffset(datetime.now()))) // 60
        w.put_int(mins_fix)
        w.put_int(login.client_lcid)
        w.put_smallint(current_pos)
        w.put_smallint(len(client_host_name))
        current_pos += len(client_host_name) * 2
        if self.authentication:
            w.put_smallint(0)
            w.put_smallint(0)
            w.put_smallint(0)
            w.put_smallint(0)
        else:
            w.put_smallint(current_pos)
            w.put_smallint(len(user_name))
            current_pos += len(user_name) * 2
            w.put_smallint(current_pos)
            w.put_smallint(len(login.password))
            current_pos += len(login.password) * 2
        w.put_smallint(current_pos)
        w.put_smallint(len(login.app_name))
        current_pos += len(login.app_name) * 2
        # server name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.server_name))
        current_pos += len(login.server_name) * 2
        # reserved
        w.put_smallint(0)
        w.put_smallint(0)
        # library name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.library))
        current_pos += len(login.library) * 2
        # language
        w.put_smallint(current_pos)
        w.put_smallint(len(login.language))
        current_pos += len(login.language) * 2
        # database name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.database))
        current_pos += len(login.database) * 2
        # ClientID
        client_id = struct.pack('>Q', login.client_id)[2:]
        w.write(client_id)
        # authentication
        w.put_smallint(current_pos)
        w.put_smallint(len(auth_packet))
        current_pos += len(auth_packet)
        # db file
        w.put_smallint(current_pos)
        w.put_smallint(len(login.attach_db_file))
        current_pos += len(login.attach_db_file) * 2
        if IS_TDS72_PLUS(self):
            # new password
            w.put_smallint(current_pos)
            w.put_smallint(len(login.change_password))
            # sspi long
            w.put_int(0)
        w.write_ucs2(client_host_name)
        if not self.authentication:
            w.write_ucs2(user_name)
            w.write(tds7_crypt_pass(login.password))
        w.write_ucs2(login.app_name)
        w.write_ucs2(login.server_name)
        w.write_ucs2(login.library)
        w.write_ucs2(login.language)
        w.write_ucs2(login.database)
        if self.authentication:
            w.write(auth_packet)
        w.write_ucs2(login.attach_db_file)
        w.write_ucs2(login.change_password)
        w.flush()

    _SERVER_TO_CLIENT_MAPPING = {
        0x07000000: TDS70,
        0x07010000: TDS71,
        0x71000001: TDS71rev1,
        TDS72: TDS72,
        TDS73A: TDS73A,
        TDS73B: TDS73B,
        TDS74: TDS74,
        }

    def process_login_tokens(self):
        r = self._reader
        succeed = False
        #logger.debug('process_login_tokens()')
        while True:
            marker = r.get_byte()
            #logger.debug('looking for login token, got  {0:x}({1})'.format(marker, tds_token_name(marker)))
            if marker == TDS_LOGINACK_TOKEN:
                succeed = True
                size = r.get_smallint()
                r.get_byte()  # interface
                version = r.get_uint_be()
                self.conn.tds_version = self._SERVER_TO_CLIENT_MAPPING.get(version, version)
                #logger.debug('server reports TDS version {0:x}'.format(version))
                if not IS_TDS7_PLUS(self):
                    self.bad_stream('Only TDS 7.0 and higher are supported')
                # get server product name
                # ignore product name length, some servers seem to set it incorrectly
                r.get_byte()
                size -= 10
                self.conn.product_name = r.read_ucs2(size // 2)
                product_version = r.get_uint_be()
                # MSSQL 6.5 and 7.0 seem to return strange values for this
                # using TDS 4.2, something like 5F 06 32 FF for 6.50
                self.conn.product_version = product_version
                #logger.debug('Product version {0:x}'.format(product_version))
                if self.conn.authentication:
                    self.conn.authentication.close()
                    self.conn.authentication = None
            else:
                self.process_token(marker)
                if marker == TDS_DONE_TOKEN:
                    break
        return succeed

    def process_returnstatus(self):
        self.ret_status = self._reader.get_int()
        self.has_status = True

    def process_token(self, marker):
        handler = _token_map.get(marker)
        if not handler:
            self.bad_stream('Invalid TDS marker: {0}({0:x})'.format(marker))
        return handler(self)

    def get_token_id(self):
        self.set_state(TDS_READING)
        try:
            marker = self._reader.get_byte()
        except TimeoutError:
            self.set_state(TDS_PENDING)
            raise
        except:
            self._tds.close()
            raise
        return marker

    def process_simple_request(self):
        while True:
            marker = self.get_token_id()
            if marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS:
                    # skip results that don't event have rowcount
                    continue
                return
            else:
                self.process_token(marker)

    def next_set(self):
        while self.more_rows:
            self.next_row()
        if self.state == TDS_IDLE:
            return False
        if self.find_result_or_done():
            return True

    def fetchone(self):
        if self.res_info is None:
            raise ProgrammingError("Previous statement didn't produce any results")

        if self.skipped_to_status:
            raise ProgrammingError("Unable to fetch any rows after accessing return_status")

        if not self.next_row():
            return None

        return self.row

    def next_row(self):
        if not self.more_rows:
            return False
        while True:
            marker = self.get_token_id()
            if marker in (TDS_ROW_TOKEN, TDS_NBC_ROW_TOKEN):
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                return False
            else:
                self.process_token(marker)

    def find_result_or_done(self):
        self.done_flags = 0
        while True:
            marker = self.get_token_id()
            if marker == TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS:
                    if self.done_flags & TDS_DONE_COUNT:
                        return True
                    else:
                        # skip results without rowcount
                        continue
                else:
                    return False
            else:
                self.process_token(marker)

    def process_rpc(self):
        self.done_flags = 0
        self.return_value_index = 0
        while True:
            marker = self.get_token_id()
            if marker == TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS and not self.done_flags & TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
                return False
            else:
                self.process_token(marker)

    def find_return_status(self):
        self.skipped_to_status = True
        while True:
            marker = self.get_token_id()
            self.process_token(marker)
            if marker == TDS_RETURNSTATUS_TOKEN:
                return


_token_map = {
    TDS_AUTH_TOKEN: _TdsSession.process_auth,
    TDS_ENVCHANGE_TOKEN: _TdsSession.process_env_chg,
    TDS_DONE_TOKEN: lambda self: self.process_end(TDS_DONE_TOKEN),
    TDS_DONEPROC_TOKEN: lambda self: self.process_end(TDS_DONEPROC_TOKEN),
    TDS_DONEINPROC_TOKEN: lambda self: self.process_end(TDS_DONEINPROC_TOKEN),
    TDS_ERROR_TOKEN: lambda self: self.process_msg(TDS_ERROR_TOKEN),
    TDS_INFO_TOKEN: lambda self: self.process_msg(TDS_INFO_TOKEN),
    TDS_EED_TOKEN: lambda self: self.process_msg(TDS_EED_TOKEN),
    TDS_CAPABILITY_TOKEN: lambda self: self.process_msg(TDS_CAPABILITY_TOKEN),
    TDS_PARAM_TOKEN: lambda self: self.process_param(),
    TDS7_RESULT_TOKEN: lambda self: self.tds7_process_result(),
    TDS_ROW_TOKEN: lambda self: self.process_row(),
    TDS_NBC_ROW_TOKEN: lambda self: self.process_nbcrow(),
    TDS_TABNAME_TOKEN: lambda self: self.process_tabname(),
    TDS_COLINFO_TOKEN: lambda self: self.process_colinfo(),
    TDS_ORDERBY2_TOKEN: lambda self: self.process_orderby2(),
    TDS_ORDERBY_TOKEN: lambda self: self.process_orderby(),
    TDS_RETURNSTATUS_TOKEN: lambda self: self.process_returnstatus(),
    }


class _TdsSocket(object):
    def __init__(self, use_tz=None):
        self._is_connected = False
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = 0
        self.authentication = None
        self._mars_enabled = False
        self.chunk_handler = MemoryChunkedHandler()
        self._sock = None
        self._bufsize = 4096
        self.tds_version = TDS74
        self.use_tz = use_tz
        self._type_factory = TypeFactory(self.tds_version)
        self._type_inferrer = None

    def __repr__(self):
        fmt = "<_TdsSocket tran={} mars={} tds_version={} use_tz={}>"
        return fmt.format(self.tds72_transaction, self._mars_enabled,
                          self.tds_version, self.use_tz)

    def login(self, login, sock, tzinfo_factory):
        self.login = login
        self._bufsize = login.blocksize
        self.query_timeout = login.query_timeout
        self._main_session = _TdsSession(self, self, tzinfo_factory)
        self._sock = sock
        self.tds_version = login.tds_version
        if IS_TDS71_PLUS(self):
            self._main_session._send_prelogin(login)
            self._main_session._process_prelogin(login)
        if IS_TDS7_PLUS(self):
            self._main_session.tds7_send_login(login)
        else:
            raise ValueError('This TDS version is not supported')
        if not self._main_session.process_login_tokens():
            self._main_session.raise_db_exception()
        self._type_factory = TypeFactory(self.tds_version)
        self._type_inferrer = TdsTypeInferrer(
            type_factory=self._type_factory,
            collation=self.collation,
            bytes_to_unicode=self.login.bytes_to_unicode,
            allow_tz=not self.use_tz
        )
        text_size = login.text_size
        if self._mars_enabled:
            from .smp import SmpManager
            self._smp_manager = SmpManager(self)
            self._main_session = _TdsSession(
                self,
                self._smp_manager.create_session(),
                tzinfo_factory)
        self._is_connected = True
        q = []
        if text_size:
            q.append('set textsize {0}'.format(int(text_size)))
        if login.database and self.env.database != login.database:
            q.append('use ' + tds_quote_id(login.database))
        if q:
            self._main_session.submit_plain_query(''.join(q))
            self._main_session.process_simple_request()

    @property
    def mars_enabled(self):
        return self._mars_enabled

    @property
    def main_session(self):
        return self._main_session

    def create_session(self, tzinfo_factory):
        return _TdsSession(
            self, self._smp_manager.create_session(),
            tzinfo_factory)

    def read(self, size):
        buf = self._sock.recv(size)
        if len(buf) == 0:
            self.close()
            raise ClosedConnectionError()
        return buf

    def _write(self, data, final):
        try:
            flags = 0
            if hasattr(socket, 'MSG_NOSIGNAL'):
                flags |= socket.MSG_NOSIGNAL
            if not final:
                if hasattr(socket, 'MSG_MORE'):
                    flags |= socket.MSG_MORE
            self._sock.sendall(data, flags)
            if final and USE_CORK:
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)
        except:
            self.close()
            raise

    send = _write

    def is_connected(self):
        return self._is_connected

    def close(self):
        self._is_connected = False
        if self._sock is not None:
            self._sock.close()
        if hasattr(self, '_smp_manager'):
            self._smp_manager._transport_closed()
        self._main_session.state = TDS_DEAD
        if self.authentication:
            self.authentication.close()
            self.authentication = None


class _Results(object):
    def __init__(self):
        self.columns = []
        self.row_count = 0


def _parse_instances(msg):
    name = None
    if len(msg) > 3 and ord(msg[0]) == 5:
        tokens = msg[3:].decode('ascii').split(';')
        results = {}
        instdict = {}
        got_name = False
        for token in tokens:
            if got_name:
                instdict[name] = token
                got_name = False
            else:
                name = token
                if not name:
                    if not instdict:
                        break
                    results[instdict['InstanceName'].upper()] = instdict
                    instdict = {}
                    continue
                got_name = True
        return results


#
# Get port of all instances
# @return default port number or 0 if error
# @remark experimental, cf. MC-SQLR.pdf.
#
def tds7_get_instances(ip_addr, timeout=5):
    s = socket.socket(type=socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # send the request
        s.sendto(b'\x03', (ip_addr, 1434))
        msg = s.recv(16 * 1024 - 1)
        # got data, read and parse
        return _parse_instances(msg)
    finally:
        s.close()
