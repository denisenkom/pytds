import codecs
import contextlib
import logging
import datetime
import six
import socket
import struct

from .collate import ucs2_codec, Collation, lcid2charset, raw_collation
from . import tds_base
from . import tds_types
from . import tls
from .tds_base import readall, readall_fast, skipall, PreLoginEnc, PreLoginToken

logger = logging.getLogger()

# packet header
# https://msdn.microsoft.com/en-us/library/dd340948.aspx
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

logging_enabled = False


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
                raise ValueError('value should match param_type, value is {}, param_type is \'{}\''.format(repr(value), param_type.__name__))
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
    def __init__(self):
        self.database = None
        self.language = None
        self.charset = None


class _TdsReader(object):
    """ TDS stream reader

    Provides stream-like interface for TDS packeted stream.
    Also provides convinience methods to decode primitive data like
    different kinds of integers etc.
    """
    def __init__(self, session):
        self._buf = bytearray(b'\x00' * 4096)
        self._bufview = memoryview(self._buf)
        self._pos = len(self._buf)  # position in the buffer
        self._have = 0  # number of bytes read from packet
        self._size = 0  # size of current packet
        self._session = session
        self._transport = session._transport
        self._type = None
        self._status = None

    def set_block_size(self, size):
        self._buf = bytearray(b'\x00' * size)
        self._bufview = memoryview(self._buf)

    def get_block_size(self):
        return len(self._buf)

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
        if self._pos >= self._size:
            self._read_packet()
        offset = self._pos
        to_read = min(size, self._size - self._pos)
        self._pos += to_read
        return self._buf, offset

    def recv(self, size):
        if self._pos >= self._size:
            self._read_packet()
        offset = self._pos
        to_read = min(size, self._size - self._pos)
        self._pos += to_read
        return self._buf[offset:offset+to_read]

    def unpack(self, struc):
        """ Unpacks given structure from stream

        :param struc: A struct.Struct instance
        :returns: Result of unpacking
        """
        buf, offset = readall_fast(self, struc.size)
        return struc.unpack_from(buf, offset)

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

    def _read_packet(self):
        """ Reads next TDS packet from the underlying transport

        If timeout is happened during reading of packet's header will
        cancel current request.
        Can only be called when transport's read pointer is at the begining
        of the packet.
        """
        try:
            pos = 0
            while pos < _header.size:
                received = self._transport.recv_into(self._bufview[pos:], _header.size - pos)
                if received == 0:
                    raise tds_base.ClosedConnectionError()
                pos += received
        except tds_base.TimeoutError:
            self._session.put_cancel()
            raise
        self._pos = _header.size
        self._type, self._status, self._size, self._session._spid, _ = _header.unpack_from(self._bufview, 0)
        self._have = pos
        while pos < self._size:
            received = self._transport.recv_into(self._bufview[pos:], self._size - pos)
            if received == 0:
                raise tds_base.ClosedConnectionError()
            pos += received
            self._have += received

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
        self._transport = session._transport
        self._pos = 0
        self._buf = bytearray(bufsize)
        self._packet_no = 0
        self._type = 0

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

    def pack(self, struc, *args):
        """ Packs and writes structure into stream """
        self.write(struc.pack(*args))

    def put_byte(self, value):
        """ Writes single byte into stream """
        self.pack(_byte, value)

    def put_smallint(self, value):
        """ Writes 16-bit signed integer into the stream """
        self.pack(_smallint_le, value)

    def put_usmallint(self, value):
        """ Writes 16-bit unsigned integer into the stream """
        self.pack(_usmallint_le, value)

    def put_usmallint_be(self, value):
        """ Writes 16-bit unsigned big-endian integer into the stream """
        self.pack(_usmallint_be, value)

    def put_int(self, value):
        """ Writes 32-bit signed integer into the stream """
        self.pack(_int_le, value)

    def put_uint(self, value):
        """ Writes 32-bit unsigned integer into the stream """
        self.pack(_uint_le, value)

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
        for i in range(0, len(s), self.bufsize):
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
        self._transport.sendall(self._buf[:self._pos])
        self._pos = 8


def _create_exception_by_message(msg, custom_error_msg=None):
    msg_no = msg['msgno']
    if custom_error_msg is not None:
        error_msg = custom_error_msg
    else:
        error_msg = msg['message']
    if msg_no in tds_base.prog_errors:
        ex = tds_base.ProgrammingError(error_msg)
    elif msg_no in tds_base.integrity_errors:
        ex = tds_base.IntegrityError(error_msg)
    else:
        ex = tds_base.OperationalError(error_msg)
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
        self._writer = _TdsWriter(self, tds.bufsize)
        self._writer._transport = transport
        self.in_buf_max = 0
        self.state = tds_base.TDS_IDLE
        self._tds = tds
        self.messages = []
        self.rows_affected = -1
        self.use_tz = tds.use_tz
        self._spid = 0
        self.tzinfo_factory = tzinfo_factory
        self.more_rows = False
        self.done_flags = 0
        self.internal_sp_called = 0
        self.output_params = {}
        self.authentication = None
        self.return_value_index = 0
        self._out_params_indexes = []
        self.row = None
        self.end_marker = 0

    def log_response_message(self, msg):
        # logging is disabled by default
        if logging_enabled:
            logger.info('[%d] %s', self._spid, msg)

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
            raise tds_base.Error("Request failed, server didn't send error message")
        msg = None
        while True:
            msg = self.messages[-1]
            if msg['msgno'] == 3621:  # the statement has been terminated
                self.messages = self.messages[:-1]
            else:
                break

        error_msg = ' '.join(m['message'] for m in self.messages)
        ex = _create_exception_by_message(msg, error_msg)
        raise ex

    def get_type_info(self, curcol):
        """ Reads TYPE_INFO structure (http://msdn.microsoft.com/en-us/library/dd358284.aspx)

        :param curcol: An instance of :class:`Column` that will receive read information
        """
        r = self._reader
        # User defined data type of the column
        if tds_base.IS_TDS72_PLUS(self):
            user_type = r.get_uint()
        else:
            user_type = r.get_usmallint()
        curcol.column_usertype = user_type
        curcol.flags = r.get_usmallint()  # Flags
        type_id = r.get_byte()
        serializer_class = self._tds.type_factory.get_type_serializer(type_id)
        curcol.serializer = serializer_class.from_stream(r)

    def tds7_process_result(self):
        """ Reads and processes COLMETADATA stream

        This stream contains a list of returned columns.
        Stream format link: http://msdn.microsoft.com/en-us/library/dd357363.aspx
        """
        self.log_response_message('got COLMETADATA')
        r = self._reader

        # read number of columns and allocate the columns structure

        num_cols = r.get_smallint()

        # This can be a DUMMY results token from a cursor fetch

        if num_cols == -1:
            return

        self.param_info = None
        self.has_status = False
        self.ret_status = None
        self.skipped_to_status = False
        self.rows_affected = tds_base.TDS_NO_COUNT
        self.more_rows = True
        self.row = [None] * num_cols
        self.res_info = info = _Results()

        #
        # loop through the columns populating COLINFO struct from
        # server response
        #
        header_tuple = []
        for col in range(num_cols):
            curcol = tds_base.Column()
            info.columns.append(curcol)
            self.get_type_info(curcol)

            curcol.column_name = r.read_ucs2(r.get_byte())
            precision = curcol.serializer.precision
            scale = curcol.serializer.scale
            size = curcol.serializer.size
            header_tuple.append(
                (curcol.column_name,
                 curcol.serializer.get_typeid(),
                 None,
                 size,
                 precision,
                 scale,
                 curcol.flags & tds_base.Column.fNullable))
        info.description = tuple(header_tuple)
        return info

    def process_param(self):
        """ Reads and processes RETURNVALUE stream.

        This stream is used to send OUTPUT parameters from RPC to client.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303881.aspx
        """
        self.log_response_message('got RETURNVALUE message')
        r = self._reader
        if tds_base.IS_TDS72_PLUS(self):
            ordinal = r.get_usmallint()
        else:
            r.get_usmallint()  # ignore size
            ordinal = self._out_params_indexes[self.return_value_index]
        name = r.read_ucs2(r.get_byte())
        r.get_byte()  # 1 - OUTPUT of sp, 2 - result of udf
        param = tds_base.Column()
        param.column_name = name
        self.get_type_info(param)
        param.value = param.serializer.read(r)
        self.output_params[ordinal] = param
        self.return_value_index += 1

    def process_cancel(self):
        """
        Process the incoming token stream until it finds
        an end token DONE with the cancel flag set.
        At that point the connection should be ready to handle a new query.

        In case when no cancel request is pending this function does nothing.
        """
        self.log_response_message('got CANCEL message')
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
        self.log_response_message('got ERROR/INFO message')
        r = self._reader
        r.get_smallint()  # size
        msg = {'marker': marker, 'msgno': r.get_int(), 'state': r.get_byte(), 'severity': r.get_byte(),
               'sql_state': None}
        if marker == tds_base.TDS_INFO_TOKEN:
            msg['priv_msg_type'] = 0
        elif marker == tds_base.TDS_ERROR_TOKEN:
            msg['priv_msg_type'] = 1
        else:
            logger.error('tds_process_msg() called with unknown marker "{0}"'.format(marker))
        msg['message'] = r.read_ucs2(r.get_smallint())
        # server name
        msg['server'] = r.read_ucs2(r.get_byte())
        # stored proc name if available
        msg['proc_name'] = r.read_ucs2(r.get_byte())
        msg['line_number'] = r.get_int() if tds_base.IS_TDS72_PLUS(self) else r.get_smallint()
        # in case extended error data is sent, we just try to discard it

        # special case
        self.messages.append(msg)

    def process_row(self):
        """ Reads and handles ROW stream.

        This stream contains list of values of one returned row.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd357254.aspx
        """
        self.log_response_message("got ROW message")
        r = self._reader
        info = self.res_info
        info.row_count += 1
        for i, curcol in enumerate(info.columns):
            curcol.value = self.row[i] = curcol.serializer.read(r)

    def process_nbcrow(self):
        """ Reads and handles NBCROW stream.

        This stream contains list of values of one returned row in a compressed way,
        introduced in TDS 7.3.B
        Stream format url: http://msdn.microsoft.com/en-us/library/dd304783.aspx
        """
        self.log_response_message("got NBCROW message")
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
            if tds_base.my_ord(nbc[i // 8]) & (1 << (i % 8)):
                value = None
            else:
                value = curcol.serializer.read(r)
            self.row[i] = value

    def process_orderby(self):
        """ Reads and processes ORDER stream

        Used to inform client by which column dataset is ordered.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303317.aspx
        """
        r = self._reader
        skipall(r, r.get_smallint())

    def process_end(self, marker):
        """ Reads and processes DONE/DONEINPROC/DONEPROC streams

        Stream format urls:

        - DONE: http://msdn.microsoft.com/en-us/library/dd340421.aspx
        - DONEINPROC: http://msdn.microsoft.com/en-us/library/dd340553.aspx
        - DONEPROC: http://msdn.microsoft.com/en-us/library/dd340753.aspx

        :param marker: Can be TDS_DONE_TOKEN or TDS_DONEINPROC_TOKEN or TDS_DONEPROC_TOKEN
        """
        code_to_str = {
            tds_base.TDS_DONE_TOKEN: 'DONE',
            tds_base.TDS_DONEINPROC_TOKEN: 'DONEINPROC',
            tds_base.TDS_DONEPROC_TOKEN: 'DONEPROC',
        }
        self.end_marker = marker
        self.more_rows = False
        r = self._reader
        status = r.get_usmallint()
        r.get_usmallint()  # cur_cmd
        more_results = status & tds_base.TDS_DONE_MORE_RESULTS != 0
        was_cancelled = status & tds_base.TDS_DONE_CANCELLED != 0
        done_count_valid = status & tds_base.TDS_DONE_COUNT != 0
        if self.res_info:
            self.res_info.more_results = more_results
        rows_affected = r.get_int8() if tds_base.IS_TDS72_PLUS(self) else r.get_int()
        self.log_response_message("got {} message, more_res={}, cancelled={}, rows_affected={}".format(
            code_to_str[marker], more_results, was_cancelled, rows_affected))
        if was_cancelled or (not more_results and not self.in_cancel):
            self.in_cancel = False
            self.set_state(tds_base.TDS_IDLE)
        if done_count_valid:
            self.rows_affected = rows_affected
        else:
            self.rows_affected = -1
        self.done_flags = status
        if self.done_flags & tds_base.TDS_DONE_ERROR and not was_cancelled and not self.in_cancel:
            self.raise_db_exception()

    def process_env_chg(self):
        """ Reads and processes ENVCHANGE stream.

        Stream info url: http://msdn.microsoft.com/en-us/library/dd303449.aspx
        """
        self.log_response_message("got ENVCHANGE message")
        r = self._reader
        size = r.get_smallint()
        type_id = r.get_byte()
        if type_id == tds_base.TDS_ENV_SQLCOLLATION:
            size = r.get_byte()
            self.conn.collation = r.get_collation()
            logger.info('switched collation to %s', self.conn.collation)
            skipall(r, size - 5)
            # discard old one
            skipall(r, r.get_byte())
        elif type_id == tds_base.TDS_ENV_BEGINTRANS:
            size = r.get_byte()
            assert size == 8
            self.conn.tds72_transaction = r.get_uint8()
            skipall(r, r.get_byte())
        elif type_id == tds_base.TDS_ENV_COMMITTRANS or type_id == tds_base.TDS_ENV_ROLLBACKTRANS:
            self.conn.tds72_transaction = 0
            skipall(r, r.get_byte())
            skipall(r, r.get_byte())
        elif type_id == tds_base.TDS_ENV_PACKSIZE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            new_block_size = int(newval)
            if new_block_size >= 512:
                # Is possible to have a shrink if server limits packet
                # size more than what we specified
                #
                # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
                self._writer.bufsize = new_block_size
        elif type_id == tds_base.TDS_ENV_DATABASE:
            newval = r.read_ucs2(r.get_byte())
            logger.info('switched to database %s', newval)
            r.read_ucs2(r.get_byte())
            self.conn.env.database = newval
        elif type_id == tds_base.TDS_ENV_LANG:
            newval = r.read_ucs2(r.get_byte())
            logger.info('switched language to %s', newval)
            r.read_ucs2(r.get_byte())
            self.conn.env.language = newval
        elif type_id == tds_base.TDS_ENV_CHARSET:
            newval = r.read_ucs2(r.get_byte())
            logger.info('switched charset to %s', newval)
            r.read_ucs2(r.get_byte())
            self.conn.env.charset = newval
            remap = {'iso_1': 'iso8859-1'}
            self.conn.server_codec = codecs.lookup(remap.get(newval, newval))
        elif type_id == tds_base.TDS_ENV_DB_MIRRORING_PARTNER:
            newval = r.read_ucs2(r.get_byte())
            logger.info('got mirroring partner %s', newval)
            r.read_ucs2(r.get_byte())
        elif type_id == tds_base.TDS_ENV_LCID:
            lcid = int(r.read_ucs2(r.get_byte()))
            logger.info('switched lcid to %s', lcid)
            self.conn.server_codec = codecs.lookup(lcid2charset(lcid))
            r.read_ucs2(r.get_byte())
        elif type_id == tds_base.TDS_ENV_UNICODE_DATA_SORT_COMP_FLAGS:
            old_comp_flags = r.read_ucs2(r.get_byte())
            comp_flags = r.read_ucs2(r.get_byte())
            self.conn.comp_flags = comp_flags
        elif type_id == 20:
            # routing
            sz = r.get_usmallint()
            protocol = r.get_byte()
            protocol_property = r.get_usmallint()
            alt_server = r.read_ucs2(r.get_usmallint())
            logger.info('got routing info proto=%d proto_prop=%d alt_srv=%s', protocol, protocol_property, alt_server)
            self.conn.route = {
                'server': alt_server,
                'port': protocol_property,
            }
            # OLDVALUE = 0x00, 0x00
            r.get_usmallint()
        else:
            logger.warning("unknown env type: {0}, skipping".format(type_id))
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
            raise tds_base.Error('Got unexpected token')
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
        raise tds_base.InterfaceError(msg)

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
        if state == tds_base.TDS_PENDING:
            if prior_state in (tds_base.TDS_READING, tds_base.TDS_QUERYING):
                self.state = tds_base.TDS_PENDING
            else:
                raise tds_base.InterfaceError('logic error: cannot chage query state from {0} to {1}'.
                                              format(tds_base.state_names[prior_state], tds_base.state_names[state]))
        elif state == tds_base.TDS_READING:
            # transition to READING are valid only from PENDING
            if self.state != tds_base.TDS_PENDING:
                raise tds_base.InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                              format(tds_base.state_names[prior_state], tds_base.state_names[state]))
            else:
                self.state = state
        elif state == tds_base.TDS_IDLE:
            if prior_state == tds_base.TDS_DEAD:
                raise tds_base.InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                              format(tds_base.state_names[prior_state], tds_base.state_names[state]))
            self.state = state
        elif state == tds_base.TDS_DEAD:
            self.state = state
        elif state == tds_base.TDS_QUERYING:
            if self.state == tds_base.TDS_DEAD:
                raise tds_base.InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                              format(tds_base.state_names[prior_state], tds_base.state_names[state]))
            elif self.state != tds_base.TDS_IDLE:
                raise tds_base.InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                              format(tds_base.state_names[prior_state], tds_base.state_names[state]))
            else:
                self.rows_affected = tds_base.TDS_NO_COUNT
                self.internal_sp_called = 0
                self.state = state
        else:
            assert False
        return self.state

    @contextlib.contextmanager
    def querying_context(self, packet_type):
        """ Context manager for querying.

        Sets state to TDS_QUERYING, and reverts it to TDS_IDLE if exception happens inside managed block,
        and to TDS_PENDING if managed block succeeds and flushes buffer.
        """
        if self.set_state(tds_base.TDS_QUERYING) != tds_base.TDS_QUERYING:
            raise tds_base.Error("Couldn't switch to state")
        self._writer.begin_packet(packet_type)
        try:
            yield
        except:
            if self.state != tds_base.TDS_DEAD:
                self.set_state(tds_base.TDS_IDLE)
            raise
        else:
            self.set_state(tds_base.TDS_PENDING)
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
        if isinstance(value, tds_base.Column):
            value.column_name = name
            return value
        column = tds_base.Column()
        column.column_name = name
        column.flags = 0
        
        if isinstance(value, output):
            column.flags |= tds_base.fByRefValue
            if isinstance(value.type, six.string_types):
                column.type = tds_types.sql_type_by_declaration(value.type)
            elif value.type:
                column.type = self.conn.type_inferrer.from_class(value.type)
            value = value.value

        if value is default:
            column.flags |= tds_base.fDefaultValue
            value = None

        column.value = value
        if column.type is None:
            column.type = self.conn.type_inferrer.from_value(value)
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
        if self.state == tds_base.TDS_IDLE:
            return
        if not self.in_cancel:
            self.put_cancel()
        self.process_cancel()

    def submit_rpc(self, rpc_name, params, flags=0):
        """ Sends an RPC request.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd357576.aspx

        :param rpc_name: Name of the RPC to call, can be an instance of :class:`InternalProc`
        :param params: Stored proc parameters, should be a list of :class:`Column` instances.
        :param flags: See spec for possible flags.
        """
        logger.info('Sending RPC %s flags=%d', rpc_name, flags)
        self.messages = []
        self.output_params = {}
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.querying_context(tds_base.PacketType.RPC):
            if tds_base.IS_TDS72_PLUS(self):
                self._start_query()
            if tds_base.IS_TDS71_PLUS(self) and isinstance(rpc_name, tds_base.InternalProc):
                w.put_smallint(-1)
                w.put_smallint(rpc_name.proc_id)
            else:
                if isinstance(rpc_name, tds_base.InternalProc):
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
                if param.flags & tds_base.fByRefValue:
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
                serializer = param.choose_serializer(
                    type_factory=self._tds.type_factory,
                    collation=self._tds.collation or raw_collation
                )
                type_id = serializer.type
                w.put_byte(type_id)
                serializer.write_info(w)

                serializer.write(w, param.value)

    def submit_plain_query(self, operation):
        """ Sends a plain query to server.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd358575.aspx

        :param operation: A string representing sql statement.
        """
        self.messages = []
        self.cancel_if_pending()
        self.res_info = None
        logger.info("Sending query %s", operation[:100])
        w = self._writer
        with self.querying_context(tds_base.PacketType.QUERY):
            if tds_base.IS_TDS72_PLUS(self):
                self._start_query()
            w.write_ucs2(operation)

    def submit_bulk(self, metadata, rows):
        """ Sends insert bulk command.

        Spec: http://msdn.microsoft.com/en-us/library/dd358082.aspx

        :param metadata: A list of :class:`Column` instances.
        :param rows: A collection of rows, each row is a collection of values.
        :return:
        """
        logger.info('Sending INSERT BULK')
        num_cols = len(metadata)
        w = self._writer
        serializers = []
        with self.querying_context(tds_base.PacketType.BULK):
            w.put_byte(tds_base.TDS7_RESULT_TOKEN)
            w.put_usmallint(num_cols)
            for col in metadata:
                if tds_base.IS_TDS72_PLUS(self):
                    w.put_uint(col.column_usertype)
                else:
                    w.put_usmallint(col.column_usertype)
                w.put_usmallint(col.flags)
                serializer = col.choose_serializer(
                    type_factory=self._tds.type_factory,
                    collation=self._tds.collation,
                )
                type_id = serializer.type
                w.put_byte(type_id)
                serializers.append(serializer)
                serializer.write_info(w)
                w.put_byte(len(col.column_name))
                w.write_ucs2(col.column_name)
            for row in rows:
                w.put_byte(tds_base.TDS_ROW_TOKEN)
                for i, col in enumerate(metadata):
                    serializers[i].write(w, row[i])

            # https://msdn.microsoft.com/en-us/library/dd340421.aspx
            w.put_byte(tds_base.TDS_DONE_TOKEN)
            w.put_usmallint(tds_base.TDS_DONE_FINAL)
            w.put_usmallint(0)  # curcmd
            # row count
            if tds_base.IS_TDS72_PLUS(self):
                w.put_int8(0)
            else:
                w.put_int(0)

    def put_cancel(self):
        """ Sends a cancel request to the server.

        Switches connection to IN_CANCEL state.
        """
        logger.info('Sending CANCEL')
        self._writer.begin_packet(tds_base.PacketType.CANCEL)
        self._writer.flush()
        self.in_cancel = 1

    _begin_tran_struct_72 = struct.Struct('<HBB')

    def begin_tran(self, isolation_level=0):
        logger.info('Sending BEGIN TRAN il=%x', isolation_level)
        self.submit_begin_tran(isolation_level=isolation_level)
        self.process_simple_request()

    def submit_begin_tran(self, isolation_level=0):
        if tds_base.IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(tds_base.PacketType.TRANS):
                self._start_query()
                w.pack(
                    self._begin_tran_struct_72,
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
        logger.info('Sending ROLLBACK TRAN')
        self.submit_rollback(cont, isolation_level=isolation_level)
        prev_timeout = self._tds.sock.gettimeout()
        self._tds.sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds.sock.settimeout(prev_timeout)

    def submit_rollback(self, cont, isolation_level=0):
        if tds_base.IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(tds_base.PacketType.TRANS):
                self._start_query()
                flags = 0
                if cont:
                    flags |= 1
                w.pack(
                    self._commit_rollback_tran_struct72_hdr,
                    8,  # TM_ROLLBACK_XACT
                    0,  # transaction name
                    flags,
                    )
                if cont:
                    w.pack(
                        self._continue_tran_struct72,
                        isolation_level,
                        0,  # new transaction name
                        )
        else:
            self.submit_plain_query(
                "IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")
            self.conn.tds72_transaction = 1 if cont else 0

    def commit(self, cont, isolation_level=0):
        logger.info('Sending COMMIT TRAN')
        self.submit_commit(cont, isolation_level=isolation_level)
        prev_timeout = self._tds.sock.gettimeout()
        self._tds.sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds.sock.settimeout(prev_timeout)

    def submit_commit(self, cont, isolation_level=0):
        if tds_base.IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(tds_base.PacketType.TRANS):
                self._start_query()
                flags = 0
                if cont:
                    flags |= 1
                w.pack(
                    self._commit_rollback_tran_struct72_hdr,
                    7,  # TM_COMMIT_XACT
                    0,  # transaction name
                    flags,
                    )
                if cont:
                    w.pack(
                        self._continue_tran_struct72,
                        isolation_level,
                        0,  # new transaction name
                        )
        else:
            self.submit_plain_query(
                "IF @@TRANCOUNT > 0 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")
            self.conn.tds72_transaction = 1 if cont else 0

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

    def send_prelogin(self, login):
        from . import intversion
        # https://msdn.microsoft.com/en-us/library/dd357559.aspx
        instance_name = login.instance_name or 'MSSQLServer'
        instance_name = instance_name.encode('ascii')
        if len(instance_name) > 65490:
            raise ValueError('Instance name is too long')
        if tds_base.IS_TDS72_PLUS(self):
            start_pos = 26
            buf = struct.pack(
                b'>BHHBHHBHHBHHBHHB',
                # netlib version
                PreLoginToken.VERSION, start_pos, 6,
                # encryption
                PreLoginToken.ENCRYPTION, start_pos + 6, 1,
                # instance
                PreLoginToken.INSTOPT, start_pos + 6 + 1, len(instance_name) + 1,
                # thread id
                PreLoginToken.THREADID, start_pos + 6 + 1 + len(instance_name) + 1, 4,
                # MARS enabled
                PreLoginToken.MARS, start_pos + 6 + 1 + len(instance_name) + 1 + 4, 1,
                # end
                PreLoginToken.TERMINATOR
                )
        else:
            start_pos = 21
            buf = struct.pack(
                b'>BHHBHHBHHBHHB',
                # netlib version
                PreLoginToken.VERSION, start_pos, 6,
                # encryption
                PreLoginToken.ENCRYPTION, start_pos + 6, 1,
                # instance
                PreLoginToken.INSTOPT, start_pos + 6 + 1, len(instance_name) + 1,
                # thread id
                PreLoginToken.THREADID, start_pos + 6 + 1 + len(instance_name) + 1, 4,
                # end
                PreLoginToken.TERMINATOR
                )
        assert start_pos == len(buf)
        w = self._writer
        w.begin_packet(tds_base.PacketType.PRELOGIN)
        w.write(buf)
        w.put_uint_be(intversion)
        w.put_usmallint_be(0)  # build number
        # encryption flag
        w.put_byte(login.enc_flag)
        w.write(instance_name)
        w.put_byte(0)  # zero terminate instance_name
        w.put_int(0)  # TODO: change this to thread id
        attribs = {
            'lib_ver': '%x' % intversion,
            'enc_flag': '%x' % login.enc_flag,
            'inst_name': instance_name,
        }
        if tds_base.IS_TDS72_PLUS(self):
            # MARS (1 enabled)
            w.put_byte(1 if login.use_mars else 0)
            attribs['mars'] = login.use_mars
        logger.info('Sending PRELOGIN %s', ' '.join('%s=%s' % (n, v) for n, v in attribs.items()))

        w.flush()

    def process_prelogin(self, login):
        # https://msdn.microsoft.com/en-us/library/dd357559.aspx
        p = self._reader.read_whole_packet()
        size = len(p)
        if size <= 0 or self._reader.packet_type != tds_base.PacketType.REPLY:
            self.bad_stream('Invalid packet type: {0}, expected PRELOGIN(4)'.format(self._reader.packet_type))
        self.parse_prelogin(octets=p, login=login)

    def parse_prelogin(self, octets, login):
        # https://msdn.microsoft.com/en-us/library/dd357559.aspx
        size = len(octets)
        p = octets
        # default 2, no certificate, no encryptption
        crypt_flag = 2
        i = 0
        byte_struct = struct.Struct('B')
        off_len_struct = struct.Struct('>HH')
        prod_version_struct = struct.Struct('>LH')
        while True:
            if i >= size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            type_id, = byte_struct.unpack_from(p, i)
            if type_id == PreLoginToken.TERMINATOR:
                break
            if i + 4 > size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            off, l = off_len_struct.unpack_from(p, i + 1)
            if off > size or off + l > size:
                self.bad_stream('Invalid offset in PRELOGIN structure')
            if type_id == PreLoginToken.VERSION:
                self.conn.server_library_version = prod_version_struct.unpack_from(p, off)
            elif type_id == PreLoginToken.ENCRYPTION and l >= 1:
                crypt_flag, = byte_struct.unpack_from(p, off)
            elif type_id == PreLoginToken.MARS:
                self.conn._mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
            elif type_id == PreLoginToken.INSTOPT:
                # ignore instance name mismatch
                pass
            i += 5
        logger.info("Got PRELOGIN response crypt=%x mars=%d",
                    crypt_flag, self.conn._mars_enabled)
        # if server do not has certificate do normal login
        login.server_enc_flag = crypt_flag
        if crypt_flag == PreLoginEnc.ENCRYPT_OFF:
            if login.enc_flag == PreLoginEnc.ENCRYPT_ON:
                raise self.bad_stream('Server returned unexpected ENCRYPT_ON value')
            else:
                # encrypt login packet only
                tls.establish_channel(self)
        elif crypt_flag == PreLoginEnc.ENCRYPT_ON:
            # encrypt entire connection
            tls.establish_channel(self)
        elif crypt_flag == PreLoginEnc.ENCRYPT_REQ:
            if login.enc_flag == PreLoginEnc.ENCRYPT_NOT_SUP:
                # connection terminated by server and client
                raise tds_base.Error('Client does not have encryption enabled but it is required by server, '
                                     'enable encryption and try connecting again')
            else:
                # encrypt entire connection
                tls.establish_channel(self)
        elif crypt_flag == PreLoginEnc.ENCRYPT_NOT_SUP:
            if login.enc_flag == PreLoginEnc.ENCRYPT_ON:
                # connection terminated by server and client
                raise tds_base.Error('You requested encryption but it is not supported by server')
            # do not encrypt anything
        else:
            self.bad_stream('Unexpected value of enc_flag returned by server: {}'.format(crypt_flag))

    def tds7_send_login(self, login):
        # https://msdn.microsoft.com/en-us/library/dd304019.aspx
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
        w.begin_packet(tds_base.PacketType.LOGIN)
        self.authentication = None
        current_pos = 86 + 8 if tds_base.IS_TDS72_PLUS(self) else 86
        client_host_name = login.client_host_name
        login.client_host_name = client_host_name
        packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) +
                                     len(login.library) + len(login.language) + len(login.database)) * 2
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
        option_flag1 = tds_base.TDS_SET_LANG_ON | tds_base.TDS_USE_DB_NOTIFY | tds_base.TDS_INIT_DB_FATAL
        if not login.bulk_copy:
            option_flag1 |= tds_base.TDS_DUMPLOAD_OFF
        w.put_byte(option_flag1)
        if self.authentication:
            option_flag2 |= tds_base.TDS_INTEGRATED_SECURITY_ON
        w.put_byte(option_flag2)
        type_flags = 0
        if login.readonly:
            type_flags |= (2 << 5)
        w.put_byte(type_flags)
        option_flag3 = tds_base.TDS_UNKNOWN_COLLATION_HANDLING
        w.put_byte(option_flag3 if tds_base.IS_TDS73_PLUS(self) else 0)
        mins_fix = int(login.client_tz.utcoffset(datetime.datetime.now()).total_seconds()) // 60
        logger.info('Sending LOGIN tds_ver=%x bufsz=%d pid=%d opt1=%x opt2=%x opt3=%x cli_tz=%d cli_lcid=%s '
                    'cli_host=%s lang=%s db=%s',
                    login.tds_version, w.bufsize, login.pid, option_flag1, option_flag2, option_flag3, mins_fix,
                    login.client_lcid, client_host_name, login.language, login.database)
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
        if tds_base.IS_TDS72_PLUS(self):
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
        0x07000000: tds_base.TDS70,
        0x07010000: tds_base.TDS71,
        0x71000001: tds_base.TDS71rev1,
        tds_base.TDS72: tds_base.TDS72,
        tds_base.TDS73A: tds_base.TDS73A,
        tds_base.TDS73B: tds_base.TDS73B,
        tds_base.TDS74: tds_base.TDS74,
        }

    def process_login_tokens(self):
        r = self._reader
        succeed = False
        while True:
            marker = r.get_byte()
            if marker == tds_base.TDS_LOGINACK_TOKEN:
                # https://msdn.microsoft.com/en-us/library/dd340651.aspx
                succeed = True
                size = r.get_smallint()
                r.get_byte()  # interface
                version = r.get_uint_be()
                self.conn.tds_version = self._SERVER_TO_CLIENT_MAPPING.get(version, version)
                if not tds_base.IS_TDS7_PLUS(self):
                    self.bad_stream('Only TDS 7.0 and higher are supported')
                # get server product name
                # ignore product name length, some servers seem to set it incorrectly
                r.get_byte()
                size -= 10
                self.conn.product_name = r.read_ucs2(size // 2)
                product_version = r.get_uint_be()
                logger.info('Got LOGINACK tds_ver=%x srv_name=%s srv_ver=%x',
                            self.conn.tds_version, self.conn.product_name, product_version)
                # MSSQL 6.5 and 7.0 seem to return strange values for this
                # using TDS 4.2, something like 5F 06 32 FF for 6.50
                self.conn.product_version = product_version
                if self.authentication:
                    self.authentication.close()
                    self.authentication = None
            else:
                self.process_token(marker)
                if marker == tds_base.TDS_DONE_TOKEN:
                    break
        return succeed

    def process_returnstatus(self):
        self.log_response_message('got RETURNSTATUS message')
        self.ret_status = self._reader.get_int()
        self.has_status = True

    def process_token(self, marker):
        handler = _token_map.get(marker)
        if not handler:
            self.bad_stream('Invalid TDS marker: {0}({0:x})'.format(marker))
        return handler(self)

    def get_token_id(self):
        self.set_state(tds_base.TDS_READING)
        try:
            marker = self._reader.get_byte()
        except tds_base.TimeoutError:
            self.set_state(tds_base.TDS_PENDING)
            raise
        except:
            self._tds.close()
            raise
        return marker

    def process_simple_request(self):
        while True:
            marker = self.get_token_id()
            if marker in (tds_base.TDS_DONE_TOKEN, tds_base.TDS_DONEPROC_TOKEN, tds_base.TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if not self.done_flags & tds_base.TDS_DONE_MORE_RESULTS:
                    return
            else:
                self.process_token(marker)

    def next_set(self):
        while self.more_rows:
            self.next_row()
        if self.state == tds_base.TDS_IDLE:
            return False
        if self.find_result_or_done():
            return True

    def fetchone(self):
        if self.res_info is None:
            raise tds_base.ProgrammingError("Previous statement didn't produce any results")

        if self.skipped_to_status:
            raise tds_base.ProgrammingError("Unable to fetch any rows after accessing return_status")

        if not self.next_row():
            return None

        return self.row

    def next_row(self):
        if not self.more_rows:
            return False
        while True:
            marker = self.get_token_id()
            if marker in (tds_base.TDS_ROW_TOKEN, tds_base.TDS_NBC_ROW_TOKEN):
                self.process_token(marker)
                return True
            elif marker in (tds_base.TDS_DONE_TOKEN, tds_base.TDS_DONEPROC_TOKEN, tds_base.TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                return False
            else:
                self.process_token(marker)

    def find_result_or_done(self):
        self.done_flags = 0
        while True:
            marker = self.get_token_id()
            if marker == tds_base.TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (tds_base.TDS_DONE_TOKEN, tds_base.TDS_DONEPROC_TOKEN, tds_base.TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & tds_base.TDS_DONE_MORE_RESULTS:
                    if self.done_flags & tds_base.TDS_DONE_COUNT:
                        return True
                else:
                    return False
            else:
                self.process_token(marker)

    def process_rpc(self):
        self.done_flags = 0
        self.return_value_index = 0
        while True:
            marker = self.get_token_id()
            if marker == tds_base.TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (tds_base.TDS_DONE_TOKEN, tds_base.TDS_DONEPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & tds_base.TDS_DONE_MORE_RESULTS and not self.done_flags & tds_base.TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
                return False
            else:
                self.process_token(marker)

    def complete_rpc(self):
        # go through all result sets
        while self.next_set():
            pass

    def find_return_status(self):
        self.skipped_to_status = True
        while True:
            marker = self.get_token_id()
            self.process_token(marker)
            if marker == tds_base.TDS_RETURNSTATUS_TOKEN:
                return


_token_map = {
    tds_base.TDS_AUTH_TOKEN: _TdsSession.process_auth,
    tds_base.TDS_ENVCHANGE_TOKEN: _TdsSession.process_env_chg,
    tds_base.TDS_DONE_TOKEN: lambda self: self.process_end(tds_base.TDS_DONE_TOKEN),
    tds_base.TDS_DONEPROC_TOKEN: lambda self: self.process_end(tds_base.TDS_DONEPROC_TOKEN),
    tds_base.TDS_DONEINPROC_TOKEN: lambda self: self.process_end(tds_base.TDS_DONEINPROC_TOKEN),
    tds_base.TDS_ERROR_TOKEN: lambda self: self.process_msg(tds_base.TDS_ERROR_TOKEN),
    tds_base.TDS_INFO_TOKEN: lambda self: self.process_msg(tds_base.TDS_INFO_TOKEN),
    tds_base.TDS_CAPABILITY_TOKEN: lambda self: self.process_msg(tds_base.TDS_CAPABILITY_TOKEN),
    tds_base.TDS_PARAM_TOKEN: lambda self: self.process_param(),
    tds_base.TDS7_RESULT_TOKEN: lambda self: self.tds7_process_result(),
    tds_base.TDS_ROW_TOKEN: lambda self: self.process_row(),
    tds_base.TDS_NBC_ROW_TOKEN: lambda self: self.process_nbcrow(),
    tds_base.TDS_ORDERBY_TOKEN: lambda self: self.process_orderby(),
    tds_base.TDS_RETURNSTATUS_TOKEN: lambda self: self.process_returnstatus(),
    }


# this class represents root TDS connection
# if MARS is used it can have multiple sessions represented by _TdsSession class
# if MARS is not used it would have single _TdsSession instance
class _TdsSocket(object):
    def __init__(self, use_tz=None):
        self._is_connected = False
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = 0
        self._mars_enabled = False
        self.sock = None
        self.bufsize = 4096
        self.tds_version = tds_base.TDS74
        self.use_tz = use_tz
        self.type_factory = tds_types.SerializerFactory(self.tds_version)
        self.type_inferrer = None
        self.query_timeout = 0
        self._smp_manager = None
        self._main_session = None
        self._login = None
        self.route = None

    def __repr__(self):
        fmt = "<_TdsSocket tran={} mars={} tds_version={} use_tz={}>"
        return fmt.format(self.tds72_transaction, self._mars_enabled,
                          self.tds_version, self.use_tz)

    def login(self, login, sock, tzinfo_factory):
        self._login = login
        self.bufsize = login.blocksize
        self.query_timeout = login.query_timeout
        self._main_session = _TdsSession(self, sock, tzinfo_factory)
        self.sock = sock
        self.tds_version = login.tds_version
        login.server_enc_flag = PreLoginEnc.ENCRYPT_NOT_SUP
        if tds_base.IS_TDS71_PLUS(self):
            self._main_session.send_prelogin(login)
            self._main_session.process_prelogin(login)
        self._main_session.tds7_send_login(login)
        if login.server_enc_flag == PreLoginEnc.ENCRYPT_OFF:
            tls.revert_to_clear(self._main_session)
        if not self._main_session.process_login_tokens():
            self._main_session.raise_db_exception()
        if self.route is not None:
            return self.route

        # update block size if server returned different one
        if self._main_session._writer.bufsize != self._main_session._reader.get_block_size():
            self._main_session._reader.set_block_size(self._main_session._writer.bufsize)

        self.type_factory = tds_types.SerializerFactory(self.tds_version)
        self.type_inferrer = tds_types.TdsTypeInferrer(
            type_factory=self.type_factory,
            collation=self.collation,
            bytes_to_unicode=self._login.bytes_to_unicode,
            allow_tz=not self.use_tz
        )
        if self._mars_enabled:
            from .smp import SmpManager
            self._smp_manager = SmpManager(self.sock)
            self._main_session = _TdsSession(
                self,
                self._smp_manager.create_session(),
                tzinfo_factory)
        self._is_connected = True
        q = []
        if login.database and self.env.database != login.database:
            q.append('use ' + tds_base.tds_quote_id(login.database))
        if q:
            self._main_session.submit_plain_query(''.join(q))
            self._main_session.process_simple_request()
        return None

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

    def is_connected(self):
        return self._is_connected

    def close(self):
        self._is_connected = False
        if self.sock is not None:
            self.sock.close()
        if self._smp_manager:
            self._smp_manager.transport_closed()
        self._main_session.state = tds_base.TDS_DEAD
        if self._main_session.authentication:
            self._main_session.authentication.close()
            self._main_session.authentication = None


class _Results(object):
    def __init__(self):
            self.columns = []
            self.row_count = 0


def _parse_instances(msg):
    name = None
    if len(msg) > 3 and tds_base.my_ord(msg[0]) == 5:
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
