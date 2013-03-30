# vim: set fileencoding=utf8 :
import struct
import socket
from dateutil.tz import tzlocal
import uuid
import os
import logging
ENCRYPTION_ENABLED = False
try:
    import ssl
except:
    encryption_supported = False
else:
    encryption_supported = True
from .tdsproto import *
from .tds import *
from .token import *

logger = logging.getLogger(__name__)


class SspiAuth(object):
    def __init__(self, user_name='', password='', server_name='', port=None, spn=None):
        import sspi
        # parse username/password informations
        if '\\' in user_name:
            domain, user_name = user_name.split('\\')
        else:
            domain = ''
        if domain and user_name:
            self._identity = sspi.make_winnt_identity(
                domain,
                user_name,
                password)
        else:
            self._identity = None
        # build SPN
        if spn:
            self._sname = spn
        else:
            primary_host_name, _, _ = socket.gethostbyname_ex(server_name)
            self._sname = 'MSSQLSvc/{0}:{1}'.format(primary_host_name, port)

        # using Negotiate system will use proper protocol (either NTLM or Kerberos)
        self._cred = sspi.SspiCredentials(
            package='Negotiate',
            use=sspi.SECPKG_CRED_OUTBOUND,
            identity=self._identity)

        self._flags = sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_REPLAY_DETECT | sspi.ISC_REQ_CONNECTION

    def create_packet(self):
        import sspi
        import ctypes
        buf = ctypes.create_string_buffer(4096)
        self._ctx, status, bufs = self._cred.create_context(
            flags=self._flags,
            byte_ordering='network',
            target_name=self._sname,
            output_buffers=[(sspi.SECBUFFER_TOKEN, buf)])
        if status == sspi.Status.SEC_I_COMPLETE_AND_CONTINUE:
            self._ctx.complete_auth_token(bufs)
        return bufs[0][1]

    def handle_next(self, packet):
        import sspi
        import ctypes
        buf = ctypes.create_string_buffer(4096)
        status, buffers = self._ctx.next(
            flags=self._flags,
            byte_ordering='network',
            target_name=self._sname,
            input_buffers=[(sspi.SECBUFFER_TOKEN, packet)],
            output_buffers=[(sspi.SECBUFFER_TOKEN, buf)])
        return buffers[0][1]

    def close(self):
        self._ctx.close()
        self._cred.close()


class NtlmAuth(object):
    def __init__(self, user_name, password):
        self._domain, self._user = user_name.split('\\', 1)
        self._password = password

    def create_packet(self):
        import ntlm
        return ntlm.create_NTLM_NEGOTIATE_MESSAGE_raw(this_host_name, self._domain)

    def handle_next(self, packet):
        import ntlm
        nonce, flags = ntlm.parse_NTLM_CHALLENGE_MESSAGE_raw(packet)
        return ntlm.create_NTLM_AUTHENTICATE_MESSAGE_raw(nonce, self._user, self._domain, self._password, flags)

    def close(self):
        pass


def tds_login(tds, login):
    if IS_TDS71_PLUS(tds):
        tds71_do_login(tds, login)
    elif IS_TDS7_PLUS(tds):
        tds7_send_login(tds, login)
    else:
        raise NotImplementedError('This TDS version is not supported')
        tds._writer.begin_packet(TDS_LOGIN)
        tds_send_login(tds, login)
    if not tds_process_login_tokens(tds):
        raise_db_exception(tds)
        #raise LoginError("Cannot connect to server '{0}' as user '{1}'".format(login.server_name, login.user_name))

this_host_name = socket.gethostname()
mins_fix = tzlocal().utcoffset(datetime.now()).total_seconds() / 60
mac_address = struct.pack('>Q', uuid.getnode())[:6]


def tds7_send_login(tds, login):
    option_flag2 = login.option_flag2
    user_name = login.user_name
    w = tds._writer
    w.begin_packet(TDS7_LOGIN)
    tds.authentication = None
    if len(login.password) > 128:
        raise Error('Password should be not more than 128 characters')
    current_pos = 86 + 8 if IS_TDS72_PLUS(tds) else 86
    client_host_name = this_host_name
    login.client_host_name = client_host_name
    packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) + len(login.library) + len(login.language) + len(login.database)) * 2
    if login.auth:
        tds.authentication = login.auth
        auth_packet = login.auth.create_packet()
        packet_size += len(auth_packet)
    else:
        auth_packet = ''
        packet_size += (len(user_name) + len(login.password)) * 2
    w.put_int(packet_size)
    w.put_uint(login.tds_version)
    w.put_int(w.bufsize)
    from pytds import intversion
    w.put_uint(intversion)
    w.put_int(os.getpid())
    w.put_uint(0)  # connection id
    option_flag1 = TDS_SET_LANG_ON | TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL
    if not login.bulk_copy:
        option_flag1 |= TDS_DUMPLOAD_OFF
    w.put_byte(option_flag1)
    if tds.authentication:
        option_flag2 |= TDS_INTEGRATED_SECURITY_ON
    w.put_byte(option_flag2)
    type_flags = 0
    if login.readonly:
        type_flags |= (2 << 5)
    w.put_byte(type_flags)
    option_flag3 = TDS_UNKNOWN_COLLATION_HANDLING
    w.put_byte(option_flag3 if IS_TDS73_PLUS(tds) else 0)
    w.put_int(int(mins_fix))
    w.put_int(login.client_lcid)
    w.put_smallint(current_pos)
    w.put_smallint(len(client_host_name))
    current_pos += len(client_host_name) * 2
    if tds.authentication:
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
    w.write(mac_address)
    # authentication
    w.put_smallint(current_pos)
    w.put_smallint(len(auth_packet))
    current_pos += len(auth_packet)
    # db file
    w.put_smallint(current_pos)
    w.put_smallint(len(login.attach_db_file))
    current_pos += len(login.attach_db_file) * 2
    if IS_TDS72_PLUS(tds):
        # new password
        w.put_smallint(current_pos)
        w.put_smallint(0)
        # sspi long
        w.put_int(0)
    w.write_ucs2(client_host_name)
    if not tds.authentication:
        w.write_ucs2(user_name)
        w.write(tds7_crypt_pass(login.password))
    w.write_ucs2(login.app_name)
    w.write_ucs2(login.server_name)
    w.write_ucs2(login.library)
    w.write_ucs2(login.language)
    w.write_ucs2(login.database)
    if tds.authentication:
        w.write(auth_packet)
    w.write_ucs2(login.attach_db_file)
    w.flush()


def tds7_crypt_pass(password):
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4) & 0xff | (ch >> 4)) ^ 0xA5
    return encoded

VERSION = 0
ENCRYPTION = 1
INSTOPT = 2
THREADID = 3
MARS = 4
TRACEID = 5
TERMINATOR = 0xff


def tds71_do_login(tds, login):
    instance_name = login.instance_name or 'MSSQLServer'
    encryption_level = login.encryption_level
    if IS_TDS72_PLUS(tds):
        START_POS = 26
        buf = struct.pack(
            b'>BHHBHHBHHBHHBHHB',
            #netlib version
            VERSION, START_POS, 6,
            #encryption
            ENCRYPTION, START_POS + 6, 1,
            #instance
            INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
            # thread id
            THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
            # MARS enabled
            MARS, START_POS + 6 + 1 + len(instance_name) + 1 + 4, 1,
            # end
            TERMINATOR
            )
    else:
        START_POS = 21
        buf = struct.pack(
            b'>BHHBHHBHHBHHB',
            #netlib version
            VERSION, START_POS, 6,
            #encryption
            ENCRYPTION, START_POS + 6, 1,
            #instance
            INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
            # thread id
            THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
            # end
            TERMINATOR
            )
    assert START_POS == len(buf)
    w = tds._writer
    w.begin_packet(TDS71_PRELOGIN)
    w.write(buf)
    from pytds import intversion
    w.put_uint_be(intversion)
    w.put_usmallint_be(0)
    # encryption
    if ENCRYPTION_ENABLED and encryption_supported:
        w.put_byte(1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
    else:
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise Error('Client requested encryption but it is not supported')
        # not supported
        w.put_byte(2)
    w.write(instance_name.encode('ascii'))
    w.put_byte(0)  # zero terminate instance_name
    w.put_int(os.getpid())  # TODO: change this to thread id
    if IS_TDS72_PLUS(tds):
        # MARS (1 enabled)
        w.put_byte(1 if login.use_mars else 0)
    w.flush()
    p = tds._reader.read_whole_packet()
    size = len(p)
    if size <= 0 or tds._reader.packet_type != 4:
        raise Error('TDS_FAIL')
    # default 2, no certificate, no encryptption
    crypt_flag = 2
    i = 0
    byte_struct = struct.Struct('B')
    off_len_struct = struct.Struct('>HH')
    prod_version_struct = struct.Struct('>LH')
    while True:
        if i >= size:
            raise Error('TDS_FAIL')
        type, = byte_struct.unpack_from(p, i)
        if type == 0xff:
            break
        if i + 4 > size:
            raise Error('TDS_FAIL')
        off, l = off_len_struct.unpack_from(p, i + 1)
        if off > size or off + l > size:
            raise Error('TDS_FAIL')
        if type == VERSION:
            tds.conn.product_version = prod_version_struct.unpack_from(p, off)
        elif type == ENCRYPTION and l >= 1:
            crypt_flag, = byte_struct.unpack_from(p, off)
        elif type == MARS:
            tds.conn._mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
        i += 5
    # we readed all packet
    logger.debug('detected flag %d', crypt_flag)
    # if server do not has certificate do normal login
    if crypt_flag == 2:
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise Error('Server required encryption but it is not supported')
        return tds7_send_login(tds, login)
    tds._sock = ssl.wrap_socket(tds._sock, ssl_version=ssl.PROTOCOL_SSLv3)
    return tds7_send_login(tds, login)
