# vim: set fileencoding=utf8 :
import struct
import os
import logging
ENCRYPTION_ENABLED = False
try:
    import ssl
except:
    encryption_supported = False
else:
    encryption_supported = True
from tdsproto import *
from tds import *
from token import *

logger = logging.getLogger(__name__)


def tds_connect_and_login(tds, login):
    tds.login = login
    tds.tds_version = login.tds_version
    tds_conn(tds).emul_little_endian = login.emul_little_endian
    if IS_TDS7_PLUS(tds):
        # TDS 7/8 only supports little endian
        tds_conn(tds).emul_little_endian = True
    if IS_TDS7_PLUS(tds) and login.instance_name and not login.port:
        instances = tds7_get_instances(login.ip_addr or login.server_name)
        if login.instance_name not in instances:
            raise LoginError("Instance {0} not found on server {1}".format(login.instance_name, login.server_name))
        instdict = instances[login.instance_name]
        if 'tcp' not in instdict:
            raise LoginError("Instance {0} doen't have tcp connections enabled".format(login.instance_name))
        login.port = int(instdict['tcp'])
    connect_timeout = login.connect_timeout
    tds.query_timeout = connect_timeout if connect_timeout else login.query_timeout
    try:
        tds_open_socket(tds, login.ip_addr or login.server_name, login.port, connect_timeout)
    except socket.error as e:
        raise LoginError("Cannot connect to server '{0}': {1}".format(login.server_name, e), e)
    tds_set_state(tds, TDS_IDLE)
    try:
        db_selected = False
        if IS_TDS71_PLUS(tds):
            tds71_do_login(tds, login)
            db_selected = True
        elif IS_TDS7_PLUS(tds):
            tds7_send_login(tds, login)
            db_selected = True
        else:
            raise NotImplementedError('This TDS version is not supported')
            tds._writer.begin_packet(TDS_LOGIN)
            tds_send_login(tds, login)
        if not tds_process_login_tokens(tds):
            raise_db_exception(tds)
            #raise LoginError("Cannot connect to server '{0}' as user '{1}'".format(login.server_name, login.user_name))
        text_size = login.text_size
        if text_size or not db_selected and login.database:
            q = []
            if text_size:
                q.append('set textsize {0}'.format(int(text_size)))
            if not db_selected and login.database:
                q.append('use ' + tds_quote_id(tds, login.database))
            tds_submit_query(tds, ''.join(q))
            tds_process_simple_query(tds)
        return tds
    except:
        tds_close_socket(tds)
        raise

import socket
this_host_name = socket.gethostname()
from dateutil.tz import tzlocal
mins_fix = tzlocal().utcoffset(datetime.now()).total_seconds()/60
import uuid
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
    packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) + len(login.library) + len(login.language) + len(login.database))*2
    auth_len = 0
    # TODO: support sspi login
    if False:
        if user_name.find('\\') != -1 or not user_name:
            raise NotImplementedError('sspi not implemented')
    else:
        if user_name.find('\\') != -1:
            raise NotImplementedError('ntlm not implemented')
        elif not user_name:
            raise NotImplementedError('requested GSS authentication but it is not implemented')
        else:
            packet_size += (len(user_name) + len(login.password))*2
    w.put_int(packet_size)
    w.put_uint(login.tds_version)
    w.put_int(w.bufsize)
    from pytds import intversion
    w.put_uint(intversion)
    w.put_int(os.getpid())
    w.put_uint(0) # connection id
    option_flag1 = TDS_SET_LANG_ON | TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL
    if not login.bulk_copy:
        option_flag1 |= TDS_DUMPLOAD_OFF
    w.put_byte(option_flag1)
    if False:
        if tds.authentication:
            option_flag2 |= TDS_INTEGRATED_SECURITY_ON
    w.put_byte(option_flag2)
    w.put_byte(0) # sql_type_flag
    option_flag3 = TDS_UNKNOWN_COLLATION_HANDLING
    w.put_byte(option_flag3 if IS_TDS73_PLUS(tds) else 0)
    w.put_int(mins_fix)
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
    w.put_smallint(current_pos);
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
    w.put_smallint(current_pos);
    w.put_smallint(len(login.language));
    current_pos += len(login.language) * 2;
    # database name
    w.put_smallint(current_pos);
    w.put_smallint(len(login.database));
    current_pos += len(login.database) * 2;
    # ClientID
    w.write(mac_address)
    # authentication
    w.put_smallint(current_pos)
    w.put_smallint(auth_len)
    current_pos += auth_len
    # db file
    w.put_smallint(current_pos)
    w.put_smallint(len(login.attach_db_file))
    current_pos += len(login.attach_db_file) * 2;
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
        w.write(tds.authentication.packet)
    w.write_ucs2(login.attach_db_file)
    w.flush()

def tds7_crypt_pass(password):
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4)&0xff | (ch >> 4)) ^ 0xA5
    return encoded

def tds71_do_login(tds, login):
    VERSION = 0
    ENCRYPTION = 1
    INSTOPT = 2
    THREADID = 3
    MARS = 4
    TRACEID = 5
    TERMINATOR = 0xff
    instance_name = login.instance_name or 'MSSQLServer'
    encryption_level = login.encryption_level
    if IS_TDS72_PLUS(tds):
        START_POS = 26
        buf = struct.pack('>BHHBHHBHHBHHBHHB',
                #netlib version
                VERSION, START_POS, 6,
                #encryption
                ENCRYPTION, START_POS + 6, 1,
                #instance
                INSTOPT, START_POS + 6 + 1, len(instance_name)+1,
                # thread id
                THREADID, START_POS + 6 + 1 + len(instance_name)+1, 4,
                # MARS enabled
                MARS, START_POS + 6 + 1 + len(instance_name)+1 + 4, 1,
                # end
                TERMINATOR
                )
    else:
        START_POS = 21
        buf = struct.pack('>BHHBHHBHHBHHB',
                #netlib version
                VERSION, START_POS, 6,
                #encryption
                ENCRYPTION, START_POS + 6, 1,
                #instance
                INSTOPT, START_POS + 6 + 1, len(instance_name)+1,
                # thread id
                THREADID, START_POS + 6 + 1 + len(instance_name)+1, 4,
                # end
                TERMINATOR
                )
    assert START_POS == len(buf)
    assert buf[START_POS-1] == b'\xff'
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
    w.put_byte(0) # zero terminate instance_name
    w.put_int(os.getpid()) # TODO: change this to thread id
    if IS_TDS72_PLUS(tds):
        # MARS (1 enabled)
        w.put_byte(0)
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
            tds.product_version = prod_version_struct.unpack_from(p, off)
        elif type == ENCRYPTION and l >= 1:
            crypt_flag, = byte_struct.unpack_from(p, off)
        elif type == MARS:
            tds.mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
        i += 5
    # we readed all packet
    logger.debug('detected flag %d', crypt_flag)
    # if server do not has certificate do normal login
    if crypt_flag == 2:
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise Error('Server required encryption but it is not supported')
        return tds7_send_login(tds, login)
    tds_set_s(tds, ssl.wrap_socket(tds._sock, ssl_version=ssl.PROTOCOL_SSLv3))
    return tds7_send_login(tds, login)
