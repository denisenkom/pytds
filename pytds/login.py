# vim: set fileencoding=utf8 :
import struct
import os
import logging
ENCRYPTION_ENABLED = False
encryption_supported = False
try:
    import ssl
    encryption_supported = True
except:
    pass
from tdsproto import *
from write import *
from tds import *
from util import *
from net import *
from token import *

logger = logging.getLogger(__name__)

class TdsError(Exception):
    pass

#
# \brief Set the servername in a TDSLOGIN structure
#
# Normally copies \a server into \a tds_login.  If \a server does not point to a plausible name, the environment 
# variables TDSQUERY and DSQUERY are used, in that order.  If they don't exist, the "default default" servername
# is "SYBASE" (although the utility of that choice is a bit murky).  
#
# \param tds_login  points to a TDSLOGIN structure
# \param server the servername, or NULL, or a zero-length string
# \todo open the log file earlier, so these messages can be seen.  
#
def tds_set_server(tds_login, server):
    if server:
        tds_login.server_name = server


# additional args: app_name, server_name, client_host_name, text_size, tds_version
# instance_name, encryption, block_size, bulk_copy, option_flag2
# connect_timeout, query_timeout
def tds_connect(tds, login):
    tds.login = login
    tds.tds_version = login.tds_version
    tds_conn(tds).emul_little_endian = login.emul_little_endian
    if IS_TDS7_PLUS(tds):
        # TDS 7/8 only supports little endian
        tds_conn(tds).emul_little_endian = True
    if not IS_TDS50(tds) and login.instance_name and not login.port:
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
            raise Exception('This TDS version is not supported')
            tds.out_flag = TDS_LOGIN
            tds_send_login(tds, login)
        if not tds_process_login_tokens(tds):
            raise LoginError("Cannot connect to server '{0}' as user '{1}'".format(login.server_name, login.user_name))
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

def tds7_send_login(tds, login):
    option_flag2 = login.option_flag2
    user_name = login.user_name
    tds.out_flag = TDS7_LOGIN
    tds.authentication = None
    if len(login.password) > 128:
        login.password = login.password[:128]
    current_pos = 86 + 8 if IS_TDS72_PLUS(tds) else 86
    client_host_name = login.client_host_name or this_host_name
    packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) + len(login.library) + len(login.language) + len(login.database))*2
    auth_len = 0
    if False:
        if user_name.find('\\') != -1 or not user_name:
            raise Exception('sspi not implemented')
    else:
        if user_name.find('\\') != -1:
            raise Exception('ntlm not implemented')
        elif not user_name:
            raise Exception('requested GSS authentication but it is not implemented')
        else:
            packet_size += (len(user_name) + len(login.password))*2
    tds_put_int(tds, packet_size)
    tds_put_uint(tds, login.tds_version)
    block_size = 4096
    if login.block_size < 512 or 1000000 < login.block_size:
        block_size = login.block_size
    tds_put_int(tds, block_size)
    tds_put_s(tds, b'\x06\x83\xf2\xf8') # client progver
    tds_put_int(tds, os.getpid())
    tds_put_s(tds, b'\x00\x00\x00\x00') # connection_id
    option_flag1 = TDS_SET_LANG_ON | TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL
    if not login.bulk_copy:
        option_flag1 |= TDS_DUMPLOAD_OFF
    tds_put_byte(tds, option_flag1)
    if False:
        if tds.authentication:
            option_flag2 |= TDS_INTEGRATED_SECURITY_ON
    tds_put_byte(tds, option_flag2)
    tds_put_byte(tds, 0) # sql_type_flag
    option_flag3 = TDS_UNKNOWN_COLLATION_HANDLING
    tds_put_byte(tds, option_flag3 if IS_TDS73_PLUS(tds) else 0)
    tds_put_s(tds, b'\x88\xff\xff\xff') # time zone
    tds_put_s(tds, b'\x36\x04\x00\x00') # time zone
    tds_put_smallint(tds, current_pos)
    tds_put_smallint(tds, len(client_host_name))
    current_pos += len(client_host_name) * 2
    if tds.authentication:
        tds_put_smallint(tds, 0)
        tds_put_smallint(tds, 0)
        tds_put_smallint(tds, 0)
        tds_put_smallint(tds, 0)
    else:
        tds_put_smallint(tds, current_pos)
        tds_put_smallint(tds, len(user_name))
        current_pos += len(user_name) * 2
        tds_put_smallint(tds, current_pos)
        tds_put_smallint(tds, len(login.password))
        current_pos += len(login.password) * 2
    tds_put_smallint(tds, current_pos)
    tds_put_smallint(tds, len(login.app_name))
    current_pos += len(login.app_name) * 2
    # server name
    TDS_PUT_SMALLINT(tds, current_pos);
    TDS_PUT_SMALLINT(tds, len(login.server_name))
    current_pos += len(login.server_name) * 2
    # unknown
    tds_put_smallint(tds, 0)
    tds_put_smallint(tds, 0)
    # library name
    TDS_PUT_SMALLINT(tds, current_pos)
    TDS_PUT_SMALLINT(tds, len(login.library))
    current_pos += len(login.library) * 2
    # language  - kostya@warmcat.excom.spb.su
    TDS_PUT_SMALLINT(tds, current_pos);
    TDS_PUT_SMALLINT(tds, len(login.language));
    current_pos += len(login.language) * 2;
    # database name
    TDS_PUT_SMALLINT(tds, current_pos);
    TDS_PUT_SMALLINT(tds, len(login.database));
    current_pos += len(login.database) * 2;
    import uuid
    tds_put_s(tds, struct.pack('>Q', uuid.getnode())[:6])
    # authentication
    tds_put_smallint(tds, current_pos)
    tds_put_smallint(tds, auth_len)
    current_pos += auth_len
    # db file
    tds_put_smallint(tds, current_pos)
    tds_put_smallint(tds, 0)
    if IS_TDS72_PLUS(tds):
        # new password
        tds_put_smallint(tds, current_pos)
        tds_put_smallint(tds, 0)
        # sspi long
        tds_put_int(tds, 0)
    tds_put_string(tds, client_host_name)
    if not tds.authentication:
        tds_put_string(tds, user_name)
        tds_put_s(tds, tds7_crypt_pass(login.password))
    tds_put_string(tds, login.app_name)
    tds_put_string(tds, login.server_name)
    tds_put_string(tds, login.library)
    tds_put_string(tds, login.language)
    tds_put_string(tds, login.database)
    if tds.authentication:
        tds_put_s(tds, tds.authentication.packet)
    tds_flush_packet(tds)
    #tdsdump_on()

def tds7_crypt_pass(password):
    encoded = bytearray(password.encode('utf16')[2:])
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
        buf = bytearray(struct.pack('>BHHBHHBHHBHHBHHB',
                #netlib version
                VERSION, START_POS, 6,
                #encryption
                ENCRYPTION, START_POS + 6, 1,
                #instance
                INSTOPT, START_POS + 6 + 1, len(instance_name)+1,
                # process id
                THREADID, START_POS + 6 + 1 + len(instance_name)+1, 4,
                # MARS enabled
                MARS, START_POS + 6 + 1 + len(instance_name)+1 + 4, 1,
                # end
                TERMINATOR
                ))
    else:
        START_POS = 21
        buf = bytearray(struct.pack('>BHHBHHBHHBHHB',
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
                ))
    assert START_POS == len(buf)
    assert buf[START_POS-1] == 0xff
    tds.out_flag = TDS71_PRELOGIN
    tds_put_s(tds, buf)
    netlib8 = b'\x08\x00\x01\x55\x00\x00'
    netlib9 = b'\x09\x00\x00\x00\x00\x00'
    tds_put_s(tds, netlib9 if IS_TDS72_PLUS(tds) else netlib8)
    # encryption
    if ENCRYPTION_ENABLED and encryption_supported:
        tds_put_byte(tds, 1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
    else:
        # not supported
        tds_put_byte(tds, 2)
    tds_put_s(tds, instance_name.encode('ascii'))
    tds_put_byte(tds, 0) # zero terminate instance_name
    tds_put_int(tds, os.getpid()) # TODO: change this to thread id
    if IS_TDS72_PLUS(tds):
        # MARS (1 enabled)
        tds_put_byte(tds, 0)
    tds_flush_packet(tds)
    size = tds_read_packet(tds)
    if size <= 0 or tds.in_flag != 4:
        raise TdsError(TDS_FAIL)
    size = tds.in_len - tds.in_pos
    # default 2, no certificate, no encryptption
    crypt_flag = 2
    p = tds.in_buf[tds.in_pos:]
    i = 0
    while True:
        if i >= size:
            raise TdsError(TDS_FAIL)
        type = p[i]
        if type == 0xff:
            break
        if i + 4 > size:
            raise TdsError(TDS_FAIL)
        off, l = struct.unpack('>HH', bytes(p[i+1:i+1+4]))
        if off > size or off + l > size:
            raise TdsError(TDS_FAIL)
        if type == VERSION:
            tds.product_version = struct.unpack_from('>LH', str(p), off)
        elif type == ENCRYPTION and l >= 1:
            crypt_flag = p[off]
        elif type == MARS:
            tds.mars_enabled = bool(p[off])
        i += 5
    # we readed all packet
    tds.in_pos += size
    logger.debug('detected flag %d', crypt_flag)
    # if server do not has certificate do normal login
    if crypt_flag == 2:
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise TdsError(TDS_FAIL)
        return tds7_send_login(tds, login)
    tds_set_s(ssl.wrap_socket(tds_get_s(tds), ssl_version=ssl.PROTOCOL_TLSv1))
    return tds7_send_login(tds, login)

def tds_connect_and_login(tds, login):
    return tds_connect(tds, login)
