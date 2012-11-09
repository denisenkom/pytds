import net
import struct
import os
import logging

logger = logging.getLogger(__name__)

class TdsError(Exception):
    pass

def tds_connect(ip_addr, port=1344, database=None, user=None, password=None, connect_timeout=None, query_timeout=None, instance_name=None, tds_version=0x703, text_size=None):
    tds = net.tds_open_socket(ip_addr, port, connect_timeout)
    tds.tds_version = tds_version
    tds.query_timeout = query_timeout
    tds_set_state(tds, TDS_IDLE)
    db_selected = False
    if tds_version >= 0x701:
        tds71_do_login(tds)
        db_selected = True
    elif tds_version >= 0x700:
        tds7_send_login(tds)
        db_selected = True
    else:
        tds.out_flag = TDS_LOGIN
        tds_send_login(tds)
    if text_size or not db_selected and database:
        q = []
        if text_size:
            q.append('set textsize {0}'.format(int(text_size)))
        if not db_selected and database:
            q.append('use ' + tds_quote_id(tds, database))
        tds_submit_query(tds, ''.join(q))
        tds_process_simple_query(tds)
    return tds

def tds7_send_login(tds, user_name, password, client_host_name, app_name, server_name, library, language, database):
    tds.authentication = None
    if len(password) > 128:
        password = password[:128]


def tds71_do_login(tds, **kwargs):
    instance_name = kwargs.pop('instance_name', 'MSSQLServer')
    encryption_level = kwargs.pop('encryption_level', 0)
    if tds.tds_version < 0x702:
        START_POS = 21
        buf = struct.pack('>BHHBHHBHHBHHBHHB',
                #netlib version
                0, START_POS, 6,
                #encryption
                1, START_POS + 6, 1,
                #instance
                2, START_POS + 6 + 1, len(instance_name),
                # process id
                3, START_POS + 6 + 1 + len(instance_name), 4,
                # end
                0xff
                )

    else:
        START_POS = 26
        buf = struct.pack('>BHHBHHBHHBHHBHHB',
                #netlib version
                0, START_POS, 6,
                #encryption
                1, START_POS + 6, 1,
                #instance
                2, START_POS + 6 + 1, len(instance_name),
                # process id
                3, START_POS + 6 + 1 + len(instance_name), 4,
                # MARS enabled
                4, START_POS + 6 + 1 + len(instance_name) + 4, 1,
                # end
                0xff
                )
    assert START_POS >= 21 and START_POS <= len(buf)
    assert buf[START_POS-1] == 0xff
    tds.out_flag = TDS71_PRELOGIN
    tds_put(tds, buf)
    netlib8 = '\x08\x00\x01\0x55\0x00\0x00'
    netlib9 = '\x09\x00\x00\0x00\0x00\0x00'
    tds_put(tds, netlib9 if tds.tds_version >= 0x702 else netlib8)
    # encryption
    if True:
        # not supported
        tds_put_byte(tds, 2)
    else:
        tds_put_byte(tds, 1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
    tds_put(tds, instance_name.encode('ascii'))
    tds_put_int(tds, os.getpid())
    if tds.tds_version >= 0x702:
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
        off, l = struct.unpack('>HH')
        if off > size or off + l > size:
            raise TdsError(TDS_FAIL)
        if type == 1 and l >= 1:
            crypt_flag = p[off]
    # we readed all packet
    tds.in_pos += size
    logger.debug('detected flag %d', crypt_flag)
    # if server do not has certificate do normal login
    if crypt_flag == 2:
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise TdsError(TDS_FAIL)
        return tds7_send_login(tds, **kwargs)
    raise Exception('encryption is not supported yet')
