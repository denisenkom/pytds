import logging
from tds import *

logger = logging.getLogger(__name__)

iconv_aliases = [
        {'alias': 'cp1251', 'canonic': TDS_CHARSET_CP1251},
        {'alias': 'iso_1', 'canonic': TDS_CHARSET_CP1251},
        ]

canonic_charsets = {
        TDS_CHARSET_ISO_8859_1: {'name': 'ISO8859'},
        TDS_CHARSET_CP1251: {'name': 'cp1251'},
        }

# change singlebyte conversions according to server
def tds_srv_charset_changed_num(tds, canonic_charset_num):
    char_conv = tds.char_convs[client2server_chardata]

    if IS_TDS7_PLUS(tds) and canonic_charset_num == TDS_CHARSET_ISO_8859_1:
        canonic_charset_num = TDS_CHARSET_CP1252

    logger.debug("setting server single-byte charset to \"{0}\"\n".format(canonic_charsets[canonic_charset_num]['name']))

    if canonic_charset_num == char_conv['server_charset']['canonic']:
        return

    # find and set conversion
    char_conv = tds_iconv_get_info(tds, tds.char_convs[client2ucs2]['client_charset']['canonic'], canonic_charset_num)
    if char_conv:
        tds.char_convs[client2server_chardata] = char_conv

    # if sybase change also server conversions
    if IS_TDS7_PLUS(tds):
        return

    char_conv = tds.char_convs[iso2server_metadata]

    tds_iconv_info_close(char_conv)

    tds_iconv_info_init(char_conv, TDS_CHARSET_ISO_8859_1, canonic_charset_num)

def tds_srv_charset_changed(tds, charset):
    n = tds_canonical_charset(charset)

    # ignore request to change to unknown charset
    if n < 0:
        logger.error("tds_srv_charset_changed: what is charset \"{0}\"?\n".format(charset))
        return

    tds_srv_charset_changed_num(tds, n)

def lookup_canonic(aliases, charset_name):
    for alias in aliases:
        if charset_name == alias['alias']:
            return alias['canonic']
    return -1

#
# Determine canonical iconv character set.
# \returns canonical position, or -1 if lookup failed.
# \remarks Returned name can be used in bytes_per_char(), above.
#
def tds_canonical_charset(charset_name):
    # search in alternative
    res = lookup_canonic(iconv_aliases, charset_name)
    if res >= 0:
        return res

    # search in sybase
    return lookup_canonic(sybase_aliases, charset_name)

# Get a iconv info structure, allocate and initialize if needed
def tds_iconv_get_info(tds, canonic_client, canonic_server):
    # search a charset from already allocated charsets
    i = len(tds.char_convs) - 1
    while i >= initial_char_conv_count:
        if canonic_client == tds.char_convs[i]['client_charset']['canonic']\
            and canonic_server == tds.char_convs[i]['server_charset']['canonic']:
                return tds.char_convs[i]
        i -= 1

    # allocate a new iconv structure
    new_id = len(tds.char_convs)
    tds.char_convs[new_id] = {}

    # init
    if tds_iconv_info_init(tds.char_convs[new_id], canonic_client, canonic_server):
        return tds.char_convs[new_id]

    tds_iconv_info_close(tds.char_convs[new_id])
    del tds.char_convs[new_id]
    return None

def tds_iconv_alloc(tds):
    tds.char_convs = {
            client2ucs2: {
                'server_charset': {'canonic': TDS_CHARSET_UCS_2LE, 'name': 'utf16'},
                'client_charset': {'canonic': TDS_CHARSET_UNICODE, 'name': 'unicode'},
                'from_wire': lambda buf: buf.decode('utf16'),
                'from_wire2': None,
                'flags': 0,
                },
            client2server_chardata: {
                'server_charset': {'canonic': TDS_CHARSET_CP1251, 'name': 'cp1251'},
                'client_charset': {'canonic': TDS_CHARSET_UNICODE, 'name': 'unicode'},
                'from_wire': lambda buf: buf.decode('cp1251'),
                'from_wire2': None,
                'flags': 0,
                },
            iso2server_metadata: {},
            }

def tds_iconv(tds, conv, io, inbuf):
    if io == to_server:
        cd = conv['to_wire']
        cd2 = conv['to_wire2']
    elif io == to_client:
        cd = conv['from_wire']
        cd2 = conv['from_wire2']
    else:
        assert io == to_server or io == to_client

    # silly case, memcpy
    if conv['flags'] & TDS_ENCODING_MEMCPY:
        return inbuf

    if conv['flags'] & TDS_ENCODING_INDIRECT:
        tmp = tds_sys_iconv(cd, inbuf)
        result = tds_sys_iconv(cd2, tmp)
    elif io == to_client and conv['flags'] & TDS_ENCODING_SWAPBYTE and inbuf:
        # swap bytes if necessary
        raise Exception('not implemented')
    else:
        result = tds_sys_iconv(cd, inbuf)

    # swap bytes if necessary
    if io == to_server and conv['flags'] & TDS_ENCODING_SWAPBYTE:
        raise Exception('not implemented')

    return result

def tds_sys_iconv(conv, buf):
    return conv(buf)
