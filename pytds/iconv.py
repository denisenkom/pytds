import codecs
import logging
from tds import *
from collate import *

logger = logging.getLogger(__name__)

iconv_aliases = [
        {'alias': 'cp1251', 'canonic': TDS_CHARSET_CP1251},
        {'alias': 'iso_1', 'canonic': TDS_CHARSET_CP1251},
        ]

canonic_charsets = {
        TDS_CHARSET_ISO_8859_1: {'name': 'ISO8859', 'canonic': TDS_CHARSET_ISO_8859_1},
        TDS_CHARSET_CP1251: {'name': 'cp1251', 'canonic': TDS_CHARSET_CP1251},
        TDS_CHARSET_CP1252: {'name': 'cp1252', 'canonic': TDS_CHARSET_CP1252},
        TDS_CHARSET_UNICODE: {'name': 'unicode', 'canonic': TDS_CHARSET_UNICODE},
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

# change singlebyte conversions according to server
def tds7_srv_charset_changed(tds, collation):
    tds_srv_charset_changed_num(tds, collation.get_charset())

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
    assert canonic_client == TDS_CHARSET_UNICODE
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

_utf16_le_codec = codecs.lookup('utf_16_le')
_cp1251_codec = codecs.lookup('cp1251')

def tds_iconv_alloc(tds):
    tds.char_convs = {
            client2ucs2: {
                'server_charset': {'canonic': TDS_CHARSET_UCS_2LE, 'name': 'utf_16_le'},
                'client_charset': {'canonic': TDS_CHARSET_UNICODE, 'name': 'unicode'},
                'from_wire': lambda buf: _utf16_le_codec.decode(buf)[0],
                'from_wire2': None,
                'to_wire': lambda s: _utf16_le_codec.encode(s)[0],
                'codec': _utf16_le_codec,
                'flags': 0,
                },
            client2server_chardata: {
                'server_charset': {'canonic': TDS_CHARSET_CP1251, 'name': 'cp1251'},
                'client_charset': {'canonic': TDS_CHARSET_UNICODE, 'name': 'unicode'},
                'from_wire': lambda buf: _cp1251_codec.decode(buf)[0],
                'from_wire2': None,
                'codec': _cp1251_codec,
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

def tds_iconv_from_collate(tds, collate):
    canonic_charset = collate.get_charset()

    # same as client (usually this is true, so this improve performance) ?
    if tds.char_convs[client2server_chardata]['server_charset']['canonic'] == canonic_charset:
        return tds.char_convs[client2server_chardata]

    return tds_iconv_get_info(tds, tds.char_convs[client2ucs2]['client_charset']['canonic'], canonic_charset)

#
# Open iconv descriptors to convert between character sets (both directions).
# 1.  Look up the canonical names of the character sets.
# 2.  Look up their widths.
# 3.  Ask iconv to open a conversion descriptor.
# 4.  Fail if any of the above offer any resistance.  
# \remarks The charset names written to \a iconv will be the canonical names, 
#          not necessarily the names passed in. 
#
def tds_iconv_info_init(char_conv, client_canonical, server_canonical):
    assert client_canonical == TDS_CHARSET_UNICODE
    assert 'to_wire' not in char_conv
    assert 'to_wire2' not in char_conv
    assert 'from_wire' not in char_conv
    assert 'from_wire2' not in char_conv

    if client_canonical < 0:
        logger.debug("tds_iconv_info_init: client charset name \"%d\" invalid", client_canonical)
        return False

    if server_canonical < 0:
        logger.debug("tds_iconv_info_init: server charset name \"%d\" invalid", server_canonical)
        return False

    char_conv['client_charset'] = canonic_charsets[client_canonical]
    char_conv['server_charset'] = canonic_charsets[server_canonical]

    # special case, same charset, no conversion
    if client_canonical == server_canonical:
        char_conv['to_wire'] = -1
        char_conv['from_wire'] = -1
        char_conv['flags'] = TDS_ENCODING_MEMCPY
        return True

    char_conv['flags'] = 0
    char_conv['codec'] = codec = codecs.lookup(char_conv['server_charset']['name'])
    char_conv['from_wire'] = lambda buf: codec.decode(buf)[0]
    char_conv['from_wire2'] = -1
    char_conv['to_wire'] = lambda buf: codec.encode(buf)[0]
    char_conv['to_wire2'] = -1
    return True

    #if not iconv_names[server_canonical]:
    #    if server_canonical == POS_UCS2LE:
    #        server_canonical = POS_UCS2BE
    #        char_conv['flags'] = TDS_ENCODING_SWAPBYTE
    #    elif server_canonical == POS_UCS2BE:
    #        server_canonical = POS_UCS2LE
    #        char_conv['flags'] = TDS_ENCODING_SWAPBYTE

    ## get iconv names
    #if not iconv_names[client_canonical]:
    #    if not tds_set_iconv_name(client_canonical):
    #        logger.debug("Charset %d not supported by iconv, using \"%s\" instead", client_canonical, iconv_names[client_canonical])
    #if not iconv_names[server_canonical]:
    #    if not tds_set_iconv_name(server_canonical):
    #        logger.debug("Charset %d not supported by iconv, using \"%s\" instead", server_canonical, iconv_names[server_canonical])

    #char_conv['to_wire'] = tds_sys_iconv_open(iconv_names[server_canonical], iconv_names[client_canonical])
    #if char_conv['to_wire'] == -1:
    #    logger.debug("tds_iconv_info_init: cannot convert \"%s\"->\"%s\"", client['name'], server['name'])

    #char_conv['from_wire'] = tds_sys_iconv_open(iconv_names[client_canonical], iconv_names[server_canonical])
    #if char_conv['from_wire'] == -1:
    #    logger.debug("tds_iconv_info_init: cannot convert \"%s\"->\"%s\"\n", server['name'], client['name'])

    ## try indirect conversions
    #if char_conv['to_wire'] == -1 or char_conv['from_wire'] == -1:
    #    tds_iconv_info_close(char_conv);

    #    # TODO reuse some conversion, client charset is usually constant in all connection (or ISO8859-1)
    #    char_conv['to_wire'] = tds_sys_iconv_open(iconv_names[POS_UTF8], iconv_names[client_canonical])
    #    char_conv['to_wire2'] = tds_sys_iconv_open(iconv_names[server_canonical], iconv_names[POS_UTF8])
    #    char_conv['from_wire'] = tds_sys_iconv_open(iconv_names[POS_UTF8], iconv_names[server_canonical])
    #    char_conv['from_wire2'] = tds_sys_iconv_open(iconv_names[client_canonical], iconv_names[POS_UTF8])

    #    if char_conv['to_wire'] == -1 or char_conv['to_wire2'] == -1 or char_conv['from_wire'] == -1 or char_conv['from_wire2'] == -1:
    #        tds_iconv_info_close(char_conv)
    #        logger.debug("tds_iconv_info_init: cannot convert \"%s\"->\"%s\" indirectly", server['name'], client['name'])
    #        return 0

    #    char_conv['flags'] |= TDS_ENCODING_INDIRECT
    ## TODO, do some optimizations like UCS2 -> UTF8 min,max = 2,2 (UCS2) and 1,4 (UTF8)
    ## tdsdump_log(TDS_DBG_FUNC, "tds_iconv_info_init: converting \"%s\"->\"%s\"\n", client->name, server->name)
    #return 1
