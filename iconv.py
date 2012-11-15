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

# change singlebyte conversions according to server
def tds7_srv_charset_changed(tds, sql_collate, lcid):
    tds_srv_charset_changed_num(tds, collate2charset(sql_collate, lcid))

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

def collate2charset(sql_collate, lcid):
    #
    # The table from the MSQLServer reference "Windows Collation Designators" 
    # and from " NLS Information for Microsoft Windows XP"
    #

    cp = 0

    if sql_collate in (30, # SQL_Latin1_General_CP437_BIN
                       31,		# SQL_Latin1_General_CP437_CS_AS */
                       32,		# SQL_Latin1_General_CP437_CI_AS */
                       33,		# SQL_Latin1_General_Pref_CP437_CI_AS */
                       34):	# SQL_Latin1_General_CP437_CI_AI */
        return TDS_CHARSET_CP437
    elif sql_collate in (40, # SQL_Latin1_General_CP850_BIN */
                         41,		# SQL_Latin1_General_CP850_CS_AS */
                         42,		# SQL_Latin1_General_CP850_CI_AS */
                         43,		# SQL_Latin1_General_Pref_CP850_CI_AS */
                         44,		# SQL_Latin1_General_CP850_CI_AI */
                         49,		# SQL_1xCompat_CP850_CI_AS */
                         55,		# SQL_AltDiction_CP850_CS_AS */
                         56,		# SQL_AltDiction_Pref_CP850_CI_AS */
                         57,		# SQL_AltDiction_CP850_CI_AI */
                         58,		# SQL_Scandinavian_Pref_CP850_CI_AS */
                         59,		# SQL_Scandinavian_CP850_CS_AS */
                         60,		# SQL_Scandinavian_CP850_CI_AS */
                         61):	# SQL_AltDiction_CP850_CI_AS */
        return TDS_CHARSET_CP850
    elif sql_collate in (80, # SQL_Latin1_General_1250_BIN */
                         81,		# SQL_Latin1_General_CP1250_CS_AS */
                         82):	# SQL_Latin1_General_CP1250_CI_AS */
        return TDS_CHARSET_CP1250
    elif sql_collate in (105, # SQL_Latin1_General_CP1251_CS_AS */
                         106):		# SQL_Latin1_General_CP1251_CI_AS */
        return TDS_CHARSET_CP1251
    elif sql_collate in (113, # SQL_Latin1_General_CP1253_CS_AS */
                         114,		# SQL_Latin1_General_CP1253_CI_AS */
                         120,		# SQL_MixDiction_CP1253_CS_AS */
                         121,		# SQL_AltDiction_CP1253_CS_AS */
                         122,		# SQL_AltDiction2_CP1253_CS_AS */
                         124):		# SQL_Latin1_General_CP1253_CI_AI */
        return TDS_CHARSET_CP1253
    elif sql_collate in (137, # SQL_Latin1_General_CP1255_CS_AS */
                         138):		# SQL_Latin1_General_CP1255_CI_AS */
        return TDS_CHARSET_CP1255
    elif sql_collate in (145, # SQL_Latin1_General_CP1256_CS_AS */
                         146):		# SQL_Latin1_General_CP1256_CI_AS */
        return TDS_CHARSET_CP1256
    elif sql_collate in (153, # SQL_Latin1_General_CP1257_CS_AS */
                         154):		# SQL_Latin1_General_CP1257_CI_AS */
        return TDS_CHARSET_CP1257

    lcid = lcid & 0xffff
    if lcid in (0x405,
                0x40e,		#/* 0x1040e */
                0x415,
                0x418,
                0x41a,
                0x41b,
                0x41c,
                0x424,
                # case 0x81a: seem wrong in XP table TODO check
                0x104e):
                    cp = TDS_CHARSET_CP1250;
    elif lcid in (0x402,
                  0x419,
                  0x422,
                  0x423,
                  0x42f,
                  0x43f,
                  0x440,
                  0x444,
                  0x450,
                  0x81a, # ??
                  0x82c,
                  0x843,
                  0xc1a):
                    cp = TDS_CHARSET_CP1251;
    else:
        raise Exception('not implemented')
    #case 0x1007:
    #case 0x1009:
    #case 0x100a:
    #case 0x100c:
    #case 0x1407:
    #case 0x1409:
    #case 0x140a:
    #case 0x140c:
    #case 0x1809:
    #case 0x180a:
    #case 0x180c:
    #case 0x1c09:
    #case 0x1c0a:
    #case 0x2009:
    #case 0x200a:
    #case 0x2409:
    #case 0x240a:
    #case 0x2809:
    #case 0x280a:
    #case 0x2c09:
    #case 0x2c0a:
    #case 0x3009:
    #case 0x300a:
    #case 0x3409:
    #case 0x340a:
    #case 0x380a:
    #case 0x3c0a:
    #case 0x400a:
    #case 0x403:
    #case 0x406:
    #case 0x407:		/* 0x10407 */
    #case 0x409:
    #case 0x40a:
    #case 0x40b:
    #case 0x40c:
    #case 0x40f:
    #case 0x410:
    #case 0x413:
    #case 0x414:
    #case 0x416:
    #case 0x41d:
    #case 0x421:
    #case 0x42d:
    #case 0x436:
    #case 0x437:		/* 0x10437 */
    #case 0x438:
    #        /*case 0x439:  ??? Unicode only */
    #case 0x43e:
    #case 0x440a:
    #case 0x441:
    #case 0x456:
    #case 0x480a:
    #case 0x4c0a:
    #case 0x500a:
    #case 0x807:
    #case 0x809:
    #case 0x80a:
    #case 0x80c:
    #case 0x810:
    #case 0x813:
    #case 0x814:
    #case 0x816:
    #case 0x81d:
    #case 0x83e:
    #case 0xc07:
    #case 0xc09:
    #case 0xc0a:
    #case 0xc0c:
    #        cp = TDS_CHARSET_CP1252;
    #        break;
    #case 0x408:
    #        cp = TDS_CHARSET_CP1253;
    #        break;
    #case 0x41f:
    #case 0x42c:
    #case 0x443:
    #        cp = TDS_CHARSET_CP1254;
    #        break;
    #case 0x40d:
    #        cp = TDS_CHARSET_CP1255;
    #        break;
    #case 0x1001:
    #case 0x1401:
    #case 0x1801:
    #case 0x1c01:
    #case 0x2001:
    #case 0x2401:
    #case 0x2801:
    #case 0x2c01:
    #case 0x3001:
    #case 0x3401:
    #case 0x3801:
    #case 0x3c01:
    #case 0x4001:
    #case 0x401:
    #case 0x420:
    #case 0x429:
    #case 0x801:
    #case 0xc01:
    #        cp = TDS_CHARSET_CP1256;
    #        break;
    #case 0x425:
    #case 0x426:
    #case 0x427:
    #case 0x827:		/* ?? */
    #        cp = TDS_CHARSET_CP1257;
    #        break;
    #case 0x42a:
    #        cp = TDS_CHARSET_CP1258;
    #        break;
    #case 0x41e:
    #        cp = TDS_CHARSET_CP874;
    #        break;
    #case 0x411:		/* 0x10411 */
    #        cp = TDS_CHARSET_CP932;
    #        break;
    #case 0x1004:
    #case 0x804:		/* 0x20804 */
    #        cp = TDS_CHARSET_CP936;
    #        break;
    #case 0x412:		/* 0x10412 */
    #        cp = TDS_CHARSET_CP949;
    #        break;
    #case 0x1404:
    #case 0x404:		/* 0x30404 */
    #case 0xc04:
    #        cp = TDS_CHARSET_CP950;
    #        break;
    #default:
    #        cp = TDS_CHARSET_CP1252;
    #}

    return cp

def tds_iconv_from_collate(tds, collate):
    sql_collate = ord(collate[4])
    lcid = ord(collate[1]) * 256 + ord(collate[0])
    canonic_charset = collate2charset(sql_collate, lcid)

    # same as client (usually this is true, so this improve performance) ?
    if tds.char_convs[client2server_chardata]['server_charset']['canonic'] == canonic_charset:
        return tds.char_convs[client2server_chardata]

    return tds_iconv_get_info(tds, tds.char_convs[client2ucs2]['client_charset']['canonic'], canonic_charset)
