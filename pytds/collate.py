import struct

TDS_CHARSET_ISO_8859_1  = 1
TDS_CHARSET_CP1251      = 2
TDS_CHARSET_CP1252      = 3
TDS_CHARSET_UCS_2LE     = 4

TDS_CHARSET_UNICODE     = 5

class Collation(object):
    _coll_struct = struct.Struct('<LB')
    wire_size = _coll_struct.size
    f_ignore_case = 0x100000
    f_ignore_accent = 0x200000
    f_ignore_width = 0x400000
    f_ignore_kana = 0x800000
    f_binary = 0x1000000
    f_binary2 = 0x2000000

    def __init__(self, lcid, sort_id, ignore_case,
            ignore_accent, ignore_width,
            ignore_kana, binary, binary2,
            version):
        self.lcid = lcid
        self.sort_id = sort_id
        self.ignore_case = ignore_case
        self.ignore_accent = ignore_accent
        self.ignore_width = ignore_width
        self.ignore_kana = ignore_kana
        self.binary = binary
        self.binary2 = binary2
        self.version = version

    @classmethod
    def unpack(cls, b):
        lump, sort_id = cls._coll_struct.unpack_from(b)
        lcid = lump & 0xfffff
        ignore_case = bool(lump & cls.f_ignore_case)
        ignore_accent = bool(lump & cls.f_ignore_accent)
        ignore_width = bool(lump & cls.f_ignore_width)
        ignore_kana = bool(lump & cls.f_ignore_kana)
        binary = bool(lump & cls.f_binary)
        binary2 = bool(lump & cls.f_binary2)
        version = (lump & 0xf0000000) >> 26
        return cls(lcid=lcid, ignore_case=ignore_case,
                ignore_accent=ignore_accent,
                ignore_width=ignore_width,
                ignore_kana=ignore_kana,
                binary=binary,
                binary2=binary2,
                version=version,
                sort_id=sort_id)

    def pack(self):
        lump = 0
        lump |= self.lcid & 0xfffff
        lump |= (self.version << 26) & 0xf0000000
        if self.ignore_case: lump |= self.f_ignore_case
        if self.ignore_accent: lump |= self.f_ignore_accent
        if self.ignore_width: lump |= self.f_ignore_width
        if self.ignore_kana: lump |= self.f_ignore_kana
        if self.binary: lump |= self.f_binary
        if self.binary2: lump |= self.f_binary2
        return self._coll_struct.pack(lump, self.sort_id)

    def get_charset(self):
        sql_collate = self.sort_id
        lcid = self.lcid
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
        elif lcid in (0x1007,
                    0x1009,
                    0x100a,
                    0x100c,
                    0x1407,
                    0x1409,
                    0x140a,
                    0x140c,
                    0x1809,
                    0x180a,
                    0x180c,
                    0x1c09,
                    0x1c0a,
                    0x2009,
                    0x200a,
                    0x2409,
                    0x240a,
                    0x2809,
                    0x280a,
                    0x2c09,
                    0x2c0a,
                    0x3009,
                    0x300a,
                    0x3409,
                    0x340a,
                    0x380a,
                    0x3c0a,
                    0x400a,
                    0x403,
                    0x406,
                    0x407,		#/* 0x10407 */
                    0x409,
                    0x40a,
                    0x40b,
                    0x40c,
                    0x40f,
                    0x410,
                    0x413,
                    0x414,
                    0x416,
                    0x41d,
                    0x421,
                    0x42d,
                    0x436,
                    0x437,		#/* 0x10437 */
                    0x438,
                        #case 0x439:  ??? Unicode only
                    0x43e,
                    0x440a,
                    0x441,
                    0x456,
                    0x480a,
                    0x4c0a,
                    0x500a,
                    0x807,
                    0x809,
                    0x80a,
                    0x80c,
                    0x810,
                    0x813,
                    0x814,
                    0x816,
                    0x81d,
                    0x83e,
                    0xc07,
                    0xc09,
                    0xc0a,
                    0xc0c):
                cp = TDS_CHARSET_CP1252;
        else:
            raise Exception('not implemented')
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

    def get_iconv(self, tds):
        from iconv import tds_iconv_from_collate
        return tds_iconv_from_collate(tds, self)

    #TODO: define __repr__ and __unicode__
