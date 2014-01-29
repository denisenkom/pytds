# Flags returned in TDS_DONE token
TDS_DONE_FINAL = 0
TDS_DONE_MORE_RESULTS = 0x01  # more results follow
TDS_DONE_ERROR = 0x02  # error occurred
TDS_DONE_INXACT = 0x04  # transaction in progress
TDS_DONE_PROC = 0x08  # results are from a stored procedure
TDS_DONE_COUNT = 0x10  # count field in packet is valid
TDS_DONE_CANCELLED = 0x20  # acknowledging an attention command (usually a cancel)
TDS_DONE_EVENT = 0x40  # part of an event notification.
TDS_DONE_SRVERROR = 0x100  # SQL server server error


class TokDone(object):
    def __init__(self, token_id, status, cur_cmd, rows_affected):
        self.token_id = token_id
        self.status = status
        self.cur_cmd = cur_cmd
        self.rows_affected = rows_affected

    def is_more(self):
        return bool(self.status & TDS_DONE_MORE_RESULTS)


def parse_done72(r, token_id):
    status = r.get_usmallint()
    cur_cmd = r.get_usmallint()
    rows_affected = r.get_int8()
    return TokDone(token_id, status, cur_cmd, rows_affected)


def parse_done(r, token_id):
    status = r.get_usmallint()
    cur_cmd = r.get_usmallint()
    rows_affected = r.get_int()
    return TokDone(token_id, status, cur_cmd, rows_affected)


class TokEnvChange(object):
    def __init__(self, token_id)


def parse_env_chg(r, token_id):
    size = r.get_smallint()
    type = r.get_byte()
    if type == TDS_ENV_SQLCOLLATION:
        size = r.get_byte()
        self.conn.collation = r.get_collation()
        skipall(r, size - 5)
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
