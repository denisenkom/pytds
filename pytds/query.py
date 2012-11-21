from datetime import datetime
from write import *
from tds_checks import *
from tds import *
from util import *
from tdsproto import *
from net import *
from mem import _Column
from data import *

def START_QUERY(tds):
    if IS_TDS72_PLUS(tds):
        tds_start_query(tds)

tds72_query_start = str(bytearray([
    #/* total length */
    0x16, 0, 0, 0,
    #/* length */
    0x12, 0, 0, 0,
    #/* type */
    0x02, 0,
    #/* transaction */
    0, 0, 0, 0, 0, 0, 0, 0,
    #/* request count */
    1, 0, 0, 0]))

def tds_start_query(tds):
    tds_put_s(tds, tds72_query_start[:10])
    assert len(tds.tds72_transaction) == 8
    tds_put_s(tds, tds.tds72_transaction)
    assert len(tds72_query_start[10 + 8:]) == 4
    tds_put_s(tds, tds72_query_start[10 + 8:])

def tds_query_flush_packet(tds):
    # TODO depend on result ??
    tds_set_state(tds, TDS_PENDING)
    tds_flush_packet(tds)

def convert_params(tds, parameters):
    if isinstance(parameters, dict):
        return [make_param(tds, name, value) for name, value in parameters.items()]
    else:
        params = []
        for parameter in parameters:
            if type(parameter) is output:
                raise Exception('not implemented')
                #param_type = parameter.type
                #param_value = parameter.value
                #param_output = True
            elif isinstance(parameter, _Column):
                params.append(parameter)
            else:
                params.append(make_param('', parameter))
        return params

def make_param(tds, name, value, output=False):
    column = _Column()
    column.column_name = name
    column.column_output = 1 if output else 0
    if value is None:
        col_type = XSYBVARCHAR
        size = 1
        column.column_varint_size = tds_get_varint_size(tds, col_type)
    elif isinstance(value, int):
        if -2**31 <= value <= 2**31 -1:
            col_type = SYBINTN
            size = 4
        else:
            col_type = SYBINT8
            size = 8
        column.column_varint_size = tds_get_varint_size(tds, col_type)
    elif isinstance(value, float):
        col_type = SYBFLTN
        size = 8
        column.column_varint_size = tds_get_varint_size(tds, col_type)
    elif isinstance(value, (str, unicode)):
        if len(value) > 4000:
            if IS_TDS72_PLUS(tds):
                col_type = XSYBNVARCHAR
                column.column_varint_size = 8 # nvarchar(max)
            else:
                col_type = SYBNTEXT
                column.column_varint_size = tds_get_varint_size(tds, col_type)
        else:
            col_type = XSYBNVARCHAR
            column.column_varint_size = tds_get_varint_size(tds, col_type)
        size = len(value) * 2
        column.char_conv = tds.char_convs[client2ucs2]
    elif isinstance(value, datetime):
        col_type = SYBDATETIMN
        size = 8
        column.column_varint_size = tds_get_varint_size(tds, col_type)
    elif isinstance(value, Decimal):
        col_type = SYBDECIMAL
        _, digits, exp = value.as_tuple()
        size = 12
        column.column_scale = -exp
        column.column_prec = len(digits)
        column.column_varint_size = tds_get_varint_size(tds, col_type)
    else:
        raise Exception('NotSupportedError: Unable to determine database type')
    column.on_server.column_type = col_type
    column.column_size = column.on_server.column_size = size
    column.value = value
    column.funcs = tds_get_column_funcs(tds, col_type)
    return column

def tds_submit_rpc(tds, rpc_name, params=(), recompile=False):
    if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
        raise Exception('TDS_FAIL')
    try:
        tds.cur_dyn = None
        if IS_TDS7_PLUS(tds):
            tds.out_flag = TDS_RPC
            converted_name = tds_convert_string(tds, tds.char_convs[client2ucs2], rpc_name)
            START_QUERY(tds)
            TDS_PUT_SMALLINT(tds, len(converted_name)/2)
            tds_put_s(tds, converted_name)
            #
            # TODO support flags
            # bit 0 (1 as flag) in TDS7/TDS5 is "recompile"
            # bit 1 (2 as flag) in TDS7+ is "no metadata" bit 
            # (I don't know meaning of "no metadata")
            #
            flags = 0
            if recompile:
                flags |= 1
            tds_put_smallint(tds, flags)
            params = convert_params(tds, params)
            for param in params:
                column_type = param.on_server.column_type
                tds_put_data_info(tds, param)
                param.funcs.put_data(tds, param)
            tds_query_flush_packet(tds)
        elif IS_TDS50(tds):
            tds.out_flag = TDS_NORMAL
            tds_put_byte(tds, TDS_DBRPC_TOKEN)
            # TODO ICONV convert rpc name
            tds_put_smallint(tds, len(rpc_name) + 3)
            tds_put_byte(tds, len(rpc_name))
            tds_put_s(tds, rpc_name)
            # TODO flags
            tds_put_smallint(tds, 2 if params else 0)

            if params:
                tds_put_params(tds, params, TDS_PUT_DATA_USE_NAME)

            # send it
            tds_query_flush_packet(tds)
            # emulate it for TDS4.x, send RPC for mssql
            if not IS_TDS5_PLUS(tds):
                return tds_send_emulated_rpc(tds, rpc_name, params)
    except:
        tds_set_state(tds, TDS_IDLE)
        raise

#
# tds_submit_query() sends a language string to the database server for
# processing.  TDS 4.2 is a plain text message with a packet type of 0x01,
# TDS 7.0 is a unicode string with packet type 0x01, and TDS 5.0 uses a
# TDS_LANGUAGE_TOKEN to encapsulate the query and a packet type of 0x0f.
# \param tds state information for the socket and the TDS protocol
# \param query  language query to submit
# \param params parameters of query
# \return TDS_FAIL or TDS_SUCCESS
#
def tds_submit_query(tds, query, params=()):
    logger.info('tds_submit_query(%s, %s)', query, params)
    #size_t query_len;
    CHECK_TDS_EXTRA(tds)
    if params:
        CHECK_PARAMINFO_EXTRA(params)

    if not query:
        raise Exception('TDS_FAIL')

    if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
        raise Exception('TDS_FAIL')
    try:
        if IS_TDS50(tds):
            new_query = None
            # are there '?' style parameters ?
            if tds_next_placeholder(query):
                new_query = tds5_fix_dot_query(query, params)
                query = new_query

            tds.out_flag = TDS_NORMAL
            tds_put_byte(tds, TDS_LANGUAGE_TOKEN)
            # TODO ICONV use converted size, not input size and convert string
            TDS_PUT_INT(tds, len(query) + 1)
            tds_put_byte(tds, 1 if params else 0) # 1 if there are params, 0 otherwise
            tds_put_s(tds, query)
            if params:
                # add on parameters
                tds_put_params(tds, params, TDS_PUT_DATA_USE_NAME if params.columns[0].column_name else 0)
        elif not IS_TDS7_PLUS(tds) or not params:
            tds.out_flag = TDS_QUERY
            START_QUERY(tds)
            tds_put_string(tds, query)
        else:
            #TDSCOLUMN *param;
            #size_t definition_len;
            #int count, i;
            #char *param_definition;
            #size_t converted_query_len;
            #const char *converted_query;

            converted_query = tds_convert_string(tds, tds.char_convs[client2ucs2], query)
            count = tds_count_placeholders_ucs2le(converted_query)
            params = convert_params(tds, params)

            if count:
                #
                # TODO perhaps functions that calls tds7_build_param_def_from_query
                # should call also tds7_build_param_def_from_params ??
                #
                param_definition = tds7_build_param_def_from_query(tds, converted_query, params)
            else:
                param_definition = tds7_build_param_def_from_params(tds, converted_query, params)

            tds.out_flag = TDS_RPC
            START_QUERY(tds)
            # procedure name
            if IS_TDS71_PLUS(tds):
                tds_put_smallint(tds, -1)
                tds_put_smallint(tds, TDS_SP_EXECUTESQL)
            else:
                sp_name = 'sp_executesql'
                tds_put_smallint(tds, len(sp_name))
                tds_put_s(tds, tds.char_convs[client2ucs2]['to_wire'](sp_name))
            tds_put_smallint(tds, 0)

            # string with sql statement
            if count:
                tds7_put_query_params(tds, converted_query)
            else:
                tds_put_byte(tds, 0)
                tds_put_byte(tds, 0)
                tds_put_byte(tds, SYBNTEXT) # must be Ntype
                TDS_PUT_INT(tds, len(converted_query))
                if IS_TDS71_PLUS(tds):
                    tds_put_s(tds, tds.collation)
                TDS_PUT_INT(tds, len(converted_query))
                tds_put_s(tds, converted_query)
            # parameters definition
            tds7_put_params_definition(tds, param_definition)
            # parameter values
            for param in params:
                tds_put_data_info(tds, param)
                param.funcs.put_data(tds, param)
            tds.internal_sp_called = TDS_SP_EXECUTESQL
        tds_query_flush_packet(tds)
    except:
        tds_set_state(tds, TDS_IDLE)
        raise


#/**
# * tds_send_cancel() sends an empty packet (8 byte header only)
# * tds_process_cancel should be called directly after this.
# * \param tds state information for the socket and the TDS protocol
# * \remarks
# *	tcp will either deliver the packet or time out. 
# *	(TIME_WAIT determines how long it waits between retries.)  
# *	
# *	On sending the cancel, we may get EAGAIN.  We then select(2) until we know
# *	either 1) it succeeded or 2) it didn't.  On failure, close the socket,
# *	tell the app, and fail the function.  
# *	
# *	On success, we read(2) and wait for a reply with select(2).  If we get
# *	one, great.  If the client's timeout expires, we tell him, but all we can
# *	do is wait some more or give up and close the connection.  If he tells us
# *	to cancel again, we wait some more.  
# */
def tds_send_cancel(tds):
    #TDSRET rc;
    if TDS_MUTEX_TRYLOCK(tds.wire_mtx):
        # TODO check
        # signal other socket
        raise Exception('not implemented')
        #tds_conn(tds).s_signal.send((void*) &tds, sizeof(tds))
        return TDS_SUCCESS

    CHECK_TDS_EXTRA(tds);

    logger.debug("tds_send_cancel: %sin_cancel and %sidle".format(
                            ('' if tds.in_cancel else "not "), ('' if tds.state == TDS_IDLE else "not ")))

    # one cancel is sufficient
    if tds.in_cancel or tds.state == TDS_IDLE:
        TDS_MUTEX_UNLOCK(tds.wire_mtx)
        return TDS_SUCCESS

    rc = tds_put_cancel(tds)
    TDS_MUTEX_UNLOCK(tds.wire_mtx)

    return rc

#
# Put data information to wire
# \param tds    state information for the socket and the TDS protocol
# \param curcol column where to store information
# \param flags  bit flags on how to send data (use TDS_PUT_DATA_USE_NAME for use name information)
# \return TDS_SUCCESS or TDS_FAIL
#
def tds_put_data_info(tds, curcol):
    logger.debug("tds_put_data_info putting param_name")

    if IS_TDS7_PLUS(tds):
        # TODO use a fixed buffer to avoid error ?
        converted_param = tds_convert_string(tds, tds.char_convs[client2ucs2], curcol.column_name)
        TDS_PUT_BYTE(tds, len(converted_param) / 2)
        tds_put_s(tds, converted_param)
    else:
        # TODO ICONV convert
        tds_put_byte(tds, len(curcol.column_name))
        tds_put_s(tds, curcol.column_name)
    #
    # TODO support other flags (use defaul null/no metadata)
    # bit 1 (2 as flag) in TDS7+ is "default value" bit 
    # (what's the meaning of "default value" ?)
    #

    logger.debug("tds_put_data_info putting status")
    tds_put_byte(tds, curcol.column_output) # status (input)
    if not IS_TDS7_PLUS(tds):
        tds_put_int(tds, curcol.column_usertype) # usertype
    # FIXME: column_type is wider than one byte.  Do something sensible, not just lop off the high byte.
    tds_put_byte(tds, curcol.on_server.column_type)

    curcol.funcs.put_info(tds, curcol)

    # TODO needed in TDS4.2 ?? now is called only is TDS >= 5
    if not IS_TDS7_PLUS(tds):
        tds_put_byte(tds, 0x00) # locale info length

#
# Output params types and query (required by sp_prepare/sp_executesql/sp_prepexec)
# \param tds       state information for the socket and the TDS protocol
# \param query     query (in ucs2le codings)
# \param query_len query length in bytes
#
#def tds7_put_query_params(tds, query):
#    assert IS_TDS7_PLUS(tds)
#
#    # we use all "@PX" for parameters
#    num_placeholders = tds_count_placeholders_ucs2le(query, query_end);
#    len = num_placeholders * 2;
#    # adjust for the length of X
#    for (i = 10; i <= num_placeholders; i *= 10) {
#            len += num_placeholders - i + 1;
#    }
#
#    # string with sql statement
#    # replace placeholders with dummy parametes
#    tds_put_byte(tds, 0)
#    tds_put_byte(tds, 0)
#    tds_put_byte(tds, SYBNTEXT) # must be Ntype
#    len = 2u * len + query_len;
#    TDS_PUT_INT(tds, len)
#    if (IS_TDS71_PLUS(tds))
#        tds_put_n(tds, tds->collation, 5)
#    TDS_PUT_INT(tds, len);
#    s = query;
#    # TODO do a test with "...?" and "...?)"
#    for (i = 1;; ++i)
#        e = tds_next_placeholder_ucs2le(s, query_end, 0);
#        assert(e && query <= e && e <= query_end);
#        tds_put_n(tds, s, e - s);
#        if (e == query_end)
#                break;
#        sprintf(buf, "@P%d", i);
#        tds_put_string(tds, buf, -1);
#        s = e + 2;
#    }
#}

def tds_count_placeholders_ucs2le(converted_query):
    return 0

#
# Return string with parameters definition, useful for TDS7+
# \param tds     state information for the socket and the TDS protocol
# \param params  parameters to build declaration
# \param out_len length output buffer in bytes
# \return allocated and filled string or NULL on failure (coded in ucs2le charset )
#
# TODO find a better name for this function
def tds7_build_param_def_from_params(tds, query, params):
    assert IS_TDS7_PLUS(tds)

    # try to detect missing names
    #if (params->num_cols) {
    #        ids = (struct tds_ids *) calloc(params->num_cols, sizeof(struct tds_ids));
    #        if (!ids)
    #                goto Cleanup;
    #        if (!params->columns[0]->column_name[0]) {
    #                const char *s = query, *e, *id_end;
    #                const char *query_end = query + query_len;

    #                for (i = 0;  i < params->num_cols; s = e + 2) {
    #                        e = tds_next_placeholder_ucs2le(s, query_end, 1);
    #                        if (e == query_end)
    #                                break;
    #                        if (e[0] != '@')
    #                                continue;
    #                        /* find end of param name */
    #                        for (id_end = e + 2; id_end != query_end; id_end += 2)
    #                                if (!id_end[1] && (id_end[0] != '_' && id_end[1] != '#' && !isalnum((unsigned char) id_end[0])))
    #                                        break;
    #                        ids[i].p = e;
    #                        ids[i].len = id_end - e;
    #                        ++i;
    #                }
    #        }
    #}

    param_strs = []
    param_fmt = '{0} {1}'

    for param in params:
        # this part of buffer can be not-ascii compatible, use all ucs2...
        param_strs.append(param_fmt.format(param.column_name, tds_get_column_declaration(tds, param)))
    return ','.join(param_strs)

#
# Return declaration for column (like "varchar(20)")
# \param tds    state information for the socket and the TDS protocol
# \param curcol column
# \param out    buffer to hold declaration
# \return TDS_FAIL or TDS_SUCCESS
#
def tds_get_column_declaration(tds, curcol):
    max_len = 8000 if IS_TDS7_PLUS(tds) else 255

    size = tds_fix_column_size(tds, curcol)
    t = curcol.on_server.column_type #tds_get_conversion_type(curcol.on_server.column_type, curcol.on_server.column_size)

    if t in (XSYBCHAR, SYBCHAR):
        return "CHAR(%d)" % min(size, max_len)
    elif t in (SYBVARCHAR, XSYBVARCHAR):
        if curcol.column_varint_size == 8:
            return "VARCHAR(MAX)"
        else:
            return "VARCHAR(%d)" % min(size, max_len)
    elif t == SYBINT1:
        return "TINYINT"
    elif t == SYBINT2:
        return "SMALLINT"
    elif t == SYBINT4 or t == SYBINTN and size == 4:
        return "INT"
    elif t == SYBINT8:
        # TODO even for Sybase ??
        return "BIGINT"
    elif t == SYBFLT8 or t == SYBFLTN and size == 8:
        return "FLOAT"
    elif t == SYBDATETIME or t == SYBDATETIMN and size == 8:
        return "DATETIME"
    elif t == SYBBIT:
        return "BIT"
    elif t == SYBTEXT:
        return "TEXT"
    elif t == (SYBLONGBINARY, # TODO correct ??
            SYBIMAGE):
        return "IMAGE"
    elif t == SYBMONEY4:
        return "SMALLMONEY"
    elif t == SYBMONEY:
        return "MONEY"
    elif t == SYBDATETIME4 or t == SYBDATETIMN and size == 4:
        return "SMALLDATETIME"
    elif t == SYBREAL:
        return "REAL"
    elif t == (SYBBINARY, XSYBBINARY):
        return "BINARY(%d)" % min(size, max_len)
    elif t == (SYBVARBINARY, XSYBVARBINARY):
        if curcol.column_varint_size == 8:
            return "VARBINARY(MAX)"
        else:
            return "VARBINARY(%u)" % min(size, max_len)
    elif t == SYBNUMERIC:
        return "NUMERIC(%d,%d)" % (curcol.column_prec, curcol.column_scale)
    elif t == SYBDECIMAL:
        return "DECIMAL(%d,%d)" % (curcol.column_prec, curcol.column_scale)
    elif t == SYBUNIQUE:
        if IS_TDS7_PLUS(tds):
            return "UNIQUEIDENTIFIER"
    elif t == SYBNTEXT:
        if IS_TDS7_PLUS(tds):
            return "NTEXT"
    elif t in (SYBNVARCHAR, XSYBNVARCHAR):
        if curcol.column_varint_size == 8:
            return "NVARCHAR(MAX)"
        elif IS_TDS7_PLUS(tds):
            return "NVARCHAR(%u)" % min(size/2, 4000)
    elif t == XSYBNCHAR:
        if IS_TDS7_PLUS(tds):
            return "NCHAR(%u)" % min(size/2, 4000)
    elif t == SYBVARIANT:
        if IS_TDS7_PLUS(tds):
            return "SQL_VARIANT"
    # TODO support scale !!
    elif t == SYBMSTIME:
        return "TIME"
    elif t == SYBMSDATE:
        return "DATE"
    elif t == SYBMSDATETIME2:
        return "DATETIME2"
    elif t == SYBMSDATETIMEOFFSET:
        return "DATETIMEOFFSET"
    # nullable types should not occur here...
    elif t in (SYBMONEYN, SYBDATETIMN, SYBBITN):
        assert False
        # TODO...
    else:
        logger.error("Unknown type %d", t)

    return ''

def tds7_put_params_definition(tds, param_definition):
    logger.debug('tds7_put_params_definition(%s)', param_definition)
    # string with parameters types
    tds_put_byte(tds, 0)
    tds_put_byte(tds, 0)
    tds_put_byte(tds, SYBNTEXT) # must be Ntype

    # put parameters definitions
    param_definition = tds.char_convs[client2ucs2]['to_wire'](param_definition)
    param_length = len(param_definition)
    TDS_PUT_INT(tds, param_length)
    if IS_TDS71_PLUS(tds):
        tds_put_s(tds, tds.collation)
    TDS_PUT_INT(tds, param_length if param_length else -1)
    tds_put_s(tds, param_definition)

def tds_submit_begin_tran(tds):
    logger.debug('tds_submit_begin_tran()')
    if IS_TDS72(tds):
        if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        tds.out_flag = TDS7_TRANS
        tds_start_query(tds)

        # begin transaction
        tds_put_smallint(tds, 5)
        tds_put_byte(tds, 0) # new transaction level TODO
        tds_put_byte(tds, 0) # new transaction name

        tds_query_flush_packet(tds)
    else:
        tds_submit_query(tds, "BEGIN TRANSACTION")

def tds_submit_rollback(tds, cont):
    logger.debug('tds_submit_rollback(%s, %s)', id(tds), cont)
    if IS_TDS72(tds):
        if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        tds.out_flag = TDS7_TRANS
        tds_start_query(tds)
        tds_put_smallint(tds, 8) # rollback
        tds_put_byte(tds, 0) # name
        if cont:
            tds_put_byte(tds, 1)
            tds_put_byte(tds, 0) # new transaction level TODO
            tds_put_byte(tds, 0) # new transaction name
        else:
            tds_put_byte(tds, 0) # do not continue
        tds_query_flush_packet(tds);
    else:
        tds_submit_query(tds, "IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")

def tds_submit_commit(tds, cont):
    logger.debug('tds_submit_commit(%s)', cont)
    if IS_TDS72(tds):
        if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        tds.out_flag = TDS7_TRANS
        tds_start_query(tds)
        tds_put_smallint(tds, 7) # commit
        tds_put_byte(tds, 0) # name
        if cont:
            tds_put_byte(tds, 1)
            tds_put_byte(tds, 0) # new transaction level TODO
            tds_put_byte(tds, 0) # new transaction name
        else:
            tds_put_byte(tds, 0) # do not continue
        tds_query_flush_packet(tds)
    else:
        tds_submit_query(tds, "IF @@TRANCOUNT > 0 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")
