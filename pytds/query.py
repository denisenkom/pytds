from .tds import *
from .tdsproto import *
from .tds import _Column
from .data import *


def START_QUERY(tds):
    if IS_TDS72_PLUS(tds):
        tds_start_query(tds)

tds72_query_start = str(bytearray([
    # total length
    0x16, 0, 0, 0,
    # length
    0x12, 0, 0, 0,
    # type
    0x02, 0,
    # transaction
    0, 0, 0, 0, 0, 0, 0, 0,
    # request count
    1, 0, 0, 0]))


def tds_start_query(tds):
    w = tds._writer
    w.put_uint(0x16)  # total length
    w.put_uint(0x12)  # length
    w.put_usmallint(2)  # type
    if tds.conn.tds72_transaction:
        assert len(tds.conn.tds72_transaction) == 8
        w.write(tds.conn.tds72_transaction)
    else:
        w.write(b'\x00\x00\x00\x00\x00\x00\x00\x00')
    w.put_uint(1)  # request count


def tds_query_flush_packet(tds):
    # TODO depend on result ??
    tds.set_state(TDS_PENDING)
    tds._writer.flush()


def convert_params(tds, parameters):
    if isinstance(parameters, dict):
        return [make_param(tds, name, value) for name, value in parameters.items()]
    else:
        params = []
        for parameter in parameters:
            if isinstance(parameter, _Column):
                params.append(parameter)
            else:
                params.append(make_param(tds, '', parameter))
        return params


def _submit_rpc(tds, rpc_name, params, flags):
    tds.cur_dyn = None
    w = tds._writer
    if IS_TDS7_PLUS(tds):
        w.begin_packet(TDS_RPC)
        START_QUERY(tds)
        if IS_TDS71_PLUS(tds) and isinstance(rpc_name, InternalProc):
            w.put_smallint(-1)
            w.put_smallint(rpc_name.proc_id)
        else:
            w.put_smallint(len(rpc_name))
            w.write_ucs2(rpc_name)
        #
        # TODO support flags
        # bit 0 (1 as flag) in TDS7/TDS5 is "recompile"
        # bit 1 (2 as flag) in TDS7+ is "no metadata" bit this will prevent sending of column infos
        #
        w.put_usmallint(flags)
        params = convert_params(tds, params)
        for param in params:
            tds_put_data_info(tds, param)
            param.funcs.put_data(tds, param)
        #tds_query_flush_packet(tds)
    elif IS_TDS5_PLUS(tds):
        w.begin_packet(TDS_NORMAL)
        w.put_byte(TDS_DBRPC_TOKEN)
        # TODO ICONV convert rpc name
        w.put_smallint(len(rpc_name) + 3)
        w.put_byte(len(rpc_name))
        w.write(rpc_name)
        # TODO flags
        w.put_smallint(2 if params else 0)

        if params:
            tds_put_params(tds, params, TDS_PUT_DATA_USE_NAME)

        # send it
        #tds_query_flush_packet(tds)
    else:
        # emulate it for TDS4.x, send RPC for mssql
        return tds_send_emulated_rpc(tds, rpc_name, params)


def tds_submit_rpc(tds, rpc_name, params=(), flags=0):
    with tds.state_context(TDS_QUERYING):
        _submit_rpc(tds, rpc_name, params, flags)
        tds_query_flush_packet(tds)


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
def tds_submit_query(tds, query, params=(), flags=0):
    logger.info('tds_submit_query(%s, %s)', query, params)
    if not query:
        raise ProgrammingError('Empty query is not allowed')

    with tds.state_context(TDS_QUERYING):
        tds.res_info = None
        w = tds._writer
        if IS_TDS50(tds):
            new_query = None
            # are there '?' style parameters ?
            if tds_next_placeholder(query):
                new_query = tds5_fix_dot_query(query, params)
                query = new_query

            w.begin_packet(TDS_NORMAL)
            w.put_byte(TDS_LANGUAGE_TOKEN)
            # TODO ICONV use converted size, not input size and convert string
            w.put_int(len(query) + 1)
            w.put_byte(1 if params else 0)  # 1 if there are params, 0 otherwise
            w.write(tds, query)
            if params:
                # add on parameters
                tds_put_params(tds, params, TDS_PUT_DATA_USE_NAME if params.columns[0].column_name else 0)
        elif not IS_TDS7_PLUS(tds) or not params:
            w.begin_packet(TDS_QUERY)
            START_QUERY(tds)
            w.write_ucs2(query)
        else:
            params = convert_params(tds, params)
            param_definition = ','.join(
                '{0} {1}'.format(p.column_name, p.funcs.get_declaration(tds, p))
                for p in params)
            _submit_rpc(tds, SP_EXECUTESQL,
                        [query, param_definition] + params, 0)
            tds.internal_sp_called = TDS_SP_EXECUTESQL
        tds_query_flush_packet(tds)


#
# tds_send_cancel() sends an empty packet (8 byte header only)
# tds_process_cancel should be called directly after this.
# \param tds state information for the socket and the TDS protocol
# \remarks
#  tcp will either deliver the packet or time out.
#  (TIME_WAIT determines how long it waits between retries.)
#
#  On sending the cancel, we may get EAGAIN.  We then select(2) until we know
#  either 1) it succeeded or 2) it didn't.  On failure, close the socket,
#  tell the app, and fail the function.
#
#  On success, we read(2) and wait for a reply with select(2).  If we get
#  one, great.  If the client's timeout expires, we tell him, but all we can
#  do is wait some more or give up and close the connection.  If he tells us
#  to cancel again, we wait some more.
#
def tds_send_cancel(tds):
    if TDS_MUTEX_TRYLOCK(tds.wire_mtx):
        # TODO check
        # signal other socket
        raise NotImplementedError
        #tds_conn(tds).s_signal.send((void*) &tds, sizeof(tds))
        return TDS_SUCCESS

    logger.debug("tds_send_cancel: %sin_cancel and %sidle".format(
                 ('' if tds.in_cancel else "not "), ('' if tds.state == TDS_IDLE else "not ")))

    # one cancel is sufficient
    if tds.in_cancel or tds.state == TDS_IDLE:
        TDS_MUTEX_UNLOCK(tds.wire_mtx)
        return TDS_SUCCESS

    tds.res_info = None
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
    w = tds._writer
    if IS_TDS7_PLUS(tds):
        w.put_byte(len(curcol.column_name))
        w.write_ucs2(curcol.column_name)
    else:
        # TODO ICONV convert
        w.put_byte(len(curcol.column_name))
        w.write(curcol.column_name)
    #
    # TODO support other flags (use defaul null/no metadata)
    # bit 1 (2 as flag) in TDS7+ is "default value" bit
    # (what's the meaning of "default value" ?)
    #

    w.put_byte(curcol.flags)
    if not IS_TDS7_PLUS(tds):
        w.put_int(curcol.column_usertype)  # usertype
    # FIXME: column_type is wider than one byte.  Do something sensible, not just lop off the high byte.
    w.put_byte(curcol.column_type)

    curcol.funcs.put_info(tds, curcol)

    # TODO needed in TDS4.2 ?? now is called only is TDS >= 5
    if not IS_TDS7_PLUS(tds):
        w.put_byte(0)  # locale info length


def tds_submit_begin_tran(tds):
    logger.debug('tds_submit_begin_tran()')
    if IS_TDS72_PLUS(tds):
        if tds.set_state(TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        w = tds._writer
        w.begin_packet(TDS7_TRANS)
        tds_start_query(tds)

        # begin transaction
        w.put_smallint(5)
        w.put_byte(0)  # new transaction level TODO
        w.put_byte(0)  # new transaction name

        tds_query_flush_packet(tds)
    else:
        tds_submit_query(tds, "BEGIN TRANSACTION")


def tds_submit_rollback(tds, cont):
    logger.debug('tds_submit_rollback(%s, %s)', id(tds), cont)
    if IS_TDS72_PLUS(tds):
        if tds.set_state(TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        w = tds._writer
        w.begin_packet(TDS7_TRANS)
        tds_start_query(tds)
        w.put_smallint(8)  # rollback
        w.put_byte(0)  # name
        if cont:
            w.put_byte(1)
            w.put_byte(0)  # new transaction level TODO
            w.put_byte(0)  # new transaction name
        else:
            w.put_byte(0)  # do not continue
        tds_query_flush_packet(tds)
    else:
        tds_submit_query(tds, "IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")


def tds_submit_commit(tds, cont):
    logger.debug('tds_submit_commit(%s)', cont)
    if IS_TDS72_PLUS(tds):
        if tds.set_state(TDS_QUERYING) != TDS_QUERYING:
            raise Exception('TDS_FAIL')

        w = tds._writer
        w.begin_packet(TDS7_TRANS)
        tds_start_query(tds)
        w.put_smallint(7)  # commit
        w.put_byte(0)  # name
        if cont:
            w.put_byte(1)
            w.put_byte(0)  # new transaction level TODO
            w.put_byte(0)  # new transaction name
        else:
            w.put_byte(0)  # do not continue
        tds_query_flush_packet(tds)
    else:
        tds_submit_query(tds, "IF @@TRANCOUNT > 1 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")
