"""
Testing various ways of closing connection
"""
from time import sleep

import pytest
import pytds
import settings


def get_spid(conn):
    with conn.cursor() as cur:
        return cur.spid


def kill(conn, spid):
    with conn.cursor() as cur:
        cur.execute('kill {0}'.format(spid))


def test_cursor_use_after_connection_closing():
    """
    Check that cursor is not usable after it's parent connection is closed
    """
    conn = pytds.connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
    cur = conn.cursor()
    conn.close()
    with pytest.raises(pytds.Error):
        cur.execute("select 1")
    # now create new connection which should reuse previous connection from the pool
    # and verify that it still works
    new_conn = pytds.connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
    with new_conn:
        assert 1 == new_conn.cursor().execute_scalar("select 1")


def test_open_close():
    for x in range(3):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        pytds.connect(**kwargs).close()


def test_closing_after_closed_by_server():
    """
    You should be able to call close on connection closed by server
    """
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs['database'] = 'master'
    kwargs['autocommit'] = True
    with pytds.connect(**kwargs) as master_conn:
        kwargs['autocommit'] = False
        with pytds.connect(**kwargs) as conn:
            with conn.cursor() as cur:
                cur.execute('select 1')
                conn.commit()
                kill(master_conn, get_spid(conn))
                sleep(0.2)
            conn.close()
