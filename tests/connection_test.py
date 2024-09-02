import pytest
import pytds
import unittest
import settings
from pytds import (
    connect,
    Error
)

LIVE_TEST = getattr(settings, "LIVE_TEST", True)

@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_timeout_with_mars():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs["database"] = "master"
    kwargs["timeout"] = 1
    kwargs["use_mars"] = True
    with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
        cur = conn.cursor()
        with pytest.raises(TimeoutError):
            cur.execute("waitfor delay '00:00:05'")
        cur.execute("select 1")


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_no_mars_autocommit():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update(
        {
            "use_mars": False,
            "timeout": 1,
            "pooling": True,
            "autocommit": True,
        }
    )
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            # test execute scalar with empty response
            cur.execute_scalar("declare @tbl table(f int); select * from @tbl")

            cur.execute("print 'hello'")
            messages = cur.messages
            assert len(messages) == 1
            assert len(messages[0]) == 2
            # in following assert exception class does not have to be exactly as specified
            assert messages[0][0] == pytds.OperationalError
            assert messages[0][1].text == "hello"
            assert messages[0][1].line == 1
            assert messages[0][1].severity == 0
            assert messages[0][1].number == 0
            assert messages[0][1].state == 1
            assert "hello" in messages[0][1].message

        # test cursor usage after close, should raise exception
        cur = conn.cursor()
        cur.execute_scalar("select 1")
        cur.close()
        with pytest.raises(Error) as ex:
            cur.execute("select 1")
        assert "Cursor is closed" in str(ex.value)
        # calling get_proc_return_status on closed cursor works
        # this test does not have to pass
        assert cur.get_proc_return_status() is None
        # calling rowcount on closed cursor works
        # this test does not have to pass
        assert cur.rowcount == -1
        # calling description on closed cursor works
        # this test does not have to pass
        assert cur.description is None
        # calling messages on closed cursor works
        # this test does not have to pass
        assert cur.messages is None
        # calling description on closed cursor works
        # this test does not have to pass
        assert cur.native_description is None


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_timeout_no_mars():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update(
        {
            "use_mars": False,
            "timeout": 1,
            "pooling": True,
        }
    )
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            with pytest.raises(TimeoutError):
                cur.execute("waitfor delay '00:00:05'")
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchall()

        # test cancelling
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.cancel()
            assert cur.fetchall() == []
            cur.execute("select 2")
            assert cur.fetchall() == [(2,)]

        # test rollback
        conn.rollback()

        # test callproc on non-mars connection
        with conn.cursor() as cur:
            cur.callproc("sp_reset_connection")

        with conn.cursor() as cur:
            # test spid property on non-mars cursor
            assert cur.spid is not None

            # test tzinfo_factory property r/w
            cur.tzinfo_factory = cur.tzinfo_factory

    # test non-mars cursor with connection pool enabled
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [(1,)]


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_no_mars_no_pooling():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update(
        {
            "use_mars": False,
            "pooling": False,
        }
    )
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [(1,)]


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_failover_partner():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update(
        {
            "server": "192.168.1.1\\sqlexpress-doesnotexist",
            "failover_partner": settings.CONNECT_KWARGS["server"],
            "pooling": False,
        }
    )
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [(1,)]
