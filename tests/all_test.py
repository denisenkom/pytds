# vim: set fileencoding=utf8 :
from __future__ import with_statement
from __future__ import unicode_literals
import os
import random
import string
import codecs
import logging
import socket
from io import StringIO

import utils

from pytds.tds_types import TimeType, DateTime2Type, DateType, DateTimeOffsetType, BitType, TinyIntType, SmallIntType, \
    IntType, BigIntType, RealType, FloatType, NVarCharType, VarBinaryType, SmallDateTimeType, DateTimeType, DecimalType, \
    MoneyType, UniqueIdentifierType, VariantType, ImageType, VarBinaryMaxType, VarCharType, TextType, NTextType, \
    NVarCharMaxType, VarCharMaxType, XmlType

try:
    import unittest2 as unittest
except:
    import unittest
import sys
from decimal import Decimal, getcontext
import logging
from time import sleep
from datetime import datetime, date, time
import uuid
import pytest
import pytds.tz
import pytds.login
import pytds.smp
tzoffset = pytds.tz.FixedOffsetTimezone
utc = pytds.tz.utc
import pytds.extensions
from pytds import (
    connect, ProgrammingError, TimeoutError, Time,
    Error, IntegrityError, Timestamp, DataError, Date, Binary,
    output, default,
    STRING, BINARY, NUMBER, DATETIME, DECIMAL, INTEGER, REAL, XML)
from pytds.tds_types import (DateTimeSerializer, SmallMoneyType)
from pytds.tds_base import (
    Param,
    IS_TDS73_PLUS, IS_TDS71_PLUS,
    )
import dbapi20
import pytds
import settings


logger = logging.getLogger(__name__)

LIVE_TEST = getattr(settings, 'LIVE_TEST', True)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_timeout_with_mars():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs['database'] = 'master'
    kwargs['timeout'] = 1
    kwargs['use_mars'] = True
    with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
        cur = conn.cursor()
        with pytest.raises(TimeoutError):
            cur.execute("waitfor delay '00:00:05'")
        cur.execute('select 1')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_no_mars_autocommit():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update({
        'use_mars': False,
        'timeout': 1,
        'pooling': True,
        'autocommit': True,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            # test execute scalar with empty response
            cur.execute_scalar('declare @tbl table(f int); select * from @tbl')

            cur.execute("print 'hello'")
            messages = cur.messages
            assert len(messages) == 1
            assert len(messages[0]) == 2
            # in following assert exception class does not have to be exactly as specified
            assert messages[0][0] == pytds.OperationalError
            assert messages[0][1].text == 'hello'
            assert messages[0][1].line == 1
            assert messages[0][1].severity == 0
            assert messages[0][1].number == 0
            assert messages[0][1].state == 1
            assert 'hello' in messages[0][1].message

        # test cursor usage after close, should raise exception
        cur = conn.cursor()
        cur.execute_scalar('select 1')
        cur.close()
        with pytest.raises(Error) as ex:
            cur.execute('select 1')
        assert 'Cursor is closed' in str(ex.value)
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
    kwargs.update({
        'use_mars': False,
        'timeout': 1,
        'pooling': True,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            with pytest.raises(TimeoutError):
                cur.execute("waitfor delay '00:00:05'")
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchall()

        # test cancelling
        with conn.cursor() as cur:
            cur.execute('select 1')
            cur.cancel()
            assert cur.fetchall() == []
            cur.execute('select 2')
            assert cur.fetchall() == [(2,)]

        # test rollback
        conn.rollback()

        # test callproc on non-mars connection
        with conn.cursor() as cur:
            cur.callproc('sp_reset_connection')

        with conn.cursor() as cur:
            # test spid property on non-mars cursor
            assert cur.spid is not None

            # test tzinfo_factory property r/w
            cur.tzinfo_factory = cur.tzinfo_factory

    # test non-mars cursor with connection pool enabled
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute('select 1')
            assert cur.fetchall() == [(1,)]


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_connection_no_mars_no_pooling():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update({
        'use_mars': False,
        'pooling': False,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [(1,)]


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_row_strategies():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update({
        'row_strategy': pytds.list_row_strategy,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [[1]]
    kwargs.update({
        'row_strategy': pytds.namedtuple_row_strategy,
    })
    import collections
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1 as f")
            assert cur.fetchall() == [collections.namedtuple('Row', ['f'])(1)]
    kwargs.update({
        'row_strategy': pytds.recordtype_row_strategy,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1 as e, 2 as f")
            row, = cur.fetchall()
            assert row.e == 1
            assert row.f == 2
            assert row[0] == 1
            assert row[:] == (1, 2)
            row[0] = 3
            assert row[:] == (3, 2)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_get_instances():
    if not hasattr(settings, 'BROWSER_ADDRESS'):
        return unittest.skip('BROWSER_ADDRESS setting is not defined')
    pytds.tds.tds7_get_instances(settings.BROWSER_ADDRESS)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class ConnectionTestCase(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = settings.DATABASE
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def tearDown(self):
        self.conn.close()


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class NoMarsTestCase(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['use_mars'] = False
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def tearDown(self):
        self.conn.close()

    def test_commit(self):
        cursor = self.conn.cursor()
        cursor.execute('select 1')
        cursor.fetchall()
        self.conn.commit()


class TestCaseWithCursor(ConnectionTestCase):
    def setUp(self):
        super(TestCaseWithCursor, self).setUp()
        self.cursor = self.conn.cursor()

    #def test_mars_sessions_recycle_ids(self):
    #    if not self.conn.mars_enabled:
    #        self.skipTest('Only relevant to mars')
    #    for _ in range(2 ** 16 + 1):
    #        cur = self.conn.cursor()
    #        cur.close()

    def test_parameters_ll(self):
        _params_tests(self)



class TestVariant(ConnectionTestCase):
    def _t(self, result, sql):
        with self.conn.cursor() as cur:
            cur.execute("select cast({0} as sql_variant)".format(sql))
            val, = cur.fetchone()
            self.assertEqual(result, val)

    def test_new_datetime(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        import pytds.tz
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000), "cast('2011-02-03T10:11:12.003000' as datetime2)")
        self._t(time(10, 11, 12, 3000), "cast('10:11:12.003000' as time)")
        self._t(date(2011, 2, 3), "cast('2011-02-03' as date)")
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000, pytds.tz.FixedOffsetTimezone(3 * 60)), "cast('2011-02-03T10:11:12.003000+03:00' as datetimeoffset)")


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class BadConnection(unittest.TestCase):
    def test_invalid_parameters(self):
        with self.assertRaises(Error):
            with connect(server=settings.HOST + 'bad', database='master', user='baduser', password=settings.PASSWORD, login_timeout=1) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database='doesnotexist', user=settings.USER, password=settings.PASSWORD) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database='master', user='baduser', password=None) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')

    def test_instance_and_port(self):
        host = settings.HOST
        if '\\' in host:
            host, _ = host.split('\\')
        with self.assertRaisesRegex(ValueError, 'Both instance and port shouldn\'t be specified'):
            with connect(server=host + '\\badinstancename', database='master', user=settings.USER, password=settings.PASSWORD, port=1212) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')


def get_spid(conn):
    with conn.cursor() as cur:
        return cur.spid


def kill(conn, spid):
    with conn.cursor() as cur:
        cur.execute('kill {0}'.format(spid))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class ConnectionClosing(unittest.TestCase):
    def test_open_close(self):
        for x in range(3):
            kwargs = settings.CONNECT_KWARGS.copy()
            kwargs['database'] = 'master'
            connect(**kwargs).close()

    def test_closing_after_closed_by_server(self):
        """
        You should be able to call close on connection closed by server
        """
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['autocommit'] = True
        with connect(**kwargs) as master_conn:
            kwargs['autocommit'] = False
            with connect(**kwargs) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    conn.commit()
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                conn.close()

    def test_connection_closed_by_server(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        with connect(**kwargs) as master_conn:
            master_conn.autocommit = True
            with connect(**kwargs) as conn:
                conn.autocommit = False
                # test overall recovery
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    conn.commit()
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                    cur.execute('select 1')
                    cur.fetchall()
                kill(master_conn, get_spid(conn))
                sleep(0.2)
                with conn.cursor() as cur:
                    cur.execute('select 1')

                # test cursor opening in a transaction, it should raise exception
                # make transaction dirty
                with conn.cursor() as cur:
                    cur.execute('select 1')
                kill(master_conn, get_spid(conn))
                sleep(0.2)
                # it does not have to raise this specific exception
                with pytest.raises(socket.error):
                    with conn.cursor() as cur:
                        cur.execute('select 1')

                # test recovery on transaction
                with conn.cursor() as cur:
                    cur.execute('create table ##testtable3 (fld int)')
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                    with self.assertRaises(Exception):
                        cur.execute('select * from ##testtable2')
                        cur.fetchall()
                    conn.rollback()
                    cur.execute('select 1')

                # test server closed connection on rollback
                with conn.cursor() as cur:
                    cur.execute('select 1')
                kill(master_conn, get_spid(conn))
                sleep(0.2)
                conn.rollback()

            #with connect(server=settings.HOST, database='master', user=settings.USER, password=settings.PASSWORD) as conn:
            #    spid = get_spid(conn)
            #    with conn.cursor() as cur:
            #        # test recovery of specific lowlevel methods
            #        tds_submit_query(cur._session, "waitfor delay '00:00:05'; select 1")
            #        kill(master_conn, spid)
            #        self.assertTrue(cur._session.is_connected())
            #        with self.assertRaises(Exception):
            #            tds_process_tokens(cur._session, TDS_TOKEN_RESULTS)
            #        self.assertFalse(cur._session.is_connected())


#class EncryptionTest(unittest.TestCase):
#    def runTest(self):
#        conn = connect(server=settings.HOST, database='master', user=settings.USER, password=settings.PASSWORD, encryption_level=TDS_ENCRYPTION_REQUIRE)
#        cur = conn.cursor()
#        cur.execute('select 1')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class SmallDateTimeTest(ConnectionTestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as smalldatetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])

    def runTest(self):
        self._testval(Timestamp(2010, 2, 1, 10, 12, 0))
        self._testval(Timestamp(1900, 1, 1, 0, 0, 0))
        self._testval(Timestamp(2079, 6, 6, 23, 59, 0))
        with self.assertRaises(Error):
            self._testval(Timestamp(1899, 1, 1, 0, 0, 0))
        with self.assertRaises(Error):
            self._testval(Timestamp(2080, 1, 1, 0, 0, 0))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class DateTimeTest(ConnectionTestCase):
    def _testencdec(self, val):
        self.assertEqual(val, DateTimeSerializer.decode(*DateTimeSerializer._struct.unpack(DateTimeSerializer.encode(val))))

    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])

    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute("select cast('9999-12-31T23:59:59.997' as datetime)")
            self.assertEqual(cur.fetchall(), [(Timestamp(9999, 12, 31, 23, 59, 59, 997000),)])
        self._testencdec(Timestamp(2010, 1, 2, 10, 11, 12))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0))
        self._testval(Timestamp(2010, 1, 2, 10, 11, 12))
        self._testval(Timestamp(1753, 1, 1, 0, 0, 0))
        self._testval(Timestamp(9999, 12, 31, 0, 0, 0))
        with self.conn.cursor() as cur:
            cur.execute("select cast(null as datetime)")
            self.assertEqual(cur.fetchall(), [(None,)])
        self._testval(Timestamp(9999, 12, 31, 23, 59, 59, 997000))
        with self.assertRaises(Error):
            self._testval(Timestamp(1752, 1, 1, 0, 0, 0))
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
            cur.execute('create table testtable (col datetime not null)')
            dt = Timestamp(2010, 1, 2, 20, 21, 22, 123000)
            cur.execute('insert into testtable values (%s)', (dt,))
            cur.execute('select col from testtable')
            self.assertEqual(cur.fetchone(), (dt,))


class NewDateTimeTest(ConnectionTestCase):
    def test_datetimeoffset(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')

        def _testval(val):
            with self.conn.cursor() as cur:
                import pytds.tz
                cur.tzinfo_factory = pytds.tz.FixedOffsetTimezone
                cur.execute('select cast(%s as datetimeoffset)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        with self.conn.cursor() as cur:
            import pytds.tz
            cur.tzinfo_factory = pytds.tz.FixedOffsetTimezone
            cur.execute("select cast('2010-01-02T20:21:22.1234567+05:00' as datetimeoffset)")
            self.assertEqual(datetime(2010, 1, 2, 20, 21, 22, 123456, tzoffset(5 * 60)), cur.fetchone()[0])
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, utc))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(5 * 60)))
        _testval(Timestamp(1, 1, 1, 0, 0, 0, 0, utc))
        _testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999, utc))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(14)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(-14)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(-15)))

    def test_time(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')

        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as time)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        testval(Time(14, 16, 18, 123456))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(23, 59, 59, 999999))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))

    def test_datetime2(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')

        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as datetime2)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        testval(Timestamp(2010, 1, 2, 20, 21, 22, 345678))
        testval(Timestamp(2010, 1, 2, 0, 0, 0))
        testval(Timestamp(1, 1, 1, 0, 0, 0))
        testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999))

    def test_date(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')

        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as date)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        testval(Date(2010, 1, 2))
        testval(Date(2010, 1, 2))
        testval(Date(1, 1, 1))
        testval(Date(9999, 12, 31))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class Auth(unittest.TestCase):
    @unittest.skipUnless(os.getenv('NTLM_USER') and os.getenv('NTLM_PASSWORD'), "requires NTLM_USER and NTLM_PASSWORD environment variables to be set")
    def test_ntlm(self):
        conn = connect(settings.HOST, auth=pytds.login.NtlmAuth(user_name=os.getenv('NTLM_USER'), password=os.getenv('NTLM_PASSWORD')))
        with conn.cursor() as cursor:
            cursor.execute('select 1')
            cursor.fetchall()

    @unittest.skipUnless(os.getenv('NTLM_USER') and os.getenv('NTLM_PASSWORD'), "requires NTLM_USER and NTLM_PASSWORD environment variables to be set")
    def test_spnego(self):
        conn = connect(settings.HOST, auth=pytds.login.SpnegoAuth(os.getenv('NTLM_USER'), os.getenv('NTLM_PASSWORD')))
        with conn.cursor() as cursor:
            cursor.execute('select 1')
            cursor.fetchall()

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sspi(self):
        from pytds.login import SspiAuth
        with connect(settings.HOST, auth=SspiAuth()) as conn:
            with conn.cursor() as cursor:
                cursor.execute('select 1')
                cursor.fetchall()

    @unittest.skipIf(getattr(settings, 'SKIP_SQL_AUTH', False), 'SKIP_SQL_AUTH is set')
    def test_sqlauth(self):
        with connect(settings.HOST, user=settings.USER, password=settings.PASSWORD) as conn:
            with conn.cursor() as cursor:
                cursor.execute('select 1')
                cursor.fetchall()


class CloseCursorTwice(ConnectionTestCase):
    def runTest(self):
        cursor = self.conn.cursor()
        cursor.close()
        cursor.close()


class RegressionSuite(ConnectionTestCase):
    def test_cancel(self):
        self.conn.cursor().cancel()


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TimezoneTests(unittest.TestCase):
    def check_val(self, conn, sql, input, output):
        with conn.cursor() as cur:
            cur.execute('select ' + sql, (input,))
            rows = cur.fetchall()
            self.assertEqual(rows[0][0], output)

    def runTest(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        use_tz = utc
        kwargs['use_tz'] = use_tz
        kwargs['database'] = 'master'
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            # Naive time should be interpreted as use_tz
            self.check_val(conn, '%s',
                           datetime(2011, 2, 3, 10, 11, 12, 3000),
                           datetime(2011, 2, 3, 10, 11, 12, 3000, utc))
            # Aware time shoule be passed as-is
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset(1))
            self.check_val(conn, '%s', dt, dt)
            # Aware time should be converted to use_tz if not using datetimeoffset type
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset(1))
            if IS_TDS73_PLUS(conn):
                self.check_val(conn, 'cast(%s as datetime2)', dt, dt.astimezone(use_tz))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class DbapiTestSuite(dbapi20.DatabaseAPI20Test, ConnectionTestCase):
    driver = pytds
    connect_args = settings.CONNECT_ARGS
    connect_kw_args = settings.CONNECT_KWARGS

#    def _connect(self):
#        return connection

    def _try_run(self, *args):
        with self._connect() as con:
            with con.cursor() as cur:
                for arg in args:
                    cur.execute(arg)

    def _try_run2(self, cur, *args):
        for arg in args:
            cur.execute(arg)

    # This should create the "lower" sproc.
    def _callproc_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[to_lower]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[to_lower]""",
            """
            CREATE PROCEDURE to_lower
                @input nvarchar(max)
            AS
            BEGIN
                select LOWER(@input)
            END
            """,
            )

    # This should create a sproc with a return value.
    def _retval_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one]""",
            """
CREATE PROCEDURE add_one (@input int)
AS
BEGIN
    return @input+1
END
""",
            )

    def test_retval(self):
        with self._connect() as con:
            cur = con.cursor()
            self._retval_setup(cur)
            values = cur.callproc('add_one', (1,))
            self.assertEqual(values[0], 1, 'input parameter should be left unchanged: %s' % (values[0],))

            self.assertEqual(cur.description, None, "No resultset was expected.")
            self.assertEqual(cur.return_value, 2, "Invalid return value: %s" % (cur.return_value,))

        # This should create a sproc with a return value.
    def _retval_select_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one_select]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one_select]""",
            """
CREATE PROCEDURE add_one_select (@input int)
AS
BEGIN
    select 'a' as a
    select 'b' as b
    return @input+1
END
""",
            )

    def test_retval_select(self):
        with self._connect() as con:
            cur = con.cursor()
            self._retval_select_setup(cur)
            values = cur.callproc('add_one_select', (1,))
            self.assertEqual(values[0], 1, 'input parameter should be left unchanged: %s' % (values[0],))

            self.assertEqual(len(cur.description), 1, "Unexpected resultset.")
            self.assertEqual(cur.description[0][0], 'a', "Unexpected resultset.")
            self.assertEqual(cur.fetchall(), [('a',)], 'Unexpected resultset.')

            self.assertTrue(cur.nextset(), 'No second resultset found.')
            self.assertEqual(len(cur.description), 1, "Unexpected resultset.")
            self.assertEqual(cur.description[0][0], 'b', "Unexpected resultset.")

            self.assertEqual(cur.return_value, 2, "Invalid return value: %s" % (cur.return_value,))
            with self.assertRaises(Error):
                cur.fetchall()

    # This should create a sproc with an output parameter.
    def _outparam_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one_out]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one_out]""",
            """
CREATE PROCEDURE add_one_out (@input int, @output int OUTPUT)
AS
BEGIN
    SET @output = @input+1
END
""",
            )

    def test_outparam(self):
        with self._connect() as con:
            cur = con.cursor()
            self._outparam_setup(cur)
            values = cur.callproc('add_one_out', (1, output(value=1)))
            self.assertEqual(len(values), 2, 'expected 2 parameters')
            self.assertEqual(values[0], 1, 'input parameter should be unchanged')
            self.assertEqual(values[1], 2, 'output parameter should get new values')

            values = cur.callproc('add_one_out', (None, output(value=1)))
            self.assertEqual(len(values), 2, 'expected 2 parameters')
            self.assertEqual(values[0], None, 'input parameter should be unchanged')
            self.assertEqual(values[1], None, 'output parameter should get new values')

    def test_assigning_select(self):
        # test that assigning select does not interfere with result sets
        with self._connect() as con:
            cur = con.cursor()
            cur.execute("""
declare @var1 int

select @var1 = 1
select @var1 = 2

select 'value'
""")
            self.assertFalse(cur.description)
            self.assertTrue(cur.nextset())

            self.assertFalse(cur.description)
            self.assertTrue(cur.nextset())

            self.assertTrue(cur.description)
            self.assertEqual([(u'value',)], cur.fetchall())
            self.assertFalse(cur.nextset())

            cur.execute("""
set nocount on

declare @var1 int

select @var1 = 1
select @var1 = 2

select 'value'
""")
            self.assertTrue(cur.description)
            self.assertEqual([(u'value',)], cur.fetchall())
            self.assertFalse(cur.nextset())

    # Don't need setoutputsize tests.
    def test_setoutputsize(self):
        pass

    def help_nextset_setUp(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[deleteme]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[deleteme]""",
            """
create procedure deleteme
as
begin
    select count(*) from %sbooze
    select name from %sbooze
end
""" % (self.table_prefix, self.table_prefix),
            )

    def help_nextset_tearDown(self, cur):
        cur.execute("drop procedure deleteme")

    def test_ExceptionsAsConnectionAttributes(self):
        pass

    def test_select_decimal_zero(self):
        with self._connect() as con:
            expected = (
                Decimal('0.00'),
                Decimal('0.0'),
                Decimal('-0.00'))

            cur = con.cursor()
            cur.execute("SELECT %s as A, %s as B, %s as C", expected)

            result = cur.fetchall()
            self.assertEqual(result[0], expected)

    def test_type_objects(self):
        with self._connect() as con:
            cur = con.cursor()
            cur.execute("""
select cast(0 as varchar),
       cast(1 as binary),
       cast(2 as int),
       cast(3 as real),
       cast(4 as decimal),
       cast('2005' as datetime),
       cast('6' as xml)
""")
            self.assertTrue(cur.description)
            col_types = [col[1] for col in cur.description]
            self.assertEqual(col_types[0], STRING)
            self.assertEqual(col_types[1], BINARY)
            self.assertEqual(col_types[2], NUMBER)
            self.assertEqual(col_types[2], INTEGER)
            self.assertEqual(col_types[3], NUMBER)
            self.assertEqual(col_types[3], REAL)
            # self.assertEqual(col_types[4], NUMBER) ?
            self.assertEqual(col_types[4], DECIMAL)
            self.assertEqual(col_types[5], DATETIME)
            self.assertEqual(col_types[6], XML)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestBug4(unittest.TestCase):
    def test_as_dict(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            conn.as_dict = True
            with conn.cursor() as cur:
                cur.execute('select 1 as a, 2 as b')
                self.assertDictEqual({'a': 1, 'b': 2}, cur.fetchone())


def _params_tests(self):
    def test_val(typ, val):
        with self.conn.cursor() as cur:
            param = Param(type=typ, value=val)
            logger.info("Testing with %s", repr(param))
            cur.execute('select %s', [param])
            self.assertTupleEqual(cur.fetchone(), (val,))
            self.assertIs(cur.fetchone(), None)

    test_val(BitType(), True)
    test_val(BitType(), False)
    test_val(BitType(), None)
    test_val(TinyIntType(), 255)
    test_val(SmallIntType(), 2 ** 15 - 1)
    test_val(IntType(), 2 ** 31 - 1)
    test_val(BigIntType(), 2 ** 63 - 1)
    test_val(IntType(), None)
    test_val(RealType(), 0.25)
    test_val(FloatType(), 0.25)
    test_val(RealType(), None)
    test_val(SmallDateTimeType(), datetime(1900, 1, 1, 0, 0, 0))
    test_val(SmallDateTimeType(), datetime(2079, 6, 6, 23, 59, 0))
    test_val(DateTimeType(), datetime(1753, 1, 1, 0, 0, 0))
    test_val(DateTimeType(), datetime(9999, 12, 31, 23, 59, 59, 990000))
    test_val(DateTimeType(), None)
    if pytds.tds_base.IS_TDS73_PLUS(self.conn._conn):
        test_val(DateType(), date(1, 1, 1))
        test_val(DateType(), date(9999, 12, 31))
        test_val(DateType(), None)
        test_val(TimeType(precision=0), time(0, 0, 0))
        test_val(TimeType(precision=6), time(23, 59, 59, 999999))
        test_val(TimeType(precision=0), None)
        test_val(DateTime2Type(precision=0), datetime(1, 1, 1, 0, 0, 0))
        test_val(DateTime2Type(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999))
        test_val(DateTime2Type(precision=0), None)
        test_val(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, utc))
        test_val(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, tzoffset(14)))
        test_val(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(-14)))
        #test_val(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(14)))
        test_val(DateTimeOffsetType(precision=6), None)
    test_val(DecimalType(scale=6, precision=38), Decimal('123.456789'))
    test_val(DecimalType(scale=6, precision=38), None)
    test_val(SmallMoneyType(), Decimal('-214748.3648'))
    test_val(SmallMoneyType(), Decimal('214748.3647'))
    test_val(MoneyType(), Decimal('922337203685477.5807'))
    test_val(MoneyType(), Decimal('-922337203685477.5808'))
    test_val(MoneyType(), None)
    test_val(UniqueIdentifierType(), None)
    test_val(UniqueIdentifierType(), uuid.uuid4())
    if pytds.tds_base.IS_TDS71_PLUS(self.conn._conn):
        test_val(VariantType(), None)
        #test_val(self.conn._conn.type_factory.SqlVariant(10), 100)
    test_val(VarBinaryType(size=10), b'')
    test_val(VarBinaryType(size=10), b'testtest12')
    test_val(VarBinaryType(size=10), None)
    test_val(VarBinaryType(size=8000), b'x' * 8000)
    test_val(VarCharType(size=10), None)
    test_val(VarCharType(size=10), '')
    test_val(VarCharType(size=10), 'test')
    test_val(VarCharType(size=8000), 'x' * 8000)
    test_val(NVarCharType(size=10), u'')
    test_val(NVarCharType(size=10), u'testtest12')
    test_val(NVarCharType(size=10), None)
    test_val(NVarCharType(size=4000), u'x' * 4000)
    test_val(TextType(), None)
    test_val(TextType(), '')
    test_val(TextType(), 'hello')
    test_val(NTextType(), None)
    test_val(NTextType(), '')
    test_val(NTextType(), 'hello')
    test_val(ImageType(), None)
    test_val(ImageType(), b'')
    test_val(ImageType(), b'test')
    if pytds.tds_base.IS_TDS72_PLUS(self.conn._conn):
        test_val(VarBinaryMaxType(), None)
        test_val(VarBinaryMaxType(), b'')
        test_val(VarBinaryMaxType(), b'testtest12')
        test_val(VarBinaryMaxType(), b'x' * (10 ** 6))
        test_val(NVarCharMaxType(), None)
        test_val(NVarCharMaxType(), 'test')
        test_val(NVarCharMaxType(), 'x' * (10 ** 6))
        test_val(VarCharMaxType(), None)
        test_val(VarCharMaxType(), 'test')
        test_val(VarCharMaxType(), 'x' * (10 ** 6))
        test_val(XmlType(), '<root/>')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds70(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds_base.TDS70
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds71(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = settings.DATABASE
        kwargs['tds_version'] = pytds.tds_base.TDS71
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)
        utils.create_test_database(self.conn)
        self.conn.commit()

    def test_parsing(self):
        _params_tests(self)

    def test_transaction(self):
        self.conn.rollback()
        self.conn.commit()

    def test_bulk(self):
        f = StringIO("42\tfoo\n74\tbar\n")
        with self.conn.cursor() as cur:
            cur.copy_to(f, 'bulk_insert_table', schema='myschema', columns=('num', 'data'))
            cur.execute('select num, data from myschema.bulk_insert_table')
            self.assertListEqual(cur.fetchall(), [(42, 'foo'), (74, 'bar')])

    def test_call_proc(self):
        with self.conn.cursor() as cur:
            val = 45
            values = cur.callproc('testproc', (val, default, output(value=1)))
            #self.assertEqual(cur.fetchall(), [(val,)])
            self.assertEqual(val + 2, values[2])
            self.assertEqual(val + 2, cur.get_proc_return_status())


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds72(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds_base.TDS72
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73A(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds_base.TDS73A
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73B(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds_base.TDS73B
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)

@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestRawBytes(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['bytes_to_unicode'] = False
        kwargs['database'] = 'master'
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_fetch(self):
        cur = self.conn.cursor()

        self.assertIsInstance(cur.execute_scalar("select cast('abc' as nvarchar(max))"), str)
        self.assertIsInstance(cur.execute_scalar("select cast('abc' as varchar(max))"), bytes)
        self.assertIsInstance(cur.execute_scalar("select cast('abc' as text)"), bytes)

        self.assertIsInstance(cur.execute_scalar("select %s", ['abc']), str)
        self.assertIsInstance(cur.execute_scalar("select %s", [b'abc']), bytes)

        rawBytes = b'\x01\x02\x03'
        self.assertEqual(rawBytes, cur.execute_scalar("select cast(0x010203 as varchar(max))"))
        self.assertEqual(rawBytes, cur.execute_scalar("select %s", [rawBytes]))

        utf8char = b'\xee\xb4\xba'
        self.assertEqual(utf8char, cur.execute_scalar("select %s", [utf8char]))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_invalid_block_size():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update({
        'blocksize': 4000,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute_scalar("select '{}'".format('x' * 8000))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_readonly_connection():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update({
        'readonly': True,
    })
    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute_scalar("select 1")
