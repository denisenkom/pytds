# vim: set fileencoding=utf8 :
from __future__ import with_statement
import unittest
import sys
from decimal import Decimal, getcontext
import logging
from datetime import datetime, date, time
import uuid
import socket
from dateutil.tz import tzoffset, tzutc
from pytds import connect, ProgrammingError, TimeoutError, Time, SimpleLoadBalancer, LoginError,\
    Error, IntegrityError, Timestamp, DataError, DECIMAL, TDS72, Date, Binary, Datetime, SspiAuth,\
    tds_submit_query, tds_process_tokens, TDS_TOKEN_RESULTS

# set decimal precision to match mssql maximum precision
getcontext().prec = 38

try:
    import settings
except:
    print('Settings module is not found, please create settings module and specify HOST, DATATABSE, USER and PASSWORD there')
    sys.exit(1)

#logging.basicConfig(level='DEBUG')
#logging.basicConfig(level='INFO')
logging.basicConfig()

class TestCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
    def tearDown(self):
        self.conn.close()

class TestCase2(TestCase):
    def test_all(self):
        cur = self.conn.cursor()
        with self.assertRaises(ProgrammingError):
            cur.execute(u'select ')
        assert 'abc' == cur.execute_scalar("select cast('abc' as nvarchar(max)) as fieldname")
        assert 'abc' == cur.execute_scalar("select cast('abc' as varbinary(max)) as fieldname")
        #assert 12 == cur.execute_scalar('select cast(12 as bigint) as fieldname')
        assert 12 == cur.execute_scalar('select cast(12 as smallint) as fieldname')
        assert -12 == cur.execute_scalar('select -12 as fieldname')
        assert 12 == cur.execute_scalar('select cast(12 as tinyint) as fieldname')
        assert True == cur.execute_scalar('select cast(1 as bit) as fieldname')
        assert 5.1 == cur.execute_scalar('select cast(5.1 as float) as fieldname')
        cur.execute("select 'test', 20")
        assert ('test', 20) == cur.fetchone()
        assert 'test' == cur.execute_scalar("select 'test' as fieldname")
        assert 'test' == cur.execute_scalar("select N'test' as fieldname")
        assert 5 == cur.execute_scalar('select 5 as fieldname')

    def test_decimals(self):
        cur = self.conn.cursor()
        assert Decimal(12) == cur.execute_scalar('select cast(12 as decimal) as fieldname')
        assert Decimal(-12) == cur.execute_scalar('select cast(-12 as decimal) as fieldname')
        assert Decimal('123456.12345') == cur.execute_scalar("select cast('123456.12345'as decimal(20,5)) as fieldname")
        assert Decimal('-123456.12345') == cur.execute_scalar("select cast('-123456.12345'as decimal(20,5)) as fieldname")

    def test_money(self):
        cur = self.conn.cursor()
        assert Decimal('0') == cur.execute_scalar("select cast('0' as money) as fieldname")
        assert Decimal('1') == cur.execute_scalar("select cast('1' as money) as fieldname")
        self.assertEqual(Decimal('1.5555'), cur.execute_scalar("select cast('1.5555' as money) as fieldname"))
        assert Decimal('1234567.5555') == cur.execute_scalar("select cast('1234567.5555' as money) as fieldname")
        assert Decimal('-1234567.5555') == cur.execute_scalar("select cast('-1234567.5555' as money) as fieldname")
        assert Decimal('12345.55') == cur.execute_scalar("select cast('12345.55' as smallmoney) as fieldname")

    def test_timeout(self):
        conn = connect(login_timeout=1, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
        cur = conn.cursor()
        with self.assertRaises(TimeoutError):
            cur.execute("waitfor delay '00:00:05'")
        cur.execute('select 1')

class ParametrizedQueriesTestCase(TestCase):
    def _test_val(self, val):
        cur = self.conn.cursor()
        cur.execute('select %s', (val,))
        self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        self._test_val(u'hello')
        self._test_val(123)
        self._test_val(-123)
        self._test_val(123.12)
        self._test_val(-123.12)
        self._test_val(datetime(2011, 2, 3, 10, 11, 12, 3000))
        self._test_val(Decimal('1234.567'))
        self._test_val(Decimal('1234000'))
        self._test_val(None)
        self._test_val('hello')
        self._test_val('')
        self._test_val(2**34)
        self._test_val(2**63 - 1)
        self._test_val(100L)
        self._test_val(False)
        self._test_val(True)

class TableTestCase(TestCase):
    def setUp(self):
        super(TableTestCase, self).setUp()
        cur = self.conn.cursor()
        cur.execute('''
        if object_id('testtable') is not null
            drop table testtable
        ''')
        cur.execute(u'''
        create table testtable (id int, _text text, _xml xml)
        ''')
        cur.execute(u'''
        insert into testtable (id, _text, _xml) values (1, 'text', '<root/>')
        ''')

    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('select id from testtable order by id')
        self.assertEqual([(1,)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('select _text from testtable order by id')
        self.assertEqual([(u'text',)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('select _xml from testtable order by id')
        self.assertEqual([('<root/>',)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('insert into testtable (_xml) values (%s)', ('<some/>',))

    def tearDown(self):
        cur = self.conn.cursor()
        cur.execute(u'drop table testtable')
        super(TableTestCase, self).tearDown()

class StoredProcsTestCase(TestCase):
    def _drop_sp(self):
        cur = self.conn.cursor()
        cur.execute('''
        if object_id('testproc') is not null
            drop procedure testproc
        ''')
    def setUp(self):
        super(StoredProcsTestCase, self).setUp()
        self._drop_sp()
        cur = self.conn.cursor()
        cur.execute('''
        create procedure testproc (@param int)
        as
        begin
            select @param
            return @param + 1
        end
        ''')

    def runTest(self):
        cur = self.conn.cursor()
        val = 45
        cur.callproc('testproc', {'@param': val})
        self.assertEqual(cur.fetchall(), [(val,)])
        self.assertEqual(val + 1, cur.get_proc_return_status())

class CursorCloseTestCase(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('select 10; select 12')
            cur.fetchone()
        with self.conn.cursor() as cur2:
            cur2.execute('select 20')
            cur2.fetchone()

class MultipleRecordsetsTestCase(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('select 10; select 12')
        self.assertEqual((10,), cur.fetchone())
        self.assertTrue(cur.nextset())
        self.assertEqual((12,), cur.fetchone())
        self.assertFalse(cur.nextset())

class TransactionsTestCase(TestCase):
    def _create_table(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        self.conn.commit()
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable (field datetime)
            ''')

    def runTest(self):
        self._create_table()
        with self.conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertNotEquals((None,), cur.fetchone())
        self.conn.rollback()
        with self.conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertEquals((None,), cur.fetchone())
        self._create_table()
        self.conn.commit()
        with self.conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertNotEquals((None,), cur.fetchone())

    def tearDown(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        self.conn.commit()
        super(TransactionsTestCase, self).tearDown()

class MultiPacketRequest(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        param = 'x' * (self.conn._conn.main_session._writer.bufsize*3)
        cur.execute('select %s', (param,))
        self.assertEqual([(param, )], cur.fetchall())

class BigRequest(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        param = 'x' * 5000
        params = (10, datetime(2012, 11, 19, 1, 21, 37, 3000), param, 'test')
        cur.execute('select %s, %s, %s, %s', params)
        self.assertEqual([params], cur.fetchall())

class ReadAllBug(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        params = ('x' * 5000,)
        cur.execute('select cast(%s as varchar(5000))', params)
        self.assertEqual([params], cur.fetchall())

class Rowcount(TestCase):
    def _create_table(self):
        cur = self.conn.cursor()
        cur.execute('''
        if object_id('testtable') is not null
            drop table testtable
        ''')
        cur.execute('''
        create table testtable (field int)
        ''')

    def setUp(self):
        super(Rowcount, self).setUp()
        self._create_table()

    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('insert into testtable (field) values (1)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('insert into testtable (field) values (2)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('select * from testtable')
        cur.fetchall()
        #self.assertEqual(cur.rowcount, 2)

class NoRows(TestCase):
    def _create_table(self):
        cur = self.conn.cursor()
        cur.execute('''
        if object_id('testtable') is not null
            drop table testtable
        ''')
        cur.execute('''
        create table testtable (field int)
        ''')

    def setUp(self):
        super(NoRows, self).setUp()
        self._create_table()

    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('select * from testtable')
        self.assertEqual([], cur.fetchall())

class SqlVariant(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute("select cast('test' as sql_variant)")
        self.assertEqual([('test',)], cur.fetchall())

        cur.execute("select cast(N'test' as sql_variant)")
        self.assertEqual([('test',)], cur.fetchall())

        cur.execute("select cast(100 as sql_variant)")
        self.assertEqual([(100,)], cur.fetchall())

        cur.execute("select cast(cast(100.55555 as decimal(8,5)) as sql_variant)")
        self.assertEqual([(Decimal('100.55555'),)], cur.fetchall())

        cur.execute("select cast(cast('test' as varbinary) as sql_variant)")
        self.assertEqual([('test',)], cur.fetchall())

class BadConnection(TestCase):
    def runTest(self):
        with self.assertRaises(Error):
            conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD+'bad')
            conn.cursor().execute('select 1')
        with self.assertRaises(Error):
            conn = connect(server=settings.HOST+'bad', database=settings.DATABASE, user=settings.USER+'bad', password=settings.PASSWORD)
            conn.cursor().execute('select 1')
        with self.assertRaises(Error):
            conn = connect(server=settings.HOST, database=settings.DATABASE+'x', user=settings.USER, password=settings.PASSWORD)
            conn.cursor().execute('select 1')
        with self.assertRaises(Error):
            conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=None)
            conn.cursor().execute('select 1')

class NullXml(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('select cast(NULL as xml)')
        self.assertEqual([(None,)], cur.fetchall())
        cur.execute('select cast(%s as xml)', (None,))
        self.assertEqual([(None,)], cur.fetchall())


class ConnectionClosing(unittest.TestCase):
    def test_open_close(self):
        for x in xrange(3):
            connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD).close()

    def test_connection_closed_by_server(self):
        with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD) as conn:
            # test overall recovery
            conn._conn._sock.close()
            with conn.cursor() as cur:
                with self.assertRaises(socket.error):
                    cur.execute('select 1')
                cur.execute('select 1')
                cur.fetchall()
            with conn.cursor() as cur:
                # test recovery of specific lowlevel methods
                tds_submit_query(cur._session, 'select 1')
                conn._conn._sock.close()
                self.assertTrue(cur._session.is_connected())
                with self.assertRaises(socket.error):
                    tds_process_tokens(cur._session, TDS_TOKEN_RESULTS)
                self.assertFalse(cur._session.is_connected())


class Description(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('select cast(12.65 as decimal(4,2)) as testname')
            self.assertEqual(cur.description[0][0], 'testname')
            self.assertEqual(cur.description[0][1], DECIMAL)
            self.assertEqual(cur.description[0][4], 4)
            self.assertEqual(cur.description[0][5], 2)

class Bug1(TestCase):
    def runTest(self):
        try:
            conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD+'bad')
            cur = conn.cursor()
            cur.execute('select 1')
            cur.fetchall()
            cur.close()
            conn.rollback()
        except:
            pass

class BinaryTest(TestCase):
    def runTest(self):
        binary = '\x00\x01\x02'
        cur = self.conn.cursor()
        cur.execute('select %s', (Binary(binary),))
        self.assertEqual([(binary,)], cur.fetchall())

class GuidTest(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        val = uuid.uuid4()
        cur.execute('select %s', (val,))
        self.assertEqual([(val,)], cur.fetchall())

#class EncryptionTest(unittest.TestCase):
#    def runTest(self):
#        conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD, encryption_level=TDS_ENCRYPTION_REQUIRE)
#        cur = conn.cursor()
#        cur.execute('select 1')

class Bug2(TestCase):
    def _drop_sp(self):
        cur = self.conn.cursor()
        cur.execute('''
        if object_id('testproc') is not null
            drop procedure testproc
        ''')
    def setUp(self):
        super(Bug2, self).setUp()
        self._drop_sp()
        cur = self.conn.cursor()
        cur.execute('''
        create procedure testproc (@param int)
        as
        begin
            set transaction isolation level read uncommitted -- that will produce very empty result (even no rowcount)
            select @param
            return @param + 1
        end
        ''')

    def runTest(self):
        with self.conn.cursor() as cur:
            val = 45
            cur.execute('exec testproc @param = 45')
            self.assertEqual(cur.fetchall(), [(val,)])
            self.assertEqual(val + 1, cur.get_proc_return_status())

class Bug3(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.close()

class DateAndTimeParams(TestCase):
    def test_date(self):
        with self.conn.cursor() as cur:
            date = Date(2012, 10, 6)
            cur.execute('select %s', (date, ))
            self.assertEqual(cur.fetchall(), [(date,)])

    def test_time(self):
        with self.conn.cursor() as cur:
            time = Time(8, 7, 4, 123456)
            cur.execute('select %s', (time, ))
            self.assertEqual(cur.fetchall(), [(time,)])

    def test_datetime(self):
        with self.conn.cursor() as cur:
            time = Timestamp(2013, 7, 9, 8, 7, 4, 123456)
            cur.execute('select %s', (time, ))
            self.assertEqual(cur.fetchall(), [(time,)])

class Bug4(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            set transaction isolation level read committed
            select 1
            ''')
            self.assertEqual(cur.fetchall(), [(1,)])

class FixedSizeChar(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
            cur.execute('''
            create table testtable (chr char(5), nchr nchar(5), bfld binary(5))
            insert into testtable values ('1', '2', cast('3' as binary(5)))
            ''')
            cur.execute('select * from testtable')
            self.assertEqual(cur.fetchall(), [('1    ', '2    ', '3\x00\x00\x00\x00')])

class EdgeCases(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select %s', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        with self.conn.cursor() as cur:
            self._testval(10**20)
            self._testval(10**38-1)
            self._testval(-10**38+1)
            with self.assertRaises(DataError):
                self._testval(-10**38)
            ##cur.execute('select %s', '\x00'*(2**31))
            self._testval(Decimal('9'*38))
            self._testval(Decimal('0.'+'9'*38))
            self._testval(-Decimal('9'*38))
            self._testval(Decimal('1E10'))
            self._testval(Decimal('1E-10'))
            self._testval(Decimal('0.{0}1'.format('0'*37)))
            with self.assertRaises(DataError):
                self._testval(Decimal('1' + '0'*38))
            with self.assertRaises(DataError):
                self._testval(Decimal('-1' + '0'*38))
            with self.assertRaises(DataError):
                self._testval(Decimal('1E38'))

class Extensions(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            self.assertEqual(cur.connection, self.conn)

class SmallDateTime(TestCase):
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

class DateTime(TestCase):
    def _testencdec(self, val):
        self.assertEqual(val, Datetime.decode(Datetime.encode(val)))
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        self.assertEqual(Datetime.decode('\xf2\x9c\x00\x00}uO\x01'), Timestamp(2010, 1, 2, 20, 21, 22, 123000))
        self.assertEqual(Datetime.decode('\x7f$-\x00\xff\x81\x8b\x01'), Datetime.max)
        self.assertEqual('\xf2\x9c\x00\x00}uO\x01', Datetime.encode(Timestamp(2010, 1, 2, 20, 21, 22, 123000)))
        self.assertEqual('\x7f$-\x00\xff\x81\x8b\x01', Datetime.encode(Datetime.max))
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

class DateTimeOffset(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetimeoffset)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        if self.conn.tds_version < TDS72:
            return
        with self.conn.cursor() as cur:
            cur.execute("select cast('2010-01-02T20:21:22.1234567+05:00' as datetimeoffset)")
            self.assertEqual(datetime(2010, 1, 2, 20, 21, 22, 123456, tzoffset('', 5*60*60)), cur.fetchone()[0])
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzutc()))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', 5*60*60)))
        self._testval(Timestamp(1, 1, 1, 0, 0, 0, 0, tzutc()))
        self._testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999, tzutc()))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', 14*60)))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', -14*60)))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', -15*60)))

class TimeTest(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as time)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute("select cast('20:21:22.1234567' as time)")
            self.assertEqual(Time(20, 21, 22, 123456), cur.fetchone()[0])
        self._testval(Time(14,16,18,123456))
        self._testval(Time(0, 0, 0, 0))
        self._testval(Time(0, 0, 0, 0))
        self._testval(Time(0, 0, 0, 0))
        self._testval(Time(23, 59, 59, 999999))
        self._testval(Time(0, 0, 0, 0))
        self._testval(Time(0, 0, 0, 0))
        self._testval(Time(0, 0, 0, 0))

class DateTime2(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetime2)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute("select cast('9999-12-31T23:59:59.999999' as datetime2)")
            self.assertEqual(cur.fetchall(), [(Timestamp(9999, 12, 31, 23, 59, 59, 999999),)])
        self._testval(Timestamp(2010, 1, 2, 20, 21, 22, 345678))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0))
        self._testval(Timestamp(1, 1, 1, 0, 0, 0))
        self._testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999))

class DateTest(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as date)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        if self.conn.tds_version < TDS72:
            return
        with self.conn.cursor() as cur:
            cur.execute("select cast('9999-12-31T00:00:00' as date)")
            self.assertEqual(cur.fetchall(), [(Date(9999, 12, 31),)])
        self._testval(Date(2010, 1, 2))
        self._testval(Date(2010, 1, 2))
        self._testval(Date(1, 1, 1))
        self._testval(Date(9999, 12, 31))


class Auth(unittest.TestCase):
    #def test_ntlm(self):
    #    conn = connect(settings.HOST, auth=NtlmAuth(user_name=settings.NTLM_USER, password=settings.NTLM_PASSWORD))
    #    with conn.cursor() as cursor:
    #        cursor.execute('select 1')
    #        cursor.fetchall()

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sspi(self):
        conn = connect(settings.HOST, auth=SspiAuth())
        with conn.cursor() as cursor:
            cursor.execute('select 1')
            cursor.fetchall()

    def test_sqlauth(self):
        conn = connect(settings.HOST, user=settings.USER, password=settings.PASSWORD)
        with conn.cursor() as cursor:
            cursor.execute('select 1')
            cursor.fetchall()


class CloseCursorTwice(TestCase):
    def runTest(self):
        cursor = self.conn.cursor()
        cursor.close()
        cursor.close()


class RegressionSuite(TestCase):
    def test_commit(self):
        if self.conn.mars_enabled:
            self.skipTest('Only breaks when mars is disabled')
        cursor = self.conn.cursor()
        cursor.execute('select 1')
        cursor.fetchall()
        self.conn.commit()


class TestLoadBalancer(TestCase):
    def test_second(self):
        lb = SimpleLoadBalancer(['badserver', settings.CONNECT_KWARGS['server']])
        with connect(load_balancer=lb, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS) as conn:
            with conn.cursor() as cur:
                cur.execute('select 1')
                cur.fetchall()

    def test_none(self):
        lb = SimpleLoadBalancer(['badserver'])
        with self.assertRaises(LoginError):
            with connect(load_balancer=lb, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    cur.fetchall()


class TestIntegrityError(TestCase):
    def test_primary_key(self):
        cursor = self.conn.cursor()
        cursor.execute('create table testtable(pk int primary key)')
        cursor.execute('insert into testtable values (1)')
        with self.assertRaises(IntegrityError):
            cursor.execute('insert into testtable values (1)')
        cursor.execute('drop table testtable')


class TimezoneTests(unittest.TestCase):
    def check_val(self, conn, sql, input, output):
        with conn.cursor() as cur:
            cur.execute('select ' + sql, (input,))
            rows = cur.fetchall()
            self.assertEqual(rows[0][0], output)

    def runTest(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        use_tz = tzutc()
        kwargs['use_tz'] = use_tz
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            # Naive time should be interpreted as use_tz
            self.check_val(conn, '%s',
                           datetime(2011, 2, 3, 10, 11, 12, 3000),
                           datetime(2011, 2, 3, 10, 11, 12, 3000, tzutc()))
            # Aware time shoule be passed as-is
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset('', 60))
            self.check_val(conn, '%s', dt, dt)
            # Aware time should be converted to use_tz if not using datetimeoffset type
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset('', 60))
            self.check_val(conn, 'cast(%s as datetime2)', dt, dt.astimezone(use_tz))


class _FakeSock(object):
    def __init__(self, messages):
        self._stream = b''.join(messages)

    def recv(self, size):
        if not self._stream:
            return b''
        res = self._stream[:size]
        self._stream = self._stream[size:]
        return res

    def send(self, buf, flags):
        self._sent = buf
        return len(buf)

    def setsockopt(self, *args):
        pass

    def close(self):
        self._stream = b''


class TestMessages(unittest.TestCase):
    def _make_login(self):
        from pytds.dbapi import _TdsLogin
        from pytds.tds import TDS74
        login = _TdsLogin()
        login.blocksize = 4096
        login.use_tz = None
        login.query_timeout = login.connect_timeout = 60
        login.tds_version = TDS74
        login.instance_name = None
        login.encryption_level = None
        login.use_mars = False
        login.option_flag2 = 0
        login.user_name = 'testname'
        login.password = 'password'
        login.app_name = 'appname'
        login.server_name = 'servername'
        login.library = 'library'
        login.language = 'EN'
        login.database = 'SubmissionPortal'
        login.auth = None
        login.bulk_copy = False
        login.readonly = False
        login.client_lcid = 100
        login.attach_db_file = ''
        login.text_size = 0
        login.emul_little_endian = True
        return login

    def test_login(self):
        from pytds.tds import _TdsSocket
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\x07\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01s\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b'\x04\x01\x00#\x00Z\x01\x00\xe3\x0b\x00\x08\x08\x01\x00\x00\x00Z\x00\x00\x00\x00\xfd\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            ])
        _TdsSocket(self._make_login(), sock)

        # test connection close on first message
        sock = _FakeSock([
            b'\x04\x01\x00+\x00',
            ])
        with self.assertRaises(Error):
            _TdsSocket(self._make_login(), sock)

        # test connection close on second message
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S",
            ])
        with self.assertRaises(Error):
            _TdsSocket(self._make_login(), sock)
