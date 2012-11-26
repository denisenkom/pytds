# vim: set fileencoding=utf8 :
import unittest
import sys
from decimal import Decimal
import logging
from datetime import datetime, date, time
from pytds import *
from pytds.tds import *

try:
    import settings
except:
    print('Settings module is not found, please create settings module and specify HOST, DATATABSE, USER and PASSWORD there')
    sys.exit(1)

#logging.basicConfig(level='DEBUG')
#logging.basicConfig(level='INFO')
logging.basicConfig()

conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD)

class TestCase(unittest.TestCase):
    def test_all(self):
        cur = conn.cursor()
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

    def test_dates(self):
        cur = conn.cursor()
        assert datetime(2010, 1, 2) == cur.execute_scalar("select cast('2010-01-02T00:00:00' as smalldatetime) as fieldname")
        assert datetime(2010, 1, 2) == cur.execute_scalar("select cast('2010-01-02T00:00:00' as datetime) as fieldname")
        if IS_TDS73_PLUS(conn.tds_socket):
            self.assertEqual(date(2010, 1, 2), cur.execute_scalar("select cast('2010-01-02T00:00:00' as date) as fieldname"))
            assert time(14,16,18,123456) == cur.execute_scalar("select cast('14:16:18.1234567' as time) as fieldname")
            assert datetime(2010, 1, 2, 20, 21, 22, 345678) == cur.execute_scalar("select cast('2010-01-02T20:21:22.345678' as datetime2) as fieldname")
            assert datetime(2010, 1, 2, 15, 21, 22, 123456, FixedOffset(5*60, '')) == cur.execute_scalar("select cast('2010-01-02T20:21:22.1234567+05:00' as datetimeoffset) as fieldname")

    def test_decimals(self):
        cur = conn.cursor()
        assert Decimal(12) == cur.execute_scalar('select cast(12 as decimal) as fieldname')
        assert Decimal(-12) == cur.execute_scalar('select cast(-12 as decimal) as fieldname')
        assert Decimal('123456.12345') == cur.execute_scalar("select cast('123456.12345'as decimal(20,5)) as fieldname")
        assert Decimal('-123456.12345') == cur.execute_scalar("select cast('-123456.12345'as decimal(20,5)) as fieldname")

    def test_money(self):
        cur = conn.cursor()
        assert Decimal('0') == cur.execute_scalar("select cast('0' as money) as fieldname")
        assert Decimal('1') == cur.execute_scalar("select cast('1' as money) as fieldname")
        assert Decimal('1.5555') == cur.execute_scalar("select cast('1.5555' as money) as fieldname")
        assert Decimal('1234567.5555') == cur.execute_scalar("select cast('1234567.5555' as money) as fieldname")
        assert Decimal('-1234567.5555') == cur.execute_scalar("select cast('-1234567.5555' as money) as fieldname")
        assert Decimal('12345.55') == cur.execute_scalar("select cast('12345.55' as smallmoney) as fieldname")

class ParametrizedQueriesTestCase(unittest.TestCase):
    def _test_val(self, val):
        cur = conn.cursor()
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

class TableTestCase(unittest.TestCase):
    def setUp(self):
        cur = conn.cursor()
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
        cur = conn.cursor()
        cur.execute('select id from testtable order by id')
        self.assertEqual([(1,)], cur.fetchall())

        cur = conn.cursor()
        cur.execute('select _text from testtable order by id')
        self.assertEqual([(u'text',)], cur.fetchall())

        cur = conn.cursor()
        cur.execute('select _xml from testtable order by id')
        self.assertEqual([('<root/>',)], cur.fetchall())

        cur = conn.cursor()
        cur.execute('insert into testtable (_xml) values (%s)', ('<some/>',))

    def tearDown(self):
        cur = conn.cursor()
        cur.execute(u'drop table testtable')

class StoredProcsTestCase(unittest.TestCase):
    def _drop_sp(self):
        cur = conn.cursor()
        cur.execute('''
        if object_id('testproc') is not null
            drop procedure testproc
        ''')
    def setUp(self):
        self._drop_sp()
        cur = conn.cursor()
        cur.execute('''
        create procedure testproc (@param int)
        as
        begin
            select @param
            return @param + 1
        end
        ''')
    def tearDown(self):
        self._drop_sp()

    def runTest(self):
        cur = conn.cursor()
        val = 45
        cur.callproc('testproc', {'@param': val})
        self.assertEqual(cur.fetchall(), [(val,)])
        self.assertEqual(val + 1, cur.get_proc_return_status())

class CursorCloseTestCase(unittest.TestCase):
    def runTest(self):
        with conn.cursor() as cur:
            cur.execute('select 10; select 12')
            cur.fetchone()
        with conn.cursor() as cur2:
            cur2.execute('select 20')
            cur2.fetchone()

class MultipleRecordsetsTestCase(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
        cur.execute('select 10; select 12')
        self.assertEqual((10,), cur.fetchone())
        self.assertTrue(cur.nextset())
        self.assertEqual((12,), cur.fetchone())
        self.assertFalse(cur.nextset())

class TransactionsTestCase(unittest.TestCase):
    def _create_table(self):
        with conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        conn.commit()
        with conn.cursor() as cur:
            cur.execute('''
            create table testtable (field datetime)
            ''')

    def runTest(self):
        self._create_table()
        with conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertNotEquals((None,), cur.fetchone())
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertEquals((None,), cur.fetchone())
        self._create_table()
        conn.commit()
        with conn.cursor() as cur:
            cur.execute("select object_id('testtable')")
            self.assertNotEquals((None,), cur.fetchone())

    def tearDown(self):
        with conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        conn.commit()

class MultiPacketRequest(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
        param = 'x' * (conn.tds_socket._writer.bufsize*10)
        cur.execute('select %s', (param,))
        self.assertEqual([(param, )], cur.fetchall())

class BigRequest(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
        param = 'x' * 5000
        params = (10, datetime(2012, 11, 19, 1, 21, 37, 3000), param, 'test')
        cur.execute('select %s, %s, %s, %s', params)
        self.assertEqual([params], cur.fetchall())

class Rowcount(unittest.TestCase):
    def _create_table(self):
        cur = conn.cursor()
        cur.execute('''
        if object_id('testtable') is not null
            drop table testtable
        ''')
        cur.execute('''
        create table testtable (field int)
        ''')

    def setUp(self):
        self._create_table()

    def runTest(self):
        cur = conn.cursor()
        cur.execute('insert into testtable (field) values (1)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('insert into testtable (field) values (2)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('select * from testtable')
        cur.fetchall()
        #self.assertEqual(cur.rowcount, 2)

    def tearDown(self):
        conn.rollback()

class NoRows(unittest.TestCase):
    def _create_table(self):
        cur = conn.cursor()
        cur.execute('''
        if object_id('testtable') is not null
            drop table testtable
        ''')
        cur.execute('''
        create table testtable (field int)
        ''')

    def setUp(self):
        self._create_table()

    def runTest(self):
        cur = conn.cursor()
        cur.execute('select * from testtable')
        self.assertEqual([], cur.fetchall())

    def tearDown(self):
        conn.rollback()

class SqlVariant(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
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

class BadConnection(unittest.TestCase):
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

class NullXml(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
        cur.execute('select cast(NULL as xml)')
        self.assertEqual([(None,)], cur.fetchall())
        cur.execute('select cast(%s as xml)', (None,))
        self.assertEqual([(None,)], cur.fetchall())

class ConnectionClosing(unittest.TestCase):
    def runTest(self):
        for x in xrange(10000):
            connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD).close()

class Description(unittest.TestCase):
    def runTest(self):
        with conn.cursor() as cur:
            cur.execute('select cast(12.65 as decimal(4,2)) as testname')
            self.assertEqual(cur.description[0][0], 'testname')
            self.assertEqual(cur.description[0][1], DECIMAL)
            self.assertEqual(cur.description[0][4], 4)
            self.assertEqual(cur.description[0][5], 2)

class Bug1(unittest.TestCase):
    def runTest(self):
        conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD+'bad')
        cur = conn.cursor()
        try:
            cur.execute('select 1')
            cur.fetchall()
        except:
            pass
        cur.close()
        conn.rollback()

class BinaryTest(unittest.TestCase):
    def runTest(self):
        binary = '\x00\x01\x02'
        cur = conn.cursor()
        cur.execute('select %s', (Binary(binary),))
        self.assertEqual([(binary,)], cur.fetchall())

class GuitTest(unittest.TestCase):
    def runTest(self):
        cur = conn.cursor()
        val = uuid.uuid4()
        cur.execute('select %s', (val,))
        self.assertEqual([(val,)], cur.fetchall())

#class EncryptionTest(unittest.TestCase):
#    def runTest(self):
#        conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD, encryption_level=TDS_ENCRYPTION_REQUIRE)
#        cur = conn.cursor()
#        cur.execute('select 1')


if __name__ == '__main__':
    unittest.main()
