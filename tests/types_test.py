# coding=utf-8
import datetime
from decimal import Decimal, Context
import uuid

import pytest

import pytds

from fixtures import *


@pytest.mark.parametrize(
    "sql_type",
    [
        "tinyint",
        "smallint",
        "int",
        "bigint",
        "real",
        "float",
        "smallmoney",
        "money",
        "decimal",
        "varbinary(15)",
        "binary(15)",
        "nvarchar(15)",
        "nchar(15)",
        "varchar(15)",
        "char(15)",
        "bit",
        "smalldatetime",
        "date",
        "time",
        "datetime",
        "datetime2",
        "datetimeoffset",
        "uniqueidentifier",
        "sql_variant",
    ],
)
def test_null_parameter(cursor, sql_type):
    cursor.execute(
        "set nocount on; declare @x {} = %s; select @x".format(sql_type), (None,)
    )
    (val,) = cursor.fetchone()
    assert val is None


def test_reading_values(cursor):
    cur = cursor
    with pytest.raises(pytds.ProgrammingError):
        cur.execute("select ")
    assert "abc" == cur.execute_scalar(
        "select cast('abc' as varchar(max)) as fieldname"
    )
    assert "abc" == cur.execute_scalar(
        "select cast('abc' as nvarchar(max)) as fieldname"
    )
    assert b"abc" == cur.execute_scalar(
        "select cast('abc' as varbinary(max)) as fieldname"
    )
    # assert 12 == cur.execute_scalar('select cast(12 as bigint) as fieldname')
    assert 12 == cur.execute_scalar("select cast(12 as smallint) as fieldname")
    assert -12 == cur.execute_scalar("select -12 as fieldname")
    assert 12 == cur.execute_scalar("select cast(12 as tinyint) as fieldname")
    assert True == cur.execute_scalar("select cast(1 as bit) as fieldname")
    assert 5.1 == cur.execute_scalar("select cast(5.1 as float) as fieldname")
    cur.execute("select 'test', 20")
    assert ("test", 20) == cur.fetchone()
    assert "test" == cur.execute_scalar("select 'test' as fieldname")
    assert "test" == cur.execute_scalar("select N'test' as fieldname")
    assert "test" == cur.execute_scalar("select cast(N'test' as ntext) as fieldname")
    assert "test" == cur.execute_scalar("select cast(N'test' as text) as fieldname")
    assert "test " == cur.execute_scalar("select cast(N'test' as char(5)) as fieldname")
    assert "test " == cur.execute_scalar(
        "select cast(N'test' as nchar(5)) as fieldname"
    )
    assert b"test" == cur.execute_scalar(
        "select cast('test' as varbinary(4)) as fieldname"
    )
    assert b"test" == cur.execute_scalar("select cast('test' as image) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as image) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as varbinary(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as ntext) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nvarchar(max)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as xml)")
    assert None is cur.execute_scalar("select cast(NULL as varchar(max)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nvarchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as varchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
    assert 5 == cur.execute_scalar("select 5 as fieldname")
    with pytest.raises(pytds.ProgrammingError) as ex:
        cur.execute_scalar("create table exec_scalar_empty(f int)")
    # message does not have to be exact match
    assert "Previous statement didn't produce any results" in str(ex.value)


def test_money(cursor):
    cur = cursor
    assert Decimal("0") == cur.execute_scalar("select cast('0' as money) as fieldname")
    assert Decimal("1") == cur.execute_scalar("select cast('1' as money) as fieldname")
    assert Decimal("1.5555") == cur.execute_scalar(
        "select cast('1.5555' as money) as fieldname"
    )
    assert Decimal("1234567.5555") == cur.execute_scalar(
        "select cast('1234567.5555' as money) as fieldname"
    )
    assert Decimal("-1234567.5555") == cur.execute_scalar(
        "select cast('-1234567.5555' as money) as fieldname"
    )
    assert Decimal("12345.55") == cur.execute_scalar(
        "select cast('12345.55' as smallmoney) as fieldname"
    )


def test_strs(cursor):
    cur = cursor
    assert isinstance(cur.execute_scalar("select 'test'"), str)


@pytest.mark.parametrize(
    "val",
    [
        "hello",
        "x" * 5000,
        "x" * 9000,
        123,
        -123,
        123.12,
        -123.12,
        10**20,
        10**38 - 1,
        -(10**38) + 1,
        datetime.datetime(2011, 2, 3, 10, 11, 12, 3000),
        Decimal("1234.567"),
        Decimal("1234000"),
        Decimal("9" * 38),
        Decimal("0." + "9" * 38),
        Decimal("-" + ("9" * 38), Context(prec=38)),
        Decimal("1E10"),
        Decimal("1E-10"),
        Decimal("0.{0}1".format("0" * 37)),
        None,
        "hello",
        "",
        pytds.Binary(b""),
        pytds.Binary(b"\x00\x01\x02"),
        pytds.Binary(b"x" * 9000),
        2**63 - 1,
        False,
        True,
        uuid.uuid4(),
        "Iñtërnâtiônàlizætiøn1",
        "\U0001d6fc",
    ],
)
def test_select_values(cursor, val):
    cursor.execute("select %s", (val,))
    assert cursor.fetchone() == (val,)
    assert cursor.fetchone() is None


uuid_val = uuid.uuid4()


@pytest.mark.parametrize(
    "result,sql",
    [
        (None, "cast(NULL as varchar)"),
        ("test", "cast('test' as varchar)"),
        ("test ", "cast('test' as char(5))"),
        ("test", "cast(N'test' as nvarchar)"),
        ("test ", "cast(N'test' as nchar(5))"),
        (Decimal("100.55555"), "cast(100.55555 as decimal(8,5))"),
        (Decimal("100.55555"), "cast(100.55555 as numeric(8,5))"),
        (b"test", "cast('test' as varbinary)"),
        (b"test\x00", "cast('test' as binary(5))"),
        (
            datetime.datetime(2011, 2, 3, 10, 11, 12, 3000),
            "cast('2011-02-03T10:11:12.003' as datetime)",
        ),
        (
            datetime.datetime(2011, 2, 3, 10, 11, 0),
            "cast('2011-02-03T10:11:00' as smalldatetime)",
        ),
        (uuid_val, "cast('{0}' as uniqueidentifier)".format(uuid_val)),
        (True, "cast(1 as bit)"),
        (128, "cast(128 as tinyint)"),
        (255, "cast(255 as tinyint)"),
        (-32000, "cast(-32000 as smallint)"),
        (2000000000, "cast(2000000000 as int)"),
        (2000000000000, "cast(2000000000000 as bigint)"),
        (0.12345, "cast(0.12345 as float)"),
        (0.25, "cast(0.25 as real)"),
        (Decimal("922337203685477.5807"), "cast('922,337,203,685,477.5807' as money)"),
        (Decimal("-214748.3648"), "cast('- 214,748.3648' as smallmoney)"),
    ],
)
def test_sql_variant_round_trip(cursor, result, sql):
    if not pytds.tds_base.IS_TDS71_PLUS(cursor.connection):
        pytest.skip("Requires TDS7.1+")
    cursor.execute("select cast({0} as sql_variant)".format(sql))
    (val,) = cursor.fetchone()
    assert result == val


def test_collations(cursor, collation_set):
    coll_name_set = collation_set

    tests = [
        ("Привет", "Cyrillic_General_BIN"),
        ("Привет", "Cyrillic_General_BIN2"),
        ("สวัสดี", "Thai_CI_AI"),
        ("你好", "Chinese_PRC_CI_AI"),
        ("こんにちは", "Japanese_CI_AI"),
        ("안녕하세요.", "Korean_90_CI_AI"),
        ("你好", "Chinese_Hong_Kong_Stroke_90_CI_AI"),
        ("cześć", "Polish_CI_AI"),
        ("Bonjour", "French_CI_AI"),
        ("Γεια σας", "Greek_CI_AI"),
        ("Merhaba", "Turkish_CI_AI"),
        ("שלום", "Hebrew_CI_AI"),
        ("مرحبا", "Arabic_CI_AI"),
        ("Sveiki", "Lithuanian_CI_AI"),
        ("chào", "Vietnamese_CI_AI"),
        ("ÄÅÆ", "SQL_Latin1_General_CP437_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_CP850_BIN"),
        ("ŠşĂ", "SQL_Slovak_CP1250_CS_AS_KI_WI"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1251_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_Cp1_CS_AS_KI_WI"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1253_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1254_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1255_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1256_BIN"),
        ("ÁÂÀÃ", "SQL_Latin1_General_1257_BIN"),
        ("ÁÂÀÃ", "Latin1_General_100_BIN"),
    ]
    for s, coll in tests:
        if coll not in coll_name_set:
            logger.info("Skipping {}, not supported by current server".format(coll))
            continue
        assert (
            cursor.execute_scalar(
                "select cast(N'{}' collate {} as varchar(100))".format(s, coll)
            )
            == s
        )


def skip_if_new_date_not_supported(conn):
    if not pytds.tds_base.IS_TDS73_PLUS(conn):
        pytest.skip(
            "Test requires new date types support, SQL 2008 or newer is required"
        )


def test_date(cursor):
    skip_if_new_date_not_supported(cursor.connection)
    date = pytds.Date(2012, 10, 6)
    cursor.execute("select %s", (date,))
    assert cursor.fetchall() == [(date,)]


def test_time(cursor):
    skip_if_new_date_not_supported(cursor.connection)
    time = pytds.Time(8, 7, 4, 123000)
    cursor.execute("select %s", (time,))
    assert cursor.fetchall() == [(time,)]


def test_datetime(cursor):
    time = pytds.Timestamp(2013, 7, 9, 8, 7, 4, 123000)
    cursor.execute("select %s", (time,))
    assert cursor.fetchall() == [(time,)]
