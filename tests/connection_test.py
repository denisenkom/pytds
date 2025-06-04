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
