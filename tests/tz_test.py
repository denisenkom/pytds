import datetime
from pytds import tz


def test_tz():
    assert tz.FixedOffsetTimezone(0, "UTC").tzname(None) == "UTC"
    lz = tz.LocalTimezone()
    jan_1 = datetime.datetime(2010, 1, 1, 0, 0)
    july_1 = datetime.datetime(2010, 7, 1, 0, 0)
    assert isinstance(lz.tzname(jan_1), str)
    lz.dst(jan_1)
    lz.dst(july_1)
    lz.utcoffset(jan_1)
    lz.utcoffset(july_1)
