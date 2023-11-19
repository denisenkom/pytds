import pytest

from pytds.tds_base import PacketType, _header
from pytds.tds_reader import _TdsReader
from tests.utils import BytesSocket


def test_reader():
    """
    Test that reader readiness
    """
    reader = _TdsReader(
        BytesSocket(
            # Setup byte stream which contains two responses
            # First response consists of two packets
            _header.pack(PacketType.REPLY, 0, 8 + len(b'hello'), 123, 0) +
            b'hello' +
            # Second and last packet of first response
            _header.pack(PacketType.REPLY, 1, 8 + len(b'secondpacket'), 123, 0) +
            b'secondpacket' +
            # Second response consisting of single packet
            _header.pack(PacketType.TRANS, 1, 8 + len(b'secondresponse'), 123, 0) +
            b'secondresponse',
        ),
        tds_session=None,
    )
    # Reading without calling begin_response should raise a RuntimeError
    with pytest.raises(RuntimeError):
        reader.recv(100)
    response_header = reader.begin_response()
    assert response_header.type == PacketType.REPLY
    assert response_header.spid == 123
    assert b'hello' == reader.recv(5)
    assert b'secondpacket' == reader.recv(100)
    assert b'' == reader.recv(100)
    response_header2 = reader.begin_response()
    assert response_header2.type == PacketType.TRANS
    assert response_header2.spid == 123
    assert b'secondresponse' == reader.recv(100)


def test_begin_response_incorrectly():
    """
    Test that calling begin_response at wrong time issues an exception
    """
    reader = _TdsReader(
        BytesSocket(
            # First response consists of two packets
            _header.pack(PacketType.REPLY, 0, 8 + len(b'hello'), 123, 0) +
            b'hello' +
            # Second and last packet of first response
            _header.pack(PacketType.REPLY, 1, 8 + len(b'secondpacket'), 123, 0) +
            b'secondpacket'
        ),
        tds_session=None,
    )
    response_header = reader.begin_response()
    assert response_header.type == PacketType.REPLY
    assert response_header.spid == 123
    # calling begin_response before consuming previous response should cause RuntimeError
    with pytest.raises(RuntimeError):
        reader.begin_response()
