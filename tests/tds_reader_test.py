import pytest

from pytds.tds_base import PacketType, _header, ClosedConnectionError
from pytds.tds_reader import _TdsReader
from tests.utils import BytesSocket


def test_reader():
    """
    Test normal flow for reader
    """
    reader = _TdsReader(
        transport=BytesSocket(
            # Setup byte stream which contains two responses
            # First response consists of two packets
            _header.pack(PacketType.REPLY, 0, 8 + len(b"hello"), 123, 0)
            + b"hello"
            +
            # Second and last packet of first response
            _header.pack(PacketType.REPLY, 1, 8 + len(b"secondpacket"), 123, 0)
            + b"secondpacket"
            +
            # Second response consisting of single packet
            _header.pack(PacketType.TRANS, 1, 8 + len(b"secondresponse"), 123, 0)
            + b"secondresponse",
        ),
        tds_session=None,
        bufsize=200,
    )
    # Reading without calling begin_response should return empty result indicating that stream is empty
    assert reader.recv(100) == b""

    assert reader.get_block_size() == 200

    response_header = reader.begin_response()
    assert response_header.type == PacketType.REPLY
    assert reader.packet_type == PacketType.REPLY
    assert response_header.spid == 123
    assert b"hel" == reader.recv(3)
    assert b"lo" == reader.recv(2)
    assert b"secondpacket" == reader.recv(100)
    # should return empty byte array indicating end of stream once end is reached
    assert b"" == reader.recv(100)

    # Now start reading next response stream
    response_header2 = reader.begin_response()
    assert not reader.stream_finished()
    assert response_header2.type == PacketType.TRANS
    assert response_header2.spid == 123
    assert reader.packet_type == PacketType.TRANS
    assert reader.recv(100) == b"secondresponse"
    assert reader.recv(100) == b""
    assert reader.stream_finished()

    with pytest.raises(ClosedConnectionError):
        reader.begin_response()


def test_read_fast():
    """
    Testing read_fast method
    """
    reader = _TdsReader(
        transport=BytesSocket(
            # Setup byte stream which contains two responses
            # First response consists of two packets
            _header.pack(PacketType.REPLY, 0, 8 + len(b"hello"), 123, 0)
            + b"hello"
            +
            # Second and last packet of first response
            _header.pack(PacketType.REPLY, 1, 8 + len(b"secondpacket"), 123, 0)
            + b"secondpacket"
        ),
        tds_session=None,
    )
    response_header2 = reader.begin_response()
    assert response_header2.type == PacketType.REPLY
    assert response_header2.spid == 123
    # Testing fast_read functionality
    buf, offset = reader.read_fast(100)
    assert buf[offset : reader._pos] == b"hello"
    buf, offset = reader.read_fast(100)
    assert buf[offset : reader._pos] == b"secondpacket"
    assert reader.read_fast(100) == (b"", 0)
    assert reader.stream_finished()


def test_begin_response_incorrectly():
    """
    Test that calling begin_response at wrong time issues an exception
    """
    reader = _TdsReader(
        transport=BytesSocket(
            # First response consists of two packets
            _header.pack(PacketType.REPLY, 0, 8 + len(b"hello"), 123, 0)
            + b"hello"
            +
            # Second and last packet of first response
            _header.pack(PacketType.REPLY, 1, 8 + len(b"secondpacket"), 123, 0)
            + b"secondpacket"
        ),
        tds_session=None,
    )
    response_header = reader.begin_response()

    # calling begin_response before consuming previous response stream should cause RuntimeError
    with pytest.raises(
        RuntimeError,
        match="begin_response was called before previous response was fully consumed",
    ):
        reader.begin_response()

    assert response_header.type == PacketType.REPLY
    assert response_header.spid == 123

    # consume first packet of the response stream
    assert reader.recv(6) == b"hello"

    # calling begin_response before consuming previous response stream should cause RuntimeError
    with pytest.raises(
        RuntimeError,
        match="begin_response was called before previous response was fully consumed",
    ):
        reader.begin_response()

    # consume part of the second packet of the response stream
    assert reader.recv(3) == b"sec"

    # calling begin_response before consuming previous response stream should cause RuntimeError
    with pytest.raises(
        RuntimeError,
        match="begin_response was called before previous response was fully consumed",
    ):
        reader.begin_response()
