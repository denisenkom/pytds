import unittest
import struct
import pytest
import pytds
from pytds.smp import *
from utils import MockSock


smp_hdr = struct.Struct('<BBHLLL')


class SmpSessionsTests(unittest.TestCase):
    def setUp(self):
        self.sock = MockSock()
        self.mgr = SmpManager(self.sock)
        self.sess = self.mgr.create_session()
        self.buf = bytearray(b'0' * 100)
        self.sock.consume_output()

    def test_valid_data(self):
        self.sock.set_input([smp_hdr.pack(0x53, 8, 0, len(b'test') + 16, 1, 10) + b'test'])
        l = self.sess.recv_into(self.buf)
        assert self.buf[:l] == b'test'

    def test_invalid_flags(self):
        self.sock.set_input([smp_hdr.pack(0x53, 16, 0, 16, 1, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Unexpected FLAGS' in str(excinfo)

    def test_syn_packet(self):
        """
        Server should not send SYN packets to a client, only client can send those
        """
        self.sock.set_input([smp_hdr.pack(0x53, 1, 0, 16, 1, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Unexpected SYN' in str(excinfo)

    def test_data_after_fin(self):
        sess2 = self.mgr.create_session()
        self.sock.set_input([smp_hdr.pack(0x53, 4, 0, 16, 1, 10) + smp_hdr.pack(0x53, 8, 0, 16, 2, 10)])
        assert self.sess.recv_into(self.buf) == 0
        with pytest.raises(pytds.Error) as excinfo:
            sess2.recv_into(self.buf)
        assert 'Unexpected DATA packet from server' in str(excinfo)

    def test_fin_after_fin(self):
        sess2 = self.mgr.create_session()
        self.sock.set_input([smp_hdr.pack(0x53, 4, 0, 16, 1, 10) + smp_hdr.pack(0x53, 4, 0, 16, 2, 10)])
        assert self.sess.recv_into(self.buf) == 0
        with pytest.raises(pytds.Error) as excinfo:
            sess2.recv_into(self.buf)
        assert 'Unexpected FIN' in str(excinfo)

    def test_data_after_close(self):
        """should ignore data sent from server if we already send FIN packet"""
        self.sock.set_input([smp_hdr.pack(0x53, 8, 0, len(b'test') + 16, 1, 10) + b'test' +
                             smp_hdr.pack(0x53, 4, 0, 16, 1, 10)])
        assert self.sess.get_state() == SessionState.SESSION_ESTABLISHED
        self.sess.close()
        assert self.sess.get_state() == SessionState.CLOSED
        assert self.sess.recv_into(self.buf) == 0

    def test_ack_after_fin(self):
        sess2 = self.mgr.create_session()
        self.sock.set_input([smp_hdr.pack(0x53, 4, 0, 16, 1, 10) + smp_hdr.pack(0x53, 2, 0, 16, 2, 10)])
        assert self.sess.recv_into(self.buf) == 0
        with pytest.raises(pytds.Error) as excinfo:
            sess2.recv_into(self.buf)
        assert 'Unexpected ACK packet from server' in str(excinfo)

    def test_unexpected_eof(self):
        """
        Should raise EOF error if socket does not have enough data to fill SMP header
        """
        self.sock.set_input([b'0' * 10])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Unexpected EOF' in str(excinfo)

    def test_invalid_id(self):
        self.sock.set_input([smp_hdr.pack(0, 4, 0, 16, 1, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid SMP packet signature' in str(excinfo)

    def test_invalid_session_id(self):
        self.sock.set_input([smp_hdr.pack(0x53, 0, 1, 0, 0, 0)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid SMP packet session id' in str(excinfo)

    def test_invalid_wndw_value(self):
        self.sock.set_input([smp_hdr.pack(0x53, 0, 0, 0, 0, 0)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid WNDW in packet from server' in str(excinfo)

    def test_invalid_seqnum_value(self):
        self.sock.set_input([smp_hdr.pack(0x53, 8, 0, 0, 500, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid SEQNUM in packet from server' in str(excinfo)

    def test_invalid_length(self):
        self.sock.set_input([smp_hdr.pack(0x53, 8, 0, 0, 1, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid LENGTH' in str(excinfo)

    def test_invalid_seqnum_in_data_packet(self):
        self.sock.set_input([smp_hdr.pack(0x53, 8, 0, 16, 0, 10)])
        with pytest.raises(pytds.Error) as excinfo:
            self.sess.recv_into(self.buf)
        assert 'Invalid SEQNUM' in str(excinfo)
