import struct
import logging
import bitarray
from .tds import Error, readall, skipall

logger = logging.getLogger(__name__)


class _SmpSession(object):
    def __init__(self, tds, session_id):
        self._session_id = session_id
        self._seq_num_for_send = 0
        self._high_water_for_send = 4
        self._seq_num_for_recv = 0
        self._high_water_for_recv = 4
        self._last_high_water_for_recv = 4
        self._tds = tds
        self._recv_queue = []
        self._send_queue = []
        self._state = 'new'
        self._curr_buf_pos = 0
        self._curr_buf = b''

    def close(self):
        self._tds._close_smp_session(self)

    def send(self, data, final):
        self._tds._send_packet(self, data)

    def read(self, size):
        if not self._curr_buf[self._curr_buf_pos:]:
            self._curr_buf = self._tds._recv_packet(self)
            self._curr_buf_pos = 0
            if not self._curr_buf:
                return b''
        res = self._curr_buf[self._curr_buf_pos:self._curr_buf_pos + size]
        self._curr_buf_pos += len(res)
        return res

    def is_connected(self):
        return self._state == 'SESSION ESTABLISHED'


class SmpManager(object):
    _smid = 0x53
    _smp_header = struct.Struct('<BBHLLL')
    _SYN = 0x1
    _ACK = 0x2
    _FIN = 0x4
    _DATA = 0x8

    def __init__(self, transport):
        self._transport = transport
        self._sessions = {}
        self._used_ids_ba = bitarray.bitarray(2 ** 16)
        self._used_ids_ba.setall(False)

    def create_session(self):
        try:
            session_id = self._used_ids_ba.index(False)
        except ValueError:
            raise Error("Can't create more MARS sessions, close some sessions and try again")
        session = _SmpSession(self, session_id)
        self._sessions[session_id] = session
        self._used_ids_ba[session_id] = True
        hdr = self._smp_header.pack(
            self._smid,
            self._SYN,
            session_id,
            self._smp_header.size,
            0,
            session._high_water_for_recv,
            )
        self._transport.send(hdr, True)
        session._state = 'SESSION ESTABLISHED'
        return session

    def _close_smp_session(self, session):
        if session._state in ('CLOSED', 'FIN SENT'):
            return
        elif session._state == 'SESSION ESTABLISHED':
            if self._transport.is_connected():
                hdr = self._smp_header.pack(
                    self._smid,
                    self._FIN,
                    session._session_id,
                    self._smp_header.size,
                    session._seq_num_for_send,
                    session._high_water_for_recv,
                    )
                session._state = 'FIN SENT'
                self._transport.send(hdr, True)
                self._recv_packet(session)
            else:
                session._state = 'CLOSED'

    def _send_queued_packets(self, session):
        while session._send_queue and session._seq_num_for_send < session._high_water_for_send:
            data = session._send_queue.pop(0)
            self._send_packet(session, data)

    @staticmethod
    def _add_one_wrap(val):
        return 0 if val == 2 ** 32 - 1 else val + 1

    def _send_packet(self, session, data):
        if session._seq_num_for_send < session._high_water_for_send:
            l = self._smp_header.size + len(data)
            seq_num = self._add_one_wrap(session._seq_num_for_send)
            hdr = self._smp_header.pack(
                self._smid,
                self._DATA,
                session._session_id,
                l,
                seq_num,
                session._high_water_for_recv,
                )
            session._last_high_water_for_recv = session._high_water_for_recv
            self._transport.send(hdr + data, True)
            session._seq_num_for_send = self._add_one_wrap(session._seq_num_for_send)
        else:
            session._send_queue.append(data)
            self._read_smp_message()

    def _recv_packet(self, session):
        if session._state == 'CLOSED':
            return b''
        while not session._recv_queue:
            self._read_smp_message()
            if session._state in ('CLOSED', 'FIN RECEIVED'):
                return b''
        session._high_water_for_recv = self._add_one_wrap(session._high_water_for_recv)
        if session._high_water_for_recv - session._last_high_water_for_recv >= 2:
            hdr = self._smp_header.pack(
                self._smid,
                self._ACK,
                session._session_id,
                self._smp_header.size,
                session._seq_num_for_send,
                session._high_water_for_recv,
                )
            self._transport.send(hdr, True)
            session._last_high_water_for_recv = session._high_water_for_recv
        return session._recv_queue.pop(0)

    @classmethod
    def _type_to_str(cls, t):
        if t == cls._SYN:
            return 'SYN'
        elif t == cls._ACK:
            return 'ACK'
        elif t == cls._DATA:
            return 'DATA'
        elif t == cls._FIN:
            return 'FIN'

    def _read_smp_message(self):
        smid, flags, sid, l, seq_num, wnd = self._smp_header.unpack(readall(self._transport, self._smp_header.size))
        if smid != self._smid:
            self.close()
            raise Error('Invalid SMP packet signature')
        #logger.debug('received smp packet t:%s sid:%s len:%s num:%s wnd:%s', self._type_to_str(flags), sid, l, seq_num, wnd)
        try:
            session = self._sessions[sid]
        except KeyError:
            self.close()
            raise Error('Invalid SMP packet session id')
        if wnd < session._high_water_for_send:
            self.close()
            raise Error('Invalid WNDW in packet from server')
        if seq_num > session._high_water_for_recv:
            self.close()
            raise Error('Invalid SEQNUM in packet from server')
        session._last_recv_seq_num = seq_num
        if flags == self._ACK:
            if session._state in ('FIN RECEIVED', 'CLOSED'):
                self.close()
                raise Error('Unexpected SMP ACK packet from server')
            if seq_num != session._seq_num_for_recv:
                self.close()
                raise Error('Invalid SEQNUM in ACK packet from server')
            session._high_water_for_send = wnd
            self._send_queued_packets(session)
        elif flags == self._DATA:
            if session._state == 'SESSION ESTABLISHED':
                if seq_num != self._add_one_wrap(session._seq_num_for_recv):
                    self.close()
                    raise Error('Invalid SEQNUM in ACK packet from server')
                session._seq_num_for_recv = seq_num
                data = readall(self._transport, l - self._smp_header.size)
                session._recv_queue.append(data)
                if wnd > session._high_water_for_send:
                    session._high_water_for_send = wnd
                    self._send_queued_packets(session)

            elif session._state == 'FIN SENT':
                skipall(self._transport, l - self._smp_header.size)
            else:
                self.close()
                raise Error('Unexpected SMP flags in packet from server')
        elif flags == self._FIN:
            if session._state == 'SESSION ESTABLISHED':
                session._state = 'FIN RECEIVED'
            elif session._state == 'FIN SENT':
                session._state = 'CLOSED'
                del self._sessions[session._session_id]
                self._used_ids_ba[session._session_id] = False
            elif session._state == 'FIN RECEIVED':
                self.close()
                raise Error('Unexpected SMP FIN packet from server')
            else:
                self.close()
                assert False, 'Invalid state: ' + session._state
        elif flags == self._SYN:
            self.close()
            raise Error('Unexpected SMP SYN packet from server')
        else:
            self.close()
            raise Error('Unexpected SMP flags in packet from server')

    def close(self):
        self._transport.close()

    def _transport_closed(self):
        for session in self._sessions.values():
            session._state = 'CLOSED'
