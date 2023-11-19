from __future__ import annotations

import logging
import datetime

import socket

from typing import Any

from . import tds_base
from . import tds_types
from .tds_base import PreLoginEnc, _TdsEnv, _TdsLogin, Route
from .row_strategies import list_row_strategy
from .smp import SmpManager
# _token_map is needed by sqlalchemy_pytds connector
from .tds_session import _token_map, _TdsSession

logger = logging.getLogger(__name__)


# this class represents root TDS connection
# if MARS is used it can have multiple sessions represented by _TdsSession class
# if MARS is not used it would have single _TdsSession instance
class _TdsSocket(object):
    def __init__(
            self,
            row_strategy=list_row_strategy,
            use_tz: datetime.tzinfo | None = None,
            autocommit=False
    ):
        self._is_connected = False
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = 0
        self._mars_enabled = False
        self.sock = None
        self.bufsize = 4096
        self.tds_version = tds_base.TDS74
        self.use_tz = use_tz
        self.type_factory = tds_types.SerializerFactory(self.tds_version)
        self.type_inferrer = None
        self.query_timeout = 0
        self._smp_manager: SmpManager | None = None
        self._main_session: _TdsSession | None = None
        self._login: _TdsLogin | None = None
        self.route: Route | None = None
        self._row_strategy = row_strategy
        self._autocommit = autocommit

    def __repr__(self) -> str:
        fmt = "<_TdsSocket tran={} mars={} tds_version={} use_tz={}>"
        return fmt.format(self.tds72_transaction, self._mars_enabled,
                          self.tds_version, self.use_tz)

    def login(self, login: _TdsLogin, sock: tds_base.TransportProtocol, tzinfo_factory: tds_types.TzInfoFactoryType | None) -> Route | None:
        from . import tls
        from .tds_session import _TdsSession
        self._login = login
        self.bufsize = login.blocksize
        self.query_timeout = login.query_timeout
        self._main_session = _TdsSession(
            tds=self,
            transport=sock,
            tzinfo_factory=tzinfo_factory,
            row_strategy=self._row_strategy,
            env=self.env,
        )
        self.sock = sock
        self.tds_version = login.tds_version
        login.server_enc_flag = PreLoginEnc.ENCRYPT_NOT_SUP
        if tds_base.IS_TDS71_PLUS(self):
            self._main_session.send_prelogin(login)
            self._main_session.process_prelogin(login)
        self._main_session.tds7_send_login(login)
        if login.server_enc_flag == PreLoginEnc.ENCRYPT_OFF:
            tls.revert_to_clear(self._main_session)
        self._main_session.begin_response()
        if not self._main_session.process_login_tokens():
            self._main_session.raise_db_exception()
        if self.route is not None:
            return self.route

        # update block size if server returned different one
        if self._main_session._writer.bufsize != self._main_session._reader.get_block_size():
            self._main_session._reader.set_block_size(self._main_session._writer.bufsize)

        self.type_factory = tds_types.SerializerFactory(self.tds_version)
        self.type_inferrer = tds_types.TdsTypeInferrer(
            type_factory=self.type_factory,
            collation=self.collation,
            bytes_to_unicode=self._login.bytes_to_unicode,
            allow_tz=not self.use_tz
        )
        if self._mars_enabled:
            self._smp_manager = SmpManager(self.sock)
            self._main_session = _TdsSession(
                tds=self,
                transport=self._smp_manager.create_session(),
                tzinfo_factory=tzinfo_factory,
                row_strategy=self._row_strategy,
                env=self.env,
            )
        self._is_connected = True
        q = []
        if login.database and self.env.database != login.database:
            q.append('use ' + tds_base.tds_quote_id(login.database))
        if q:
            self._main_session.submit_plain_query(''.join(q))
            self._main_session.process_simple_request()
        return None

    @property
    def mars_enabled(self) -> bool:
        return self._mars_enabled

    @property
    def main_session(self) -> _TdsSession | None:
        return self._main_session

    def create_session(self, tzinfo_factory: tds_types.TzInfoFactoryType | None) -> _TdsSession:
        from .tds_session import _TdsSession
        return _TdsSession(
            tds=self,
            transport=self._smp_manager.create_session(),
            tzinfo_factory=tzinfo_factory,
            row_strategy=self._row_strategy,
            env=self.env,
        )

    def is_connected(self) -> bool:
        return self._is_connected

    def close(self) -> None:
        self._is_connected = False
        if self.sock is not None:
            self.sock.close()
        if self._smp_manager:
            self._smp_manager.transport_closed()
        self._main_session.state = tds_base.TDS_DEAD
        if self._main_session.authentication:
            self._main_session.authentication.close()
            self._main_session.authentication = None

    def close_all_mars_sessions(self) -> None:
        self._smp_manager.close_all_sessions(keep=self.main_session._transport)


def _parse_instances(msg: bytes) -> dict[str, dict[str, str]]:
    name = None
    if len(msg) > 3 and tds_base.my_ord(msg[0]) == 5:
        tokens = msg[3:].decode('ascii').split(';')
        results = {}
        instdict = {}
        got_name = False
        for token in tokens:
            if got_name:
                instdict[name] = token
                got_name = False
            else:
                name = token
                if not name:
                    if not instdict:
                        break
                    results[instdict['InstanceName'].upper()] = instdict
                    instdict = {}
                    continue
                got_name = True
        return results


#
# Get port of all instances
# @return default port number or 0 if error
# @remark experimental, cf. MC-SQLR.pdf.
#
def tds7_get_instances(ip_addr: Any, timeout: float = 5) -> dict[str, dict[str, str]]:
    s = socket.socket(type=socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # send the request
        s.sendto(b'\x03', (ip_addr, 1434))
        msg = s.recv(16 * 1024 - 1)
        # got data, read and parse
        return _parse_instances(msg)
    finally:
        s.close()
