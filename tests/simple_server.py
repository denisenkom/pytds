import socket
import socketserver
import struct
import logging

import OpenSSL.SSL

import pytds.tds_socket
import pytds.tds_reader
import pytds.tds_writer
import pytds.collate

_BYTE_STRUCT = struct.Struct("B")
_OFF_LEN_STRUCT = struct.Struct(">HH")
_PROD_VER_STRUCT = struct.Struct(">LH")
logger = logging.getLogger(__name__)


class TdsParser:
    def bad_stream(self, msg):
        # TODO use different exception class
        raise Exception(msg)

    def parse_prelogin(self, buf):
        # https://msdn.microsoft.com/en-us/library/dd357559.aspx
        size = len(buf)
        i = 0
        result = {}
        while True:
            value = None
            if i >= size:
                self.bad_stream("Invalid size of PRELOGIN structure")
            (type_id,) = _BYTE_STRUCT.unpack_from(buf, i)
            if type_id == pytds.tds_base.PreLoginToken.TERMINATOR:
                break
            if i + 4 > size:
                self.bad_stream("Invalid size of PRELOGIN structure")
            off, l = _OFF_LEN_STRUCT.unpack_from(buf, i + 1)
            if off > size or off + l > size:
                self.bad_stream("Invalid offset in PRELOGIN structure")
            if type_id == pytds.tds_base.PreLoginToken.VERSION:
                value = _PROD_VER_STRUCT.unpack_from(buf, off)
            elif type_id == pytds.tds_base.PreLoginToken.ENCRYPTION:
                value = _BYTE_STRUCT.unpack_from(buf, off)[0]
            elif type_id == pytds.tds_base.PreLoginToken.MARS:
                value = bool(_BYTE_STRUCT.unpack_from(buf, off)[0])
            elif type_id == pytds.tds_base.PreLoginToken.INSTOPT:
                value = buf[off : off + l].decode("ascii")
            i += 5
            result[type_id] = value
        return result


class TdsGenerator:
    def generate_prelogin(self, prelogin):
        hdr_size = (1 + _OFF_LEN_STRUCT.size) * len(prelogin) + 1
        buf = bytearray([0] * hdr_size)
        hdr_offset = 0
        data_offset = hdr_size
        for type_id, value in prelogin.items():
            if type_id == pytds.tds_base.PreLoginToken.VERSION:
                packed = _PROD_VER_STRUCT.pack(value)
            elif type_id == pytds.tds_base.PreLoginToken.ENCRYPTION:
                packed = [value]
            elif type_id == pytds.tds_base.PreLoginToken.MARS:
                packed = [1 if value else 0]
            elif type_id == pytds.tds_base.PreLoginToken.INSTOPT:
                packed = value.encode("ascii")
            else:
                raise Exception(
                    f"not implemented prelogin option {type_id} in prelogin message generator"
                )

            data_size = len(packed)

            buf[hdr_offset] = type_id
            hdr_offset += 1

            _OFF_LEN_STRUCT.pack_into(buf, hdr_offset, data_offset, data_size)
            hdr_offset += _OFF_LEN_STRUCT.size

            buf.extend(packed)
            data_offset += data_size
        buf[hdr_offset] = pytds.tds_base.PreLoginToken.TERMINATOR
        return buf


class Sock:
    # wraps request in class compatible with TdsSocket
    def __init__(self, req):
        self._req = req

    def recv(self, size):
        return self._req.recv(size)

    def recv_into(self, buffer, size=0):
        return self._req.recv_into(buffer, size)

    def sendall(self, data, flags=0):
        return self._req.sendall(data, flags)


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        parser = TdsParser()
        gen = TdsGenerator()
        bufsize = 4096

        # TdsReader expects this
        self._transport = Sock(self.request)

        r = pytds.tds_reader._TdsReader(tds_session=self, transport=self._transport)
        w = pytds.tds_writer._TdsWriter(
            tds_session=self, bufsize=bufsize, transport=self._transport
        )

        resp_header = r.begin_response()
        buf = r.read_whole_packet()
        if resp_header.type != pytds.tds_base.PacketType.PRELOGIN:
            msg = "Invalid packet type: {0}, expected PRELOGIN({1})".format(
                r.packet_type, pytds.tds_base.PacketType.PRELOGIN
            )
            self.bad_stream(msg)
        prelogin = parser.parse_prelogin(buf)
        logger.info(f"received prelogin message from client {prelogin}")
        srv_enc = self.server._enc
        cli_enc = prelogin[pytds.tds_base.PreLoginToken.ENCRYPTION]
        res_enc = None
        close_conn = False
        if srv_enc == pytds.PreLoginEnc.ENCRYPT_OFF:
            if cli_enc == pytds.PreLoginEnc.ENCRYPT_OFF:
                res_enc = pytds.PreLoginEnc.ENCRYPT_OFF
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_ON:
                res_enc = pytds.PreLoginEnc.ENCRYPT_ON
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_NOT_SUP:
                res_enc = pytds.PreLoginEnc.ENCRYPT_NOT_SUP
        elif srv_enc == pytds.PreLoginEnc.ENCRYPT_ON:
            if cli_enc == pytds.PreLoginEnc.ENCRYPT_OFF:
                res_enc = pytds.PreLoginEnc.ENCRYPT_REQ
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_ON:
                res_enc = pytds.PreLoginEnc.ENCRYPT_ON
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_NOT_SUP:
                res_enc = pytds.PreLoginEnc.ENCRYPT_REQ
                close_conn = True
        elif srv_enc == pytds.PreLoginEnc.ENCRYPT_NOT_SUP:
            if cli_enc == pytds.PreLoginEnc.ENCRYPT_OFF:
                res_enc = pytds.PreLoginEnc.ENCRYPT_NOT_SUP
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_ON:
                res_enc = pytds.PreLoginEnc.ENCRYPT_NOT_SUP
                close_conn = True
            elif cli_enc == pytds.PreLoginEnc.ENCRYPT_NOT_SUP:
                res_enc = pytds.PreLoginEnc.ENCRYPT_NOT_SUP
        elif srv_enc == pytds.PreLoginEnc.ENCRYPT_REQ:
            res_enc = pytds.PreLoginEnc.ENCRYPT_REQ

        # sending reply to client's prelogin packet
        prelogin_resp = gen.generate_prelogin(
            {
                pytds.tds_base.PreLoginToken.ENCRYPTION: res_enc,
            }
        )
        w.begin_packet(pytds.tds_base.PacketType.REPLY)
        w.write(prelogin_resp)
        w.flush()

        if close_conn:
            return

        wrapped_socket = None
        if res_enc != pytds.PreLoginEnc.ENCRYPT_NOT_SUP:
            # setup TLS connection
            tlsconn = OpenSSL.SSL.Connection(self.server._tls_ctx)
            tlsconn.set_accept_state()
            done = False
            while not done:
                try:
                    tlsconn.do_handshake()
                except OpenSSL.SSL.WantReadError:
                    try:
                        buf = tlsconn.bio_read(bufsize)
                    except OpenSSL.SSL.WantReadError:
                        pass
                    else:
                        w.begin_packet(pytds.tds_base.PacketType.PRELOGIN)
                        w.write(buf)
                        w.flush()

                    r.begin_response()
                    buf = r.read_whole_packet()
                    tlsconn.bio_write(buf)
                else:
                    done = True
                    try:
                        buf = tlsconn.bio_read(bufsize)
                    except OpenSSL.SSL.WantReadError:
                        pass
                    else:
                        w.begin_packet(pytds.tds_base.PacketType.PRELOGIN)
                        w.write(buf)
                        w.flush()

            wrapped_socket = pytds.tls.EncryptedSocket(
                transport=self.request, tls_conn=tlsconn
            )
            r._transport = wrapped_socket
            w._transport = wrapped_socket

        try:
            r.begin_response()
            buf = r.read_whole_packet()
        except pytds.tds_base.ClosedConnectionError:
            logger.info(
                "client closed connection, probably did not like server certificate"
            )
            return
        logger.info(f"received login packet from client {buf}")

        if res_enc == pytds.PreLoginEnc.ENCRYPT_OFF:
            wrapped_socket.shutdown()
            r._transport = self._transport
            w._transport = self._transport

        srv_name = "Simple TDS Server"
        srv_ver = (1, 0, 0, 0)
        tds_version = self.server._tds_version

        w.begin_packet(pytds.tds_base.PacketType.REPLY)
        # https://msdn.microsoft.com/en-us/library/dd340651.aspx
        srv_name_coded, _ = pytds.collate.ucs2_codec.encode(srv_name)
        srv_name_size = len(srv_name_coded)
        w.put_byte(pytds.tds_base.TDS_LOGINACK_TOKEN)
        size = 1 + 4 + 1 + srv_name_size + 4
        w.put_usmallint(size)
        w.put_byte(1)  # interface
        w.put_uint_be(tds_version)
        w.put_byte(len(srv_name))
        w.write(srv_name_coded)
        w.put_byte(srv_ver[0])
        w.put_byte(srv_ver[1])
        w.put_byte(srv_ver[2])
        w.put_byte(srv_ver[3])

        # https://msdn.microsoft.com/en-us/library/dd340421.aspx
        w.put_byte(pytds.tds_base.TDS_DONE_TOKEN)
        w.put_usmallint(0)  # status
        w.put_usmallint(0)  # curcmd
        w.put_uint8(0)  # done row count

        w.flush()

    def bad_stream(self, msg):
        raise Exception(msg)


class SimpleServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(
        self, address, enc, cert=None, pkey=None, tds_version=pytds.tds_base.TDS74
    ):
        self._enc = enc
        super().__init__(address, RequestHandler)
        ctx = None
        if cert and pkey:
            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2)
            ctx.set_options(OpenSSL.SSL.OP_NO_SSLv3)
            ctx.use_certificate(cert)
            ctx.use_privatekey(pkey)
        self._tls_ctx = ctx
        self._tds_version = tds_version

    def set_ssl_context(self, ctx):
        self._tls_ctx = ctx

    def set_enc(self, enc):
        self._enc = enc


def run(address):
    logger.info("Starting server...")
    with SimpleServer(address) as server:
        logger.info("Press Ctrl+C to stop the server")
        server.serve_forever()


if __name__ == "__main__":
    run()
