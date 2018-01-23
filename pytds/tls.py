try:
    import OpenSSL.SSL
    import cryptography.hazmat.backends.openssl.backend
except ImportError:
    OPENSSL_AVAILABLE = False
else:
    OPENSSL_AVAILABLE = True

from . import tds_base


BUFSIZE = 65536


class EncryptedSocket(object):
    def __init__(self, transport, tls_conn):
        self._transport = transport
        self._tls_conn = tls_conn

    def gettimeout(self):
        return self._transport.gettimeout()

    def settimeout(self, timeout):
        self._transport.settimeout(timeout)

    def sendall(self, data, flags=0):
        # TLS.Connection does not support bytearrays, need to convert to bytes first
        if isinstance(data, bytearray):
            data = bytes(data)

        res = self._tls_conn.sendall(data)
        buf = self._tls_conn.bio_read(BUFSIZE)
        self._transport.sendall(buf)
        return res

    def send(self, data):
        while True:
            try:
                return self._tls_conn.send(data)
            except OpenSSL.SSL.WantWriteError:
                buf = self._tls_conn.bio_read(BUFSIZE)
                self._transport.sendall(buf)

    def recv(self, bufsize):
        while True:
            try:
                return self._tls_conn.recv(bufsize)
            except OpenSSL.SSL.WantReadError:
                buf = self._transport.recv(BUFSIZE)
                self._tls_conn.bio_write(buf)

    def close(self):
        self._tls_conn.shutdown()
        self._transport.close()

    def shutdown(self):
        self._tls_conn.shutdown()


def verify_cb(conn, cert, err_num, err_depth, ret_code):
    return ret_code == 1


def validate_host(cert, name):
    """
    Validates host name against certificate

    @param cert: Certificate returned by host
    @param name: Actual host name used for connection
    @return: Returns true if host name matches certificate
    """
    cn = None
    for t, v in cert.get_subject().get_components():
        if t == b'CN':
            cn = v
            break

    # TODO check SAN extensions
    # TODO handle wildcards
    return cn == name


def create_context(cafile):
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
    ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2)
    ctx.set_options(OpenSSL.SSL.OP_NO_SSLv3)
    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, verify_cb)
    #print("verify depth:", ctx.get_verify_depth())
    #print("verify mode:", ctx.get_verify_mode())
    #print("openssl version:", cryptography.hazmat.backends.openssl.backend.openssl_version_text())
    ctx.load_verify_locations(cafile=cafile)
    return ctx


# https://msdn.microsoft.com/en-us/library/dd357559.aspx
def establish_channel(tds_sock):
    w = tds_sock._writer
    r = tds_sock._reader
    login = tds_sock.conn._login

    bhost = login.server_name.encode('ascii')

    conn = OpenSSL.SSL.Connection(login.tls_ctx)
    conn.set_tlsext_host_name(bhost)
    conn.set_connect_state()
    while True:
        try:
            conn.do_handshake()
        except OpenSSL.SSL.WantReadError:
            req = conn.bio_read(BUFSIZE)
            w.begin_packet(tds_base.TDS71_PRELOGIN)
            w.write(req)
            w.flush()
            resp = r.read_whole_packet()
            # TODO validate r.packet_type
            conn.bio_write(resp)
        else:
            if login.validate_host:
                if not validate_host(cert=conn.get_peer_certificate(), name=bhost):
                    # TODO throw correct exception class
                    raise Exception("Certificate does not match host name '{}'".format(login.server_name))
            tds_sock.conn.sock = EncryptedSocket(transport=tds_sock.conn.sock, tls_conn=conn)
            return


def revert_to_clear(tds_sock):
    """
    Reverts connection back to non-encrypted mode
    Used when client sent ENCRYPT_OFF flag
    @param tds_sock:
    @return:
    """
    enc_conn = tds_sock.conn.sock
    clear_conn = enc_conn._transport
    enc_conn.shutdown()
    tds_sock.conn.sock = clear_conn